package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/router"
	"github.com/fly12323/RWAF/internal/ser/monitor"
	"github.com/fly12323/RWAF/internal/ser/weakpassword"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/coraza"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/jwt"
	"github.com/fly12323/RWAF/pkg/proxy"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	if err := config.LoadConfig("./configs/config.yaml"); err != nil {
		return err
	}
	cfg := config.GetConfig()
	if len(cfg.JWT.Secret) < 32 {
		return fmt.Errorf("JWT_SECRET 必须配置至少 32 字符的密钥")
	}
	gin.SetMode(cfg.Server.Mode)
	if err := dao.InitDB(); err != nil {
		return err
	}
	defer dao.CloseDB()
	if err := dao.InitRedis(); err != nil {
		return err
	}
	defer dao.CloseRedis()
	jwtInstance := jwt.NewJWT(jwt.JWTConfig{Secret: cfg.JWT.Secret, ExpireTime: cfg.JWT.ExpireTime, Issuer: cfg.JWT.Issuer})
	tokenService := service.NewTokenService()
	userService := service.NewUserService(jwtInstance, tokenService)
	if err := userService.InitAdminUser(); err != nil {
		return err
	}
	ruleService := service.NewRuleService()
	if err := ruleService.SyncAllRules(); err != nil {
		return err
	}
	engine, err := coraza.NewWAFEngine(&coraza.WAFConfig{RulesDir: cfg.WAF.RulesDir, CrsDir: cfg.WAF.CrsDir,
		CustomRulesDir: cfg.WAF.CustomRulesDir, EngineMode: cfg.WAF.EngineMode, RequestBodyLimit: cfg.WAF.RequestBodyLimit})
	if err != nil {
		return err
	}
	defer engine.StopFileWatcher()
	if err := ruleService.SyncBuiltinCatalog(); err != nil {
		return fmt.Errorf("内置规则目录同步失败: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	workerCtx, stopWorkers := context.WithCancel(ctx)
	defer stopWorkers()
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = events.EnsureTopic(readyCtx, cfg.Kafka)
	cancel()
	if err != nil {
		log.Printf("Kafka initially unavailable; durable spool will retry: %v", err)
	}
	publisher, err := events.OpenPublisher(cfg.Kafka)
	if err != nil {
		return err
	}
	events.SetPublisher(publisher)
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := publisher.Close(flushCtx); err != nil {
			log.Printf("event flush incomplete: %v; stats=%v", err, publisher.Stats())
		}
		events.SetPublisher(nil)
	}()
	detector, err := weakpassword.Start(workerCtx)
	if err != nil {
		stopWorkers()
		return err
	}
	defer func() { stopWorkers(); detector.Wait() }()
	waitMonitor, err := monitor.Start(workerCtx)
	if err != nil {
		return err
	}
	defer func() { stopWorkers(); waitMonitor() }()
	waitRetention := service.StartLogRetention(workerCtx)
	defer func() { stopWorkers(); waitRetention() }()
	manager := proxy.NewProxyManager(engine)
	service.SetProxyManager(manager)
	defer manager.StopAll()
	if err := manager.LoadSites(); err != nil {
		return err
	}
	apiRouter := gin.New()
	apiRouter.Use(gin.Recovery())
	_ = apiRouter.SetTrustedProxies(nil)
	router.SetupAPIRouter(apiRouter, manager, jwtInstance, tokenService, userService)
	apiRouter.GET("/health/ready", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ready", "events": publisher.Stats()}) })
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
	if err != nil {
		return err
	}
	apiServer := &http.Server{Handler: apiRouter, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: time.Duration(cfg.Server.ReadTimeout) * time.Second, WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout: time.Duration(cfg.Proxy.IdleTimeout) * time.Second, MaxHeaderBytes: 65536}
	failures := make(chan error, 1)
	go func() { failures <- apiServer.Serve(listener) }()
	log.Printf("WAF ready: API=%d, PostgreSQL configured, Kafka=%s, ML disabled", cfg.Server.Port, cfg.Kafka.Topic)
	select {
	case <-ctx.Done():
	case err := <-failures:
		if err != http.ErrServerClosed {
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		_ = apiServer.Close()
	}
	return nil
}
