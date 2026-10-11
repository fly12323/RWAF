package integration

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/router"
	"github.com/fly12323/RWAF/internal/ser/monitor"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/jwt"
	"github.com/fly12323/RWAF/pkg/proxy"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm/clause"
)

// Starts monitoring only after the browser verifies the genuine initial state.
// All user/config writes use the isolated test database, never production.
func TestP1BrowserHarness(t *testing.T) {
	if os.Getenv("WAF_P1_UI") != "1" {
		t.Skip("opt-in browser harness")
	}
	started := time.Now()
	db := quarantineDB(t)
	if err := dao.InitRedis(); err != nil {
		t.Fatal(err)
	}
	defer dao.CloseRedis()
	password := "P1-browser-test!42"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]string{}
	for _, role := range []string{"admin", "auditor"} {
		u := model.User{Username: "p1-ui-" + role + "-" + uuid.NewString()[:8], Password: string(hash), Role: role, Status: 1}
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
		users[role] = u.Username
	}
	c := monitor.DefaultConfig()
	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&c).Error; err != nil {
		t.Fatal(err)
	}
	prior, err := monitor.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.SaveConfig(prior)
	c.IntervalSeconds = 5
	if err := monitor.SaveConfig(&c); err != nil {
		t.Fatal(err)
	}
	cfg := config.GetConfig()
	cfg.Kafka.Topic = "waf-test-events"
	cfg.Kafka.GroupID = "p1-browser-" + uuid.NewString()
	cfg.Kafka.ConsumerWorkers = 1
	cfg.Kafka.SpoolDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	publisher, err := events.OpenPublisher(cfg.Kafka)
	if err != nil {
		t.Fatal(err)
	}
	events.SetPublisher(publisher)
	defer func() {
		events.SetPublisher(nil)
		flush, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		publisher.Close(flush)
	}()
	consumerDone := make(chan error, 1)
	go func() { consumerDone <- events.ConsumeGroup(ctx, db, cfg.Kafka) }()
	heartbeatDone := make(chan struct{})
	go func() { defer close(heartbeatDone); monitor.ConsumerHeartbeat(ctx, cfg.Kafka.GroupID) }()
	defer func() { cancel(); <-consumerDone; <-heartbeatDone }()
	tokens := service.NewTokenService()
	j := jwt.NewJWT(jwt.JWTConfig{Secret: strings.Repeat("p", 32), Issuer: "p1-browser", ExpireTime: 1})
	manager := proxy.NewProxyManager(nil)
	defer manager.StopAll()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	router.SetupAPIRouter(r, manager, j, tokens, service.NewUserService(j, tokens))
	dist, _ := filepath.Abs("../../web1/dist")
	static := http.FileServer(http.Dir(dist))
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/assets/") {
			static.ServeHTTP(c.Writer, c.Request)
		} else {
			c.File(filepath.Join(dist, "index.html"))
		}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:19080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	go server.Serve(listener)
	root := "../../output/p1-2026-10-11"
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	info, _ := json.MarshalIndent(map[string]any{"url": "http://127.0.0.1:19080", "users": users, "password": password}, "", "  ")
	if err := os.WriteFile(filepath.Join(root, "browser-fixture.json"), info, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("P1 browser fixture ready on 19080; waiting for initial-state check")
	var waitMonitor func()
	defer func() {
		cancel()
		if waitMonitor != nil {
			waitMonitor()
		}
	}()
	deadline := time.Now().Add(8 * time.Minute)
	for time.Now().Before(deadline) {
		fresh := func(name string) bool {
			marker, err := os.Stat(filepath.Join(root, name))
			return err == nil && !marker.ModTime().Before(started)
		}
		if waitMonitor == nil && fresh("browser-start") {
			waitMonitor, err = monitor.Start(ctx)
			if err != nil {
				t.Fatal(err)
			}
		}
		if fresh("browser-done") {
			stored, err := monitor.GetConfig()
			if err != nil || stored.DatabaseBudgetMB != 10240 || !monitor.PublicHealth().Ready {
				t.Fatal("browser did not restore healthy configuration", stored, err, monitor.PublicHealth())
			}
			t.Log("P1 browser changes verified in PostgreSQL; runtime ready")
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("P1 browser harness deadline")
}
