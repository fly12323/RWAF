package integration

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/jwt"
	"github.com/fly12323/RWAF/pkg/proxy"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Opt-in real API/browser fixture. Only the disposable integration database and
// loopback port are used; the built frontend is served by the same origin.
func TestP0BrowserHarness(t *testing.T) {
	if os.Getenv("WAF_P0_UI") != "1" {
		t.Skip("opt-in browser harness")
	}
	started := time.Now()
	db := quarantineDB(t)
	if err := dao.InitRedis(); err != nil {
		t.Fatal(err)
	}
	defer dao.CloseRedis()
	password := "P0-browser-test!42"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]string{}
	for _, role := range []string{"admin", "auditor"} {
		u := model.User{Username: "p0-ui-" + role + "-" + uuid.NewString()[:8], Password: string(hash), Role: role, Status: 1}
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
		users[role] = u.Username
	}
	cfg := config.GetConfig().Kafka
	cfg.GroupID = "p0-browser-" + uuid.NewString()
	cfg.Topic = "waf-test-events"
	q := quarantineFixture(t, db, cfg, []byte("{\"broken\":"), 1)
	tokens := service.NewTokenService()
	j := jwt.NewJWT(jwt.JWTConfig{Secret: strings.Repeat("b", 32), Issuer: "p0-browser", ExpireTime: 1})
	manager := proxy.NewProxyManager(nil)
	defer manager.StopAll()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	router.SetupAPIRouter(r, manager, j, tokens, service.NewUserService(j, tokens))
	dist, err := filepath.Abs("../../web1/dist")
	if err != nil {
		t.Fatal(err)
	}
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
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	root := filepath.Join("../../output/p0-2026-10-11")
	info, _ := json.MarshalIndent(map[string]any{"url": "http://127.0.0.1:19080", "users": users, "password": password, "quarantine_id": q.ID}, "", "  ")
	if err := os.WriteFile(filepath.Join(root, "browser-fixture.json"), info, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("real browser fixture ready on loopback 19080")
	deadline := time.NewTimer(8 * time.Minute)
	defer deadline.Stop()
	for {
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Fatal(err)
			}
			return
		case <-deadline.C:
			t.Fatal("browser harness deadline")
		case <-time.After(250 * time.Millisecond):
			if marker, err := os.Stat(filepath.Join(root, "browser-done")); err == nil && !marker.ModTime().Before(started) {
				var n int64
				db.Model(&model.RequestLog{}).Where("request_id = ?", "p0-browser-replayed").Count(&n)
				if n != 1 {
					t.Fatal("browser replay did not persist exactly one real log", n)
				}
				var stored model.QuarantinedEvent
				if err := db.First(&stored, q.ID).Error; err != nil {
					t.Fatal(err)
				}
				if stored.Status != "replayed" {
					t.Fatal("browser replay status missing")
				}
				server.Shutdown(context.Background())
				t.Log("browser replay verified in PostgreSQL; original quarantine retained")
				return
			}
		}
	}
}
