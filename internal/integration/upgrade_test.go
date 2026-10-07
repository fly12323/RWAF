package integration

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/protection"
	"github.com/fly12323/RWAF/internal/ser/ratelimit"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/coraza"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/jwt"
	"github.com/fly12323/RWAF/pkg/proxy"
)

func TestPostgresKafkaRedisAndProxy(t *testing.T) {
	if os.Getenv("WAF_INTEGRATION") != "1" {
		t.Skip("start scripts/integration-compose.yml and set WAF_INTEGRATION=1")
	}
	// These credentials/ports exclusively target the disposable test stack.
	for k, v := range map[string]string{"DB_HOST": "127.0.0.1", "DB_PORT": "15432", "DB_USER": "waf_test", "DB_PASSWORD": "waf-test-only", "DB_NAME": "waf_test", "REDIS_HOST": "127.0.0.1", "REDIS_PORT": "16379", "REDIS_PASSWORD": "", "KAFKA_BROKERS": "127.0.0.1:29094"} {
		t.Setenv(k, v)
	}
	if err := config.LoadConfig("../../configs/config.yaml"); err != nil {
		t.Fatal(err)
	}
	cfg := config.GetConfig()
	cfg.Server.Mode = "release"
	cfg.Kafka.Topic = "waf-test-events"
	cfg.Kafka.GroupID = "test-" + uuid.NewString()
	cfg.Kafka.FlushIntervalMs = 50
	cfg.Kafka.SpoolDir = t.TempDir()
	if err := dao.InitDB(); err != nil {
		t.Fatal(err)
	}
	defer dao.CloseDB()
	if err := dao.InitRedis(); err != nil {
		t.Fatal(err)
	}
	defer dao.CloseRedis()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := events.EnsureTopic(ctx, cfg.Kafka); err != nil {
		t.Fatal(err)
	}
	consumerCtx, stopConsumer := context.WithCancel(ctx)
	consumerDone := make(chan error, 1)
	go func() { consumerDone <- events.Consume(consumerCtx, dao.GetDB(), cfg.Kafka) }()
	defer func() {
		stopConsumer()
		select {
		case err := <-consumerDone:
			if err != nil {
				t.Errorf("consumer: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("consumer failed to stop")
		}
	}()
	publisher := events.NewPublisher(cfg.Kafka)
	events.SetPublisher(publisher)
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = publisher.Close(closeCtx)
		events.SetPublisher(nil)
	}()

	requestID := uuid.NewString()
	e := events.RequestEvent(&model.RequestLog{RequestID: requestID, Action: "block", URI: "/test"}, []model.RuleMatch{{RuleID: "1001", Severity: "CRITICAL"}})
	for i := 0; i < 2; i++ {
		if err := publisher.Submit(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := publisher.Submit(events.CrawlerEvent(&model.CrawlerLog{RequestID: requestID, CrawlerType: "scanner", DetectionRules: "[]"})); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		var n int64
		dao.GetDB().Model(&model.RequestLog{}).Where("request_id = ?", requestID).Count(&n)
		return n == 1
	})
	var entry model.RequestLog
	if err := dao.GetDB().Where("request_id = ?", requestID).First(&entry).Error; err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		var n int64
		dao.GetDB().Model(&model.CrawlerLog{}).Where("request_id = ?", requestID).Count(&n)
		return n == 1
	})
	var matches int64
	dao.GetDB().Model(&model.RuleMatch{}).Where("request_log_id = ?", entry.ID).Count(&matches)
	if matches != 1 {
		t.Fatalf("duplicate consumption created %d rule matches", matches)
	}
	// Replaying an already committed event also leaves PostgreSQL unchanged.
	if err := events.PersistBatch(ctx, dao.GetDB(), []events.Event{e, e}); err != nil {
		t.Fatal(err)
	}
	var count int64
	dao.GetDB().Model(&model.RequestLog{}).Where("request_id = ?", requestID).Count(&count)
	if count != 1 {
		t.Fatal("replay created duplicate logs")
	}
	weak := events.WeakEvent(&model.WeakPasswordEvent{RequestID: uuid.NewString(), SiteID: 42, Endpoint: "test-" + uuid.NewString(), Kind: "login", Path: "/login", Representation: "md5", Outcome: "unknown"})
	weak.Weak.CreatedAt = weak.Weak.CreatedAt.Truncate(time.Microsecond)
	if err := events.PersistBatch(ctx, dao.GetDB(), []events.Event{weak, weak}); err != nil {
		t.Fatal(err)
	}
	if err := events.PersistBatch(ctx, dao.GetDB(), []events.Event{weak}); err != nil {
		t.Fatal(err)
	}
	var weakCount int64
	dao.GetDB().Model(&model.WeakPasswordEvent{}).Where("request_id = ?", weak.Weak.RequestID).Count(&weakCount)
	var alert model.Alert
	if err := dao.GetDB().Where("key = ?", "weak:42:"+weak.Weak.Endpoint).First(&alert).Error; err != nil {
		t.Fatal(err)
	}
	if weakCount != 1 || alert.Occurrences != 1 {
		t.Fatal("weak event replay duplicated event or alert")
	}
	secondWeak := *weak.Weak
	secondWeak.RequestID = uuid.NewString()
	secondWeak.CreatedAt = weak.Weak.CreatedAt.Add(-time.Hour)
	if err := events.PersistBatch(ctx, dao.GetDB(), []events.Event{events.WeakEvent(&secondWeak)}); err != nil {
		t.Fatal(err)
	}
	if err := dao.GetDB().First(&alert, alert.ID).Error; err != nil || alert.Occurrences != 2 {
		t.Fatal("weak alert did not aggregate", err)
	}
	if !alert.LastSeen.Equal(weak.Weak.CreatedAt) {
		t.Fatal("out-of-order weak event moved last_seen backwards")
	}
	testLegacyPasswordRestriction(t)

	limiter := ratelimit.NewCCProtectionService()
	cc := &model.CCProtectionConfig{Enabled: true, RequestsPerMinute: 3, URILimits: `[{"uri":"/login","requests_per_minute":1}]`}
	ip := "test-" + uuid.NewString()
	for _, tc := range []struct {
		path    string
		allowed bool
	}{{"/login", true}, {"/login", false}, {"/other", true}, {"/other", true}, {"/other", false}} {
		allowed, _, err := limiter.CheckLimitContext(ctx, 1, ip, tc.path, cc)
		if err != nil || allowed != tc.allowed {
			t.Fatalf("limit %s: %v %v", tc.path, allowed, err)
		}
	}
	allowed, _, err := limiter.CheckLimitContext(ctx, 2, ip, "/other", cc)
	if err != nil || !allowed {
		t.Fatal("site counters are not isolated", err)
	}

	dir := t.TempDir()
	custom := filepath.Join(dir, "custom")
	crs := filepath.Join(dir, "crs")
	_ = os.MkdirAll(custom, 0755)
	_ = os.MkdirAll(filepath.Join(crs, "rules"), 0755)
	if err := os.WriteFile(filepath.Join(custom, "test.conf"), []byte(`SecRule REQUEST_URI "@contains attack" "id:1001,phase:1,deny,status:403,severity:CRITICAL"`), 0644); err != nil {
		t.Fatal(err)
	}
	engine, err := coraza.NewWAFEngine(&coraza.WAFConfig{CrsDir: crs, CustomRulesDir: custom, EngineMode: "On", RequestBodyLimit: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.StopFileWatcher()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { data, _ := io.ReadAll(r.Body); _, _ = w.Write(data) }))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	backendPort, _ := strconv.Atoi(u.Port())
	targets := "[{\"host\":\"127.0.0.1\",\"port\":" + strconv.Itoa(backendPort) + ",\"weight\":1}]"
	site := model.Site{ID: uint(time.Now().UnixNano() % 1000000000), ListenPort: freePort(t), Enabled: true, UpstreamTargets: targets, LoadBalanceStrategy: "round_robin"}
	policy := model.DefaultProtectionConfig("block", 15)
	policy.CCProtectionEnabled = false
	policy.CrawlerDetectionEnabled = false
	policy.AutoBlockEnabled = false
	policy.IPBlacklistEnabled = false
	policy.IPWhitelistEnabled = false
	if err := protection.SaveConfig(&policy); err != nil {
		t.Fatal(err)
	}
	loaded, err := protection.GetConfig()
	if err != nil || loaded.CCProtectionEnabled || loaded.AutoBlockEnabled {
		t.Fatal("false config flags were overwritten", err)
	}
	manager := proxy.NewProxyManager(engine)
	defer manager.StopAll()
	if err := manager.AddSite(&site); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	call := func(path, body string) int {
		r, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(site.ListenPort)+path, strings.NewReader(body))
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if status := call("/attack", ""); status != 403 {
		t.Fatalf("block status=%d", status)
	}
	second := site
	second.ID++
	second.ListenPort = freePort(t)
	if err := manager.AddSite(&second); err != nil {
		t.Fatal(err)
	}
	callSecond := func() int {
		resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(second.ListenPort) + "/attack")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if callSecond() != 403 {
		t.Fatal("second site did not share block policy")
	}
	policy.WafMode = "monitor"
	if err := protection.SaveConfig(&policy); err != nil {
		t.Fatal(err)
	}
	if status := call("/attack", "preserved"); status != 200 {
		t.Fatalf("monitor status=%d", status)
	}
	if callSecond() != 200 {
		t.Fatal("global mode change did not update second site")
	}
	policy.WafMode = "block"
	policy.Enabled = false
	if err := protection.SaveConfig(&policy); err != nil {
		t.Fatal(err)
	}
	if call("/attack", "") != 200 || callSecond() != 200 {
		t.Fatal("global off must keep both site proxies working")
	}
	policy.Enabled = true
	policy.DisabledRuleIDs = []string{"1001"}
	if err := protection.SaveConfig(&policy); err != nil {
		t.Fatal(err)
	}
	if call("/attack", "") != 200 || callSecond() != 200 {
		t.Fatal("disabled rule must apply to both sites")
	}
	policy.DisabledRuleIDs = []string{}
	if err := protection.SaveConfig(&policy); err != nil {
		t.Fatal(err)
	}
	if call("/attack", "") != 403 || callSecond() != 403 {
		t.Fatal("re-enabled rule must apply to both sites")
	}
	manager.RemoveSite(second.ID)
	oldPort := site.ListenPort
	site.ListenPort = freePort(t)
	if err := manager.UpdateSite(&site); err != nil {
		t.Fatal(err)
	}
	for _, port := range manager.GetListeningPorts() {
		if port == oldPort {
			t.Fatal("old port remained registered")
		}
	}
	if status := call("/normal", "preserved"); status != 200 {
		t.Fatalf("updated port status=%d", status)
	}
	site.Enabled = false
	if err := manager.UpdateSite(&site); err != nil {
		t.Fatal(err)
	}
	if len(manager.GetListeningPorts()) != 0 {
		t.Fatal("disabled site kept its listener")
	}
}

func testLegacyPasswordRestriction(t *testing.T) {
	j := jwt.NewJWT(jwt.JWTConfig{Secret: "integration-only-secret", ExpireTime: 1, Issuer: "test"})
	tokens := service.NewTokenService()
	users := service.NewUserService(j, tokens)
	user, err := users.CreateUser(&service.CreateUserRequest{Username: "legacy-" + uuid.NewString(), Password: "Unique-Initial!2026", Role: model.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	defer dao.GetDB().Delete(user)
	weakHash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.MinCost)
	if err := dao.GetDB().Model(user).Update("password", string(weakHash)).Error; err != nil {
		t.Fatal(err)
	}
	login, err := users.Login(&service.LoginRequest{Username: user.Username, Password: "admin123"})
	if err != nil || !login.User.MustChangePassword {
		t.Fatal("legacy weak user not restricted", err)
	}
	r := gin.New()
	r.Use(middleware.JWTAuthMiddleware(j, tokens))
	r.GET("/api/v1/monitor/status", func(c *gin.Context) { c.JSON(200, gin.H{"code": 0}) })
	r.GET("/api/v1/auth/info", func(c *gin.Context) { c.JSON(200, gin.H{"code": 0}) })
	for _, tc := range []struct {
		path    string
		allowed bool
	}{{"/api/v1/monitor/status", false}, {"/api/v1/auth/info", true}} {
		req := httptest.NewRequest("GET", tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+login.Token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if strings.Contains(w.Body.String(), `"code":0`) != tc.allowed {
			t.Fatalf("restricted endpoint %s: %s", tc.path, w.Body.String())
		}
	}
	id, _ := j.GetTokenID(login.Token)
	if err := users.ChangePassword(user.ID, id, &service.ChangePasswordRequest{OldPassword: "admin123", NewPassword: "Unique-Replacement!2026"}); err != nil {
		t.Fatal(err)
	}
	valid, _ := tokens.ValidateSession(user.ID, id)
	if valid {
		t.Fatal("password change did not revoke restricted session")
	}
	login, err = users.Login(&service.LoginRequest{Username: user.Username, Password: "Unique-Replacement!2026"})
	if err != nil || login.User.MustChangePassword {
		t.Fatal("strong replacement did not remove restriction", err)
	}
	_ = users.Logout(user.ID)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for log persistence")
}
