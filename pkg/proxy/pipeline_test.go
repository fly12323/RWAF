package proxy

import (
	"context"
	"errors"
	"io"
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
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/pkg/coraza"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/gin-gonic/gin"
)

type unreadBody struct{ reads int }

func (b *unreadBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("body must not be read")
}
func (*unreadBody) Close() error { return nil }

// Exercises the actual handler with an HTTP backend and real rule engine.
// Dependencies are replaced only at the storage/event boundary.
func testPipeline(t *testing.T) (*ReverseProxy, *model.ProtectionConfig, *[]model.RequestLog, *int) {
	t.Helper()
	old := config.GlobalConfig
	config.GlobalConfig = &config.Config{Proxy: config.ProxyConfig{ConnectTimeout: 1, ReadTimeout: 1, IdleTimeout: 1}, WAF: config.WAFConfig{RequestBodyLimit: 32}}
	t.Cleanup(func() { config.GlobalConfig = old })
	dir := t.TempDir()
	crs := filepath.Join(dir, "crs")
	custom := filepath.Join(dir, "custom")
	if err := os.MkdirAll(filepath.Join(crs, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(custom, 0755); err != nil {
		t.Fatal(err)
	}
	rules := `SecRule REQUEST_URI "@contains attack" "id:1001,phase:1,deny,status:403,severity:CRITICAL,msg:'header rejection'"
SecRule ARGS:input "@contains dangerous" "id:1002,phase:2,deny,status:403,msg:'body rejection'"`
	if err := os.WriteFile(filepath.Join(custom, "test.conf"), []byte(rules), 0644); err != nil {
		t.Fatal(err)
	}
	engine, err := coraza.NewWAFEngine(&coraza.WAFConfig{CrsDir: crs, CustomRulesDir: custom, EngineMode: "On", RequestBodyLimit: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.StopFileWatcher)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, r.Body) }))
	t.Cleanup(backend.Close)
	u, _ := url.Parse(backend.URL)
	port, _ := strconv.Atoi(u.Port())
	p := NewReverseProxy(1, []Target{{Host: u.Hostname(), Port: port, Weight: 1}}, "round_robin", engine)
	t.Cleanup(p.Close)
	policy := model.DefaultProtectionConfig("block", 15)
	policy.CCProtectionEnabled = false
	policy.CrawlerDetectionEnabled = false
	policy.UpdatedAt = time.Now()
	p.loadPolicy = func() (*model.ProtectionConfig, error) { return &policy, nil }
	p.isWhitelisted = func(string) (bool, error) { return false, nil }
	p.isBlocked = func(string) (bool, *model.IPBlacklist, error) { return false, nil, nil }
	logs := []model.RequestLog{}
	p.publish = func(e events.Event) error {
		if e.Request != nil {
			logs = append(logs, *e.Request)
		}
		return nil
	}
	bans := 0
	p.autoBlock = func(context.Context, uint, string, string, *model.AutoBlockConfig) error { bans++; return nil }
	return p, &policy, &logs, &bans
}

func runPipeline(p *ReverseProxy, r *http.Request) *httptest.ResponseRecorder {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Any("/*path", p.Handler())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func TestHeaderRejectionDoesNotReadBody(t *testing.T) {
	p, _, logs, bans := testPipeline(t)
	body := &unreadBody{}
	r := httptest.NewRequest("POST", "/attack", nil)
	r.Body = body
	r.ContentLength = 100
	w := runPipeline(p, r)
	if w.Code != 403 || body.reads != 0 || len(*logs) != 1 || *bans != 1 {
		t.Fatalf("status=%d reads=%d logs=%d bans=%d", w.Code, body.reads, len(*logs), *bans)
	}
	l := (*logs)[0]
	if l.ScoreBasis != "crs_anomaly" || l.RiskScore != 0 || !l.RuleEvaluated || l.DecisionSource != "waf" || len(l.Detections) != 1 {
		t.Fatalf("unexpected audit: %+v", l)
	}
}

func TestGlobalObservationAndWhitelistSemantics(t *testing.T) {
	for _, source := range []string{"ipban", "cc", "waf", "crawler"} {
		t.Run(source, func(t *testing.T) {
			p, policy, logs, bans := testPipeline(t)
			policy.WafMode = "monitor"
			if source == "ipban" {
				p.isBlocked = func(string) (bool, *model.IPBlacklist, error) { return true, &model.IPBlacklist{Reason: "test"}, nil }
			}
			if source == "cc" {
				policy.CCProtectionEnabled = true
				p.ccProtection = &testLimiter{}
			}
			if source == "crawler" {
				policy.CrawlerDetectionEnabled = true
				policy.CrawlerScannerAction = "block"
			}
			path := "/normal"
			if source == "waf" {
				path = "/attack"
			}
			r := httptest.NewRequest("POST", path, strings.NewReader("preserved"))
			if source == "crawler" {
				r.Header.Set("User-Agent", "sqlmap")
			}
			w := runPipeline(p, r)
			if w.Code != 200 || w.Body.String() != "preserved" || *bans != 0 || len(*logs) != 1 {
				t.Fatalf("status=%d body=%s bans=%d logs=%d", w.Code, w.Body.String(), *bans, len(*logs))
			}
			l := (*logs)[0]
			if l.Action != "pass" || l.ProtectionMode != "monitor" || l.PolicyVersion == "" || len(l.Detections) == 0 || l.Detections[0].Source != source {
				t.Fatalf("observation missing: %+v", l)
			}
		})
	}
	p, policy, logs, bans := testPipeline(t)
	policy.CCProtectionEnabled = true
	p.ccProtection = &testLimiter{}
	p.isWhitelisted = func(string) (bool, error) { return true, nil }
	w := runPipeline(p, httptest.NewRequest("POST", "/attack", strings.NewReader("preserved")))
	if w.Code != 200 || *bans != 0 || (*logs)[0].RuleEvaluated || len((*logs)[0].Detections) != 0 {
		t.Fatal("IP whitelist behavior changed")
	}
}

func TestBodyAndDependencyErrorsAreAuditedOnce(t *testing.T) {
	for _, failure := range []string{"body_limit", "policy_error", "ip_list_error", "cc_error", "waf_error"} {
		t.Run(failure, func(t *testing.T) {
			p, policy, logs, _ := testPipeline(t)
			body := "normal"
			status := 503
			switch failure {
			case "body_limit":
				policy.WafMode = "monitor"
				body = strings.Repeat("a", 33)
				status = 413
			case "policy_error":
				p.loadPolicy = func() (*model.ProtectionConfig, error) { return nil, errors.New("db unavailable") }
			case "ip_list_error":
				p.isWhitelisted = func(string) (bool, error) { return false, errors.New("db unavailable") }
			case "cc_error":
				policy.CCProtectionEnabled = true
				p.ccProtection = errorLimiter{}
			case "waf_error":
				policy.DisabledRuleIDs = []string{"bad"}
			}
			w := runPipeline(p, httptest.NewRequest("POST", "/normal", strings.NewReader(body)))
			if w.Code != status || len(*logs) != 1 || (*logs)[0].Action != "error" || (*logs)[0].DecisionSource != failure {
				t.Fatalf("status=%d logs=%+v", w.Code, *logs)
			}
		})
	}
}

func TestBodyRuleBlocksAndCCDoesNotAutoBan(t *testing.T) {
	p, policy, logs, bans := testPipeline(t)
	r := httptest.NewRequest("POST", "/normal", strings.NewReader("input=dangerous"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := runPipeline(p, r)
	if w.Code != 403 || len(*logs) != 1 || *bans != 1 {
		t.Fatal("body rule not enforced", w.Code, *logs, *bans)
	}
	*logs = nil
	*bans = 0
	policy.CCProtectionEnabled = true
	p.ccProtection = &testLimiter{}
	w = runPipeline(p, httptest.NewRequest("GET", "/normal", nil))
	if w.Code != 429 || len(*logs) != 1 || *bans != 0 {
		t.Fatal("CC should not invoke automatic ban", w.Code, *logs, *bans)
	}
}
