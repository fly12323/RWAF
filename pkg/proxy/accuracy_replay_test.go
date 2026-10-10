package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/pkg/coraza"
	"github.com/fly12323/RWAF/pkg/events"
)

// Explicit opt-in replays generated data through the handler and a real HTTP backend.
func TestAccuracyCorpusMatchesProxy(t *testing.T) {
	if os.Getenv("WAF_ACCURACY") != "1" {
		t.Skip("run scripts/accuracy first and set WAF_ACCURACY=1")
	}
	path := "../../output/accuracy/2026-10-10"
	var samples []struct {
		ID, Method, URI, Body string
		Headers               map[string]string
	}
	b, err := os.ReadFile(filepath.Join(path, "input.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &samples); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(path, "outcomes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	expected := map[string]bool{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	for scanner.Scan() {
		var o struct {
			ID, Dataset, Error string
			PL, Threshold      int
			Blocked            bool
		}
		if err := json.Unmarshal(scanner.Bytes(), &o); err != nil {
			t.Fatal(err)
		}
		if o.Dataset != "crs-positive" && o.Error == "" {
			expected[fmt.Sprintf("%d/%d/%s", o.PL, o.Threshold, o.ID)] = o.Blocked
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	old := config.GlobalConfig
	config.GlobalConfig = &config.Config{Proxy: config.ProxyConfig{ConnectTimeout: 3, ReadTimeout: 3, IdleTimeout: 3}, WAF: config.WAFConfig{RequestBodyLimit: 1024 * 1024}}
	t.Cleanup(func() { config.GlobalConfig = old })
	crs, _ := filepath.Abs("../../configs/rules/crs")
	e, err := coraza.NewWAFEngine(&coraza.WAFConfig{CrsDir: crs, CustomRulesDir: t.TempDir(), EngineMode: "On", RequestBodyLimit: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer e.StopFileWatcher()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body); w.WriteHeader(200) }))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	port, _ := strconv.Atoi(u.Port())
	p := NewReverseProxy(1, []Target{{Host: u.Hostname(), Port: port, Weight: 1}}, "round_robin", e)
	defer p.Close()
	policy := model.DefaultProtectionConfig("block", 5)
	policy.CCProtectionEnabled = false
	policy.CrawlerDetectionEnabled = false
	policy.AutoBlockEnabled = false
	policy.IPWhitelistEnabled = false
	policy.IPBlacklistEnabled = false
	p.loadPolicy = func() (*model.ProtectionConfig, error) { return &policy, nil }
	var last *model.RequestLog
	p.publish = func(e events.Event) error {
		if e.Request != nil {
			last = e.Request
		}
		return nil
	}
	checked := 0
	for _, threshold := range []int{5, 10, 15} {
		for pl := 1; pl <= 4; pl++ {
			policy.ScoreThreshold = threshold
			policy.ParanoiaLevel = pl
			for _, s := range samples {
				key := fmt.Sprintf("%d/%d/%s", pl, threshold, s.ID)
				want, ok := expected[key]
				if !ok {
					t.Fatalf("missing baseline %s", key)
				}
				r := httptest.NewRequest(s.Method, s.URI, strings.NewReader(s.Body))
				r.Host = "accuracy.example.test"
				for k, v := range s.Headers {
					r.Header.Set(k, v)
				}
				last = nil
				w := runPipeline(p, r)
				if last == nil || (w.Code != 200 && w.Code != 403) {
					t.Fatalf("invalid replay %s: status=%d log=%+v", key, w.Code, last)
				}
				if got := last.Action == "block" && last.DecisionSource == "waf"; got != want {
					t.Fatalf("proxy/adapter disagreement %s: status=%d log=%+v wantBlock=%v", key, w.Code, last, want)
				}
				checked++
			}
		}
	}
	t.Logf("actual proxy cross-check: %d requests, zero verdict disagreements", checked)
}
