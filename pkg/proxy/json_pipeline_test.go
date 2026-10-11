package proxy

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/pkg/coraza"
)

func TestJSONActualCRSPipeline(t *testing.T) {
	p, policy, logs, bans := testPipeline(t)
	config.GetConfig().WAF.RequestBodyLimit = 4096
	crs, err := filepath.Abs("../../configs/rules/crs")
	if err != nil {
		t.Fatal(err)
	}
	e, err := coraza.NewWAFEngine(&coraza.WAFConfig{CrsDir: crs, CustomRulesDir: t.TempDir(), EngineMode: "On", RequestBodyLimit: 4096})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.StopFileWatcher)
	p.wafEngine = e
	policy.ScoreThreshold = 5
	for _, mode := range []string{"block", "monitor"} {
		policy.WafMode = mode
		for _, tc := range []struct {
			name, ct, body string
			status         int
		}{
			{"unicode", "application/json", `{"text":"\u4e2d\u6587","emoji":"\ud83d\ude00"}`, 200},
			{"nested-array", "application/vnd.api+json; charset=utf-8", `{"items":[{"text":"hello"}],"active":true,"count":3}`, 200},
			{"media-type-policy", "application/problem+json", `{"text":"hello"}`, 403},
			{"escaped-attack", "Application/JSON; charset=UTF-8", `{"items":[{"text":"\u003cscript\u003ealert(1)\u003c/script\u003e"}]}`, 403},
			{"invalid-json", "application/problem+json", `{"text":`, 400},
			{"trailing-json", "application/json", `{} {}`, 400},
			{"deep-json", "application/json", strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129), 400},
			{"empty-body", "application/json", "", 200},
			{"body-limit", "application/json", `{"text":"` + strings.Repeat("x", 4096) + `"}`, 413},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				// Processor selection must not silently widen CRS's allowed media types.
				// Explicitly permit +json here through the existing rule policy.
				policy.DisabledRuleIDs = nil
				if strings.Contains(tc.ct, "+json") && tc.name != "media-type-policy" {
					policy.DisabledRuleIDs = []string{"920420"}
				}
				*logs = nil
				*bans = 0
				r := httptest.NewRequest("POST", "/json", strings.NewReader(tc.body))
				r.Header.Set("Content-Type", tc.ct)
				r.Header.Set("User-Agent", "Mozilla/5.0")
				r.Header.Set("Accept", "application/json")
				w := runPipeline(p, r)
				want := tc.status
				if mode == "monitor" && want == 403 {
					want = 200
				}
				if w.Code != want || len(*logs) != 1 {
					t.Fatalf("status=%d want=%d logs=%+v", w.Code, want, *logs)
				}
				l := (*logs)[0]
				if want == 400 && (l.DecisionSource != "waf_error" || l.Action != "error" || *bans != 0) {
					t.Fatalf("parser error audit: %+v bans=%d", l, *bans)
				}
				if tc.status == 403 && (len(l.Detections) == 0 || l.Detections[0].Source != "waf" || l.RiskScore < 5) {
					t.Fatalf("missing decoded attack evidence: %+v", l)
				}
				if mode == "monitor" && *bans != 0 {
					t.Fatal("monitor JSON triggered auto-ban")
				}
				if want == 200 && w.Body.String() != tc.body {
					t.Fatal("forwarded JSON bytes changed")
				}
			})
		}
	}
}
