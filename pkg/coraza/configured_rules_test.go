package coraza

import (
	"path/filepath"
	"testing"
)

func TestConfiguredCRSRulesLoad(t *testing.T) {
	crs, err := filepath.Abs("../../configs/rules/crs")
	if err != nil {
		t.Fatal(err)
	}
	waf, err := buildEngine(&WAFConfig{CrsDir: crs, CustomRulesDir: t.TempDir(), EngineMode: "On", RequestBodyLimit: 10485760}, "block", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessURI("/?id=1%20UNION%20SELECT%20username%20FROM%20users", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.test")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
	interruption := tx.ProcessRequestHeaders()
	if interruption == nil {
		interruption, _ = tx.ProcessRequestBody()
	}
	if interruption == nil && len(tx.MatchedRules()) == 0 {
		t.Fatal("configured CRS did not detect SQL injection")
	}
}
