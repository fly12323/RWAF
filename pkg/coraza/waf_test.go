package coraza

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMonitorAndDisabledRulePolicies(t *testing.T) {
	dir := t.TempDir()
	crs := filepath.Join(dir, "crs")
	custom := filepath.Join(dir, "custom")
	if err := os.MkdirAll(filepath.Join(crs, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(custom, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(custom, "test.conf"), []byte(`SecRule REQUEST_URI "@contains attack" "id:1001,phase:1,deny,status:403,severity:CRITICAL"`), 0644); err != nil {
		t.Fatal(err)
	}
	e, err := NewWAFEngine(&WAFConfig{CrsDir: crs, CustomRulesDir: custom, EngineMode: "On", RequestBodyLimit: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer e.StopFileWatcher()
	for _, tc := range []struct {
		mode      string
		disabled  []string
		interrupt bool
		score     bool
	}{{"block", nil, true, false}, {"monitor", nil, false, false}, {"block", []string{"1001"}, false, false}} {
		tx, err := e.NewTransactionWithPolicy(tc.mode, tc.disabled, nil)
		if err != nil {
			t.Fatal(err)
		}
		tx.ProcessURI("/attack", "GET", "HTTP/1.1")
		interruption := tx.ProcessRequestHeaders()
		if (interruption != nil) != tc.interrupt || (tx.GetRiskScore() > 0) != tc.score {
			t.Errorf("mode=%s disabled=%v interruption=%v score=%d", tc.mode, tc.disabled, interruption, tx.GetRiskScore())
		}
		tx.Close()
	}
	tx, err := e.NewTransactionWithPolicy("block", nil, []string{"sqli"})
	if err != nil {
		t.Fatal(err)
	}
	tx.ProcessURI("/attack", "GET", "HTTP/1.1")
	if interruption := tx.ProcessRequestHeaders(); interruption != nil || tx.GetRiskScore() != 0 {
		t.Fatal("unselected custom category still enabled")
	}
	tx.Close()
	e.StopFileWatcher() // shutdown can be called repeatedly
}
