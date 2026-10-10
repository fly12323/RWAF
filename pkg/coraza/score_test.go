package coraza

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCRSThresholdAndScoreUseSameScale(t *testing.T) {
	dir := t.TempDir()
	crs := filepath.Join(dir, "crs")
	custom := filepath.Join(dir, "custom")
	if err := os.MkdirAll(filepath.Join(crs, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(custom, 0755); err != nil {
		t.Fatal(err)
	}
	rules := `SecRule REQUEST_URI "@contains scored" "id:1001,phase:1,pass,nolog,severity:CRITICAL,setvar:tx.inbound_anomaly_score_pl1=+5"
SecRule TX:inbound_anomaly_score_pl1 "@ge %{tx.inbound_anomaly_score_threshold}" "id:1002,phase:2,deny,status:403,msg:'score threshold'"`
	if err := os.WriteFile(filepath.Join(custom, "test.conf"), []byte(rules), 0644); err != nil {
		t.Fatal(err)
	}
	e, err := NewWAFEngine(&WAFConfig{CrsDir: crs, CustomRulesDir: custom, EngineMode: "On", RequestBodyLimit: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer e.StopFileWatcher()
	for _, reload := range []bool{false, true} {
		if reload {
			if err := e.ReloadNow(); err != nil {
				t.Fatal(err)
			}
		}
		for _, tc := range []struct {
			mode      string
			threshold int
			block     bool
		}{{"block", 5, true}, {"block", 6, false}, {"monitor", 5, false}} {
			tx, err := e.NewTransactionWithPolicy(tc.mode, nil, nil, tc.threshold)
			if err != nil {
				t.Fatal(err)
			}
			tx.ProcessURI("/scored", "GET", "HTTP/1.1")
			tx.AddRequestHeader("Host", "example.test")
			tx.ProcessRequestHeaders()
			it, err := tx.InspectRequestBody(nil)
			if err != nil || (it != nil) != tc.block || tx.GetRiskScore() != 5 {
				t.Fatalf("reload=%v mode=%s threshold=%d interruption=%v score=%d err=%v", reload, tc.mode, tc.threshold, it, tx.GetRiskScore(), err)
			}
			tx.Close()
		}
	}
}

func TestActualCRSHighThresholdDoesNotUseSeveritySum(t *testing.T) {
	crs, err := filepath.Abs("../../configs/rules/crs")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewWAFEngine(&WAFConfig{CrsDir: crs, CustomRulesDir: t.TempDir(), EngineMode: "On", RequestBodyLimit: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer e.StopFileWatcher()
	for _, threshold := range []int{1, 10000} {
		tx, err := e.NewTransactionWithPolicy("block", nil, nil, threshold)
		if err != nil {
			t.Fatal(err)
		}
		tx.ProcessURI("/?id=1%20UNION%20SELECT%20username%20FROM%20users", "GET", "HTTP/1.1")
		tx.AddRequestHeader("Host", "example.test")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
		it := tx.ProcessRequestHeaders()
		if it == nil {
			it, err = tx.InspectRequestBody(nil)
		}
		if err != nil || tx.GetRiskScore() == 0 || (it != nil) != (threshold == 1) {
			t.Fatalf("threshold=%d score=%d interruption=%v err=%v", threshold, tx.GetRiskScore(), it, err)
		}
		tx.Close()
	}
}
