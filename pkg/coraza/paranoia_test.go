package coraza

import (
	"path/filepath"
	"testing"
)

func TestActualCRSParanoiaPolicyAndReload(t *testing.T) {
	crs, err := filepath.Abs("../../configs/rules/crs")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewWAFEngine(&WAFConfig{CrsDir: crs, CustomRulesDir: t.TempDir(), EngineMode: "On", RequestBodyLimit: 1024})
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
		for _, level := range []int{1, 2, 3} {
			tx, err := e.NewTransactionWithPolicy("block", nil, nil, 5, level)
			if err != nil {
				t.Fatal(err)
			}
			// SQL operator rule 942120 belongs to PL2 in the original CRS.
			tx.ProcessURI("/?q=a%20xor%20b", "GET", "HTTP/1.1")
			tx.AddRequestHeader("Host", "example.test")
			tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
			tx.AddRequestHeader("Accept", "text/html")
			it := tx.ProcessRequestHeaders()
			if it == nil {
				it, err = tx.InspectRequestBody(nil)
			}
			found := false
			for _, m := range tx.tx.MatchedRules() {
				if m.Rule().ID() == 942120 {
					found = true
				}
			}
			if err != nil || found != (level >= 2) || (level >= 2 && (it == nil || tx.GetRiskScore() < 5)) {
				t.Fatalf("reload=%v PL=%d PL2match=%v score=%d interruption=%v err=%v", reload, level, found, tx.GetRiskScore(), it, err)
			}
			tx.Close()
		}
	}
	if _, err := e.PolicyEngine("block", nil, nil, 5, 5); err == nil {
		t.Fatal("invalid PL accepted")
	}
	if _, err := e.PolicyEngine("block", []string{"01000000001"}, nil, 5, 3); err == nil {
		t.Fatal("reserved policy rule may not be disabled")
	}
}
