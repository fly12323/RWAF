package protection

import (
	"github.com/fly12323/RWAF/internal/model"
	"testing"
)

func TestParanoiaValidationAndLegacyDefault(t *testing.T) {
	for _, pl := range []int{0, 1, 2, 3, 4, -1, 5} {
		cfg := model.DefaultProtectionConfig("block", 15)
		cfg.ParanoiaLevel = pl
		err := Validate(&cfg)
		if (err != nil) != (pl < 0 || pl > 4) {
			t.Fatalf("PL=%d err=%v", pl, err)
		}
		if pl == 0 && cfg.ParanoiaLevel != 1 {
			t.Fatal("old client did not retain PL1")
		}
	}
	for _, id := range []string{"1000000001", "01000000001"} {
		cfg := model.DefaultProtectionConfig("block", 15)
		cfg.DisabledRuleIDs = []string{id}
		if Validate(&cfg) == nil {
			t.Fatal("reserved policy rule may not be disabled")
		}
	}
}
