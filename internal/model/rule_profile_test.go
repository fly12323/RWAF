package model

import "testing"

func TestRuleProfileSeparatesMetadataFromAccuracy(t *testing.T) {
	for _, tc := range []struct {
		rule              Rule
		level             int
		risk, scope, role string
	}{
		{Rule{Category: "SQL Injection", Severity: "CRITICAL", RuleContent: `SecRule ARGS "@rx attack" "id:1,phase:2,tag:'paranoia-level/1'"`}, 1, "low", "request", "detection"},
		{Rule{Category: "XSS", RuleContent: `SecRule ARGS "@rx attack" "id:2,phase:2,tag:'paranoia-level/3'"`}, 3, "high", "request", "detection"},
		{Rule{Category: "Data Leakage", RuleContent: `SecRule RESPONSE_BODY "@rx leak" "id:3,phase:4,tag:'paranoia-level/2'"`}, 2, "moderate", "response", "detection"},
		{Rule{Category: "Blocking Evaluation", RuleContent: `SecRule TX:score "@ge 5" "id:4,phase:2,deny"`}, 0, "not_applicable", "control", "control"},
		{Rule{Category: "Protocol", RuleContent: `SecRule TX:detection_paranoia_level "@lt 2" "id:5,phase:1,skipAfter:END"`}, 0, "not_applicable", "control", "control"},
		{Rule{IsCustom: true, Severity: "CRITICAL", Score: 100, RuleContent: `SecRule ARGS "@rx attack" "id:6,phase:2,tag:'paranoia-level/1'"`}, 0, "unknown", "request", "custom"},
	} {
		p := DescribeRule(tc.rule)
		if p.ParanoiaLevel != tc.level || p.FalsePositiveRisk != tc.risk || p.Scope != tc.scope || p.Role != tc.role {
			t.Fatalf("%+v: %+v", tc.rule, p)
		}
	}
}
