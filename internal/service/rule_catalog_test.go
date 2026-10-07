package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"github.com/fly12323/RWAF/internal/model"
)

func TestBuiltinCatalogPreservesChainsAndMetadata(t *testing.T) {
	text := "# comment\nSecRule ARGS \"@rx attack\" \\\n  \"id:942100,\\\n  msg:'SQL test',\\\n  severity:'CRITICAL',\\\n  chain\"\nSecRule ARGS \"@rx second\" \"t:none\"\nSecAction \"id:900100,phase:1,pass\"\n"
	rules, err := ParseBuiltinRules("REQUEST-942-APPLICATION-ATTACK-SQLI.conf", text)
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules=%v err=%v", rules, err)
	}
	if rules[0].RuleID != "942100" || rules[0].Category != "SQL Injection" || rules[0].Description != "SQL test" || rules[0].Severity != "CRITICAL" || !strings.Contains(rules[0].RuleContent, "@rx second") || rules[0].IsCustom {
		t.Fatalf("incorrect metadata: %+v", rules[0])
	}
	if _, err := ParseBuiltinRules("bad.conf", "SecRule ARGS \\"); err == nil {
		t.Fatal("unfinished rule accepted")
	}
}
func TestRepositoryBuiltinCatalog(t *testing.T) {
	files, err := filepath.Glob("../../configs/rules/crs/rules/*.conf")
	if err != nil || len(files) == 0 {
		t.Fatal("CRS files missing")
	}
	ids := map[string]bool{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		rules, err := ParseBuiltinRules(file, string(data))
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range rules {
			if ids[rule.RuleID] {
				t.Fatalf("duplicate %s", rule.RuleID)
			}
			ids[rule.RuleID] = true
		}
	}
	if !ids["942100"] || !ids["941100"] || len(ids) < 500 {
		t.Fatalf("incomplete catalogue: %d", len(ids))
	}
}
func TestLegacyDecisionDescriptions(t *testing.T) {
	rate := model.RequestLog{Action: "block", ResponseCode: 429}
	DescribeDecision(&rate)
	if rate.DecisionSource != "cc" || !rate.SourceInferred || rate.RuleEvaluated {
		t.Fatalf("CC scored: %+v", rate)
	}
	unknown := model.RequestLog{Action: "block", ResponseCode: 403}
	DescribeDecision(&unknown)
	if unknown.DecisionSource != "unknown" {
		t.Fatal("invented a source for an old 403")
	}
	actual := model.RequestLog{Action: "block", DecisionSource: "ipban", DecisionReason: "known"}
	DescribeDecision(&actual)
	if actual.SourceInferred || actual.DecisionReason != "known" {
		t.Fatal("overwrote recorded evidence")
	}
}
