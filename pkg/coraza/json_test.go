package coraza

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestJSONProcessorSelectionAndDecodedArguments(t *testing.T) {
	root := t.TempDir()
	crs := filepath.Join(root, "crs")
	custom := filepath.Join(root, "custom")
	for _, dir := range []string{filepath.Join(crs, "rules"), custom} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// This rule requires a decoded nested value; inspecting raw bytes cannot pass.
	if err := os.WriteFile(filepath.Join(custom, "json.conf"), []byte(`SecRule ARGS:json.items.0.value "@streq dangerous" "id:1002,phase:2,deny,status:403,msg:'decoded nested JSON'"`), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := NewWAFEngine(&WAFConfig{CrsDir: crs, CustomRulesDir: custom, EngineMode: "On", RequestBodyLimit: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer e.StopFileWatcher()
	for _, mode := range []string{"block", "monitor"} {
		for _, ct := range []string{"application/json", "Application/JSON; charset=utf-8", "application/problem+json", "application/vnd.api+json; charset=UTF-8", "application/x_custom+json", "application/json ; charset=utf-8", "application/jsonp", "text/plain", "application/json-invalid"} {
			t.Run(mode+"/"+ct, func(t *testing.T) {
				tx, err := e.NewTransactionWithPolicy(mode, nil, nil, 5, 1)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Close()
				tx.ProcessURI("/json", "POST", "HTTP/1.1")
				tx.AddRequestHeader("Host", "example.test")
				tx.AddRequestHeader("Content-Type", ct)
				tx.ProcessRequestHeaders()
				it, err := tx.InspectRequestBody([]byte(`{"items":[{"value":"d\u0061ngerous"}]}`))
				if err != nil {
					t.Fatal(err)
				}
				want := ct != "application/jsonp" && ct != "text/plain" && ct != "application/json-invalid"
				selected := tx.tx.(interface {
					Variables() plugintypes.TransactionVariables
				}).Variables().RequestBodyProcessor().Get() == "JSON"
				matched := false
				for _, m := range tx.GetMatchedRuleDetails() {
					if m.RuleID == "1002" {
						matched = true
					}
					if m.RuleID == "1000000002" {
						t.Fatal("selector leaked into attack evidence")
					}
				}
				if selected != want || matched != want || (it != nil) != (want && mode == "block") {
					t.Fatalf("selected=%v matched=%v interruption=%v", selected, matched, it)
				}
			})
		}
	}
	if _, err := e.PolicyEngine("block", []string{"01000000002"}, nil, 5); err == nil {
		t.Fatal("reserved JSON selector disabled")
	}
	if err := e.ReloadNow(); err != nil {
		t.Fatal(err)
	}
	tx, err := e.NewTransactionWithPolicy("block", nil, []string{"sqli"}, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	tx.ProcessURI("/json", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.ProcessRequestHeaders()
	if _, err := tx.InspectRequestBody([]byte(`{"text":"\u4e2d\u6587"}`)); err != nil {
		t.Fatal(err)
	}
	if tx.tx.(interface {
		Variables() plugintypes.TransactionVariables
	}).Variables().ArgsPost().Get("json.text")[0] != "中文" {
		t.Fatal("selector lost after category filtering/reload")
	}
}

func TestJSONValidationBoundaries(t *testing.T) {
	for _, body := range []string{`{}`, `[]`, `null`, `"text"`, `123`, `true`, `{"text":"[{}]\\\""}`, strings.Repeat("[", 128) + "0" + strings.Repeat("]", 128)} {
		if err := validateJSONBody([]byte(body)); err != nil {
			t.Errorf("valid body %q: %v", body, err)
		}
	}
	for _, body := range []string{`{"x":`, `{"x":1,}`, `{"x":1} trailing`, `{} {}`, `{"x":"\uZZZZ"}`, strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129)} {
		if err := validateJSONBody([]byte(body)); err == nil {
			t.Errorf("invalid body accepted: %q", body)
		}
	}
}
