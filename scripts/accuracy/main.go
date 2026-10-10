// Offline rule evaluation: fixture data is never executed or sent over the network.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fly12323/RWAF/pkg/coraza"
	"gopkg.in/yaml.v3"
)

type sample struct {
	ID          string            `json:"id"`
	Dataset     string            `json:"dataset"`
	Category    string            `json:"category"`
	Scenario    string            `json:"scenario"`
	Source      string            `json:"source"`
	Method      string            `json:"method"`
	URI         string            `json:"uri"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ExpectedIDs []int             `json:"expected_ids,omitempty"`
}
type outcome struct {
	ID              string   `json:"id"`
	Dataset         string   `json:"dataset"`
	Category        string   `json:"category"`
	PL              int      `json:"pl"`
	Threshold       int      `json:"threshold"`
	Blocked         bool     `json:"blocked"`
	Score           int      `json:"score"`
	RuleIDs         []string `json:"rule_ids"`
	ExpectedMatched bool     `json:"expected_matched"`
	Error           string   `json:"error,omitempty"`
}
type count struct {
	N               int `json:"n"`
	Blocked         int `json:"blocked"`
	Errors          int `json:"errors"`
	ExpectedMatched int `json:"expected_matched"`
}
type result struct {
	PL        int               `json:"pl"`
	Threshold int               `json:"threshold"`
	Groups    map[string]*count `json:"groups"`
}
type report struct {
	Experiment        string         `json:"experiment"`
	GeneratedAt       string         `json:"generated_at"`
	CorpusSHA256      string         `json:"corpus_sha256"`
	RulesSHA256       string         `json:"rules_sha256"`
	RegressionSkipped map[string]int `json:"regression_skipped"`
	Results           []result       `json:"results"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	root := flag.String("root", ".", "repository root")
	out := flag.String("out", "output/accuracy/2026-10-10", "artifact directory")
	inputPath := flag.String("input", "output/accuracy/2026-10-10/input.json", "curated input corpus")
	diagnosticJSON := flag.Bool("diagnostic-json", false, "temporary JSON processor selector; no production changes")
	curatedOnly := flag.Bool("curated-only", false, "omit official regression fixtures")
	flag.Parse()
	crs, err := filepath.Abs(filepath.Join(*root, "configs/rules/crs"))
	if err != nil {
		return err
	}
	custom, err := os.MkdirTemp("", "rwaf-accuracy-")
	if err != nil {
		return err
	}
	defer os.Remove(custom)
	experiment := "baseline"
	if *diagnosticJSON {
		experiment = "temporary-json-selector"
		directive := `SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^application/(?:[a-z0-9.-]+\+)?json(?:\s*;|$)" "id:1000000002,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"`
		diagnosticPath := filepath.Join(custom, "diagnostic.conf")
		if err := os.WriteFile(diagnosticPath, []byte(directive), 0600); err != nil {
			return err
		}
		defer os.Remove(diagnosticPath)
	}
	e, err := coraza.NewWAFEngine(&coraza.WAFConfig{CrsDir: crs, CustomRulesDir: custom, EngineMode: "On", RequestBodyLimit: 1024 * 1024})
	if err != nil {
		return err
	}
	defer e.StopFileWatcher()
	if err := os.MkdirAll(*out, 0755); err != nil {
		return err
	}
	input, err := os.ReadFile(*inputPath)
	if err != nil {
		return err
	}
	var samples []sample
	if err := json.Unmarshal(input, &samples); err != nil {
		return err
	}
	var reg []sample
	skipped := map[string]int{}
	if !*curatedOnly {
		reg, skipped, err = regression(crs)
		if err != nil {
			return err
		}
	} else {
		skipped["regression-omitted"] = 1
	}
	samples = append(samples, reg...)
	corpus, err := json.MarshalIndent(samples, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "corpus.json"), corpus, 0644); err != nil {
		return err
	}
	sum := sha256.Sum256(corpus)
	rulehash := sha256.New()
	files, _ := filepath.Glob(filepath.Join(crs, "rules", "*.conf"))
	files = append(files, filepath.Join(crs, "crs-setup.conf"))
	sort.Strings(files)
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		rulehash.Write([]byte(filepath.Base(file)))
		rulehash.Write([]byte{0})
		rulehash.Write(b)
	}
	rep := report{Experiment: experiment, GeneratedAt: time.Now().UTC().Format(time.RFC3339), CorpusSHA256: hex.EncodeToString(sum[:]), RulesSHA256: hex.EncodeToString(rulehash.Sum(nil)), RegressionSkipped: skipped}
	f, err := os.Create(filepath.Join(*out, "outcomes.jsonl"))
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	fmt.Printf("corpus=%d curated=%d regression=%d skipped=%v\n", len(samples), len(samples)-len(reg), len(reg), skipped)
	for _, threshold := range []int{5, 10, 15} {
		for pl := 1; pl <= 4; pl++ {
			if _, err := e.PolicyEngine("block", nil, nil, threshold, pl); err != nil {
				return err
			}
			r := result{PL: pl, Threshold: threshold, Groups: map[string]*count{}}
			for _, s := range samples {
				o, err := evaluate(e, s, pl, threshold)
				if err != nil {
					o.Error = err.Error()
				}
				if err := enc.Encode(o); err != nil {
					return err
				}
				for _, key := range []string{s.Dataset, s.Dataset + "/" + s.Category} {
					c := r.Groups[key]
					if c == nil {
						c = &count{}
						r.Groups[key] = c
					}
					c.N++
					if o.Error != "" {
						c.Errors++
					} else {
						if o.Blocked {
							c.Blocked++
						}
						if o.ExpectedMatched {
							c.ExpectedMatched++
						}
					}
				}
			}
			rep.Results = append(rep.Results, r)
			fmt.Printf("PL%d threshold=%d basic=%+v complex=%+v attack=%+v regression=%+v\n", pl, threshold, r.Groups["benign-basic"], r.Groups["benign-complex"], r.Groups["attack-probe"], r.Groups["crs-positive"])
			b, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(*out, "summary.json"), b, 0644); err != nil {
				return err
			}
		}
	}
	return nil
}
func evaluate(e *coraza.WAFEngine, s sample, pl, threshold int) (outcome, error) {
	o := outcome{ID: s.ID, Dataset: s.Dataset, Category: s.Category, PL: pl, Threshold: threshold, RuleIDs: []string{}}
	tx, err := e.NewTransactionWithPolicy("block", nil, nil, threshold, pl)
	if err != nil {
		return o, err
	}
	defer tx.Close()
	tx.ProcessConnection("192.0.2.10", 34567, "192.0.2.20", 80)
	tx.ProcessURI(s.URI, s.Method, "HTTP/1.1")
	tx.AddRequestHeader("Host", "accuracy.example.test")
	keys := make([]string, 0, len(s.Headers))
	for k := range s.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !strings.EqualFold(k, "Host") {
			tx.AddRequestHeader(k, s.Headers[k])
		}
	}
	it := tx.ProcessRequestHeaders()
	if it == nil {
		it, err = tx.InspectRequestBody([]byte(s.Body))
		if err != nil {
			return o, err
		}
	}
	o.Score = tx.GetRiskScore()
	o.Blocked = it != nil || o.Score >= threshold
	seen := map[int]bool{}
	for _, m := range tx.GetMatchedRuleDetails() {
		o.RuleIDs = append(o.RuleIDs, m.RuleID)
		id, _ := strconv.Atoi(m.RuleID)
		seen[id] = true
	}
	o.ExpectedMatched = len(s.ExpectedIDs) > 0
	for _, id := range s.ExpectedIDs {
		if !seen[id] {
			o.ExpectedMatched = false
		}
	}
	return o, nil
}
func regression(crs string) ([]sample, map[string]int, error) {
	files, err := filepath.Glob(filepath.Join(crs, "tests/regression/tests/REQUEST-*/*.yaml"))
	if err != nil {
		return nil, nil, err
	}
	skipped := map[string]int{}
	var out []sample
	for _, file := range files {
		name := filepath.Base(filepath.Dir(file))
		attack := false
		for _, prefix := range []string{"REQUEST-930-", "REQUEST-931-", "REQUEST-932-", "REQUEST-933-", "REQUEST-934-", "REQUEST-941-", "REQUEST-942-", "REQUEST-943-", "REQUEST-944-"} {
			if strings.HasPrefix(name, prefix) {
				attack = true
			}
		}
		if !attack {
			continue
		}
		b, err := os.ReadFile(file)
		if err != nil {
			skipped["unreadable-file"]++
			continue
		}
		var doc struct {
			Tests []struct {
				ID     int `yaml:"test_id"`
				Stages []struct {
					Input  map[string]any `yaml:"input"`
					Output struct {
						Log struct {
							Expected []int `yaml:"expect_ids"`
						} `yaml:"log"`
					} `yaml:"output"`
				} `yaml:"stages"`
			} `yaml:"tests"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		for _, test := range doc.Tests {
			if len(test.Stages) != 1 {
				skipped["multi-stage"]++
				continue
			}
			stage := test.Stages[0]
			in := stage.Input
			if len(stage.Output.Log.Expected) == 0 {
				skipped["non-positive"]++
				continue
			}
			bad := false
			for k := range in {
				switch k {
				case "dest_addr", "port", "uri", "method", "version", "headers", "data":
				default:
					bad = true
				}
			}
			if bad {
				skipped["special-input"]++
				continue
			}
			uri, ok := in["uri"].(string)
			if !ok || !strings.HasPrefix(uri, "/") {
				skipped["unsupported-uri"]++
				continue
			}
			if v, ok := in["version"].(string); ok && v != "HTTP/1.1" {
				skipped["unsupported-http-version"]++
				continue
			}
			method, _ := in["method"].(string)
			if method == "" {
				method = "GET"
			}
			body := ""
			if data, present := in["data"]; present {
				var ok bool
				body, ok = data.(string)
				if !ok {
					skipped["non-string-body"]++
					continue
				}
			}
			headers := map[string]string{}
			if raw, present := in["headers"]; present {
				h, ok := raw.(map[string]any)
				if !ok {
					skipped["unsupported-headers"]++
					continue
				}
				for k, v := range h {
					str, ok := v.(string)
					if !ok {
						bad = true
					}
					headers[k] = str
				}
			}
			if bad {
				skipped["non-string-header"]++
				continue
			}
			if body != "" {
				if _, ok := headers["Content-Type"]; !ok {
					headers["Content-Type"] = "application/x-www-form-urlencoded"
				}
				headers["Content-Length"] = strconv.Itoa(len(body))
			}
			out = append(out, sample{ID: name + "/" + filepath.Base(file) + "/" + strconv.Itoa(test.ID), Dataset: "crs-positive", Category: name, Scenario: "CRS 正向规则回归，不等同有效攻击 ground truth", Source: filepath.ToSlash(file), Method: method, URI: uri, Headers: headers, Body: body, ExpectedIDs: stage.Output.Log.Expected})
		}
	}
	return out, skipped, nil
}
