// Disposable Docker-network functional and throughput harness.
package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Check struct {
	Name   string
	Pass   bool
	Detail string
}
type Result struct {
	Name          string
	Concurrency   int
	Requests      int
	Seconds       float64
	RPS           float64
	P50Ms         float64
	P95Ms         float64
	P99Ms         float64
	Errors        int
	Unexpected    int
	Statuses      map[int]int
	Before, After map[string]any
}
type Report struct {
	Started string
	Checks  []Check
	Results []Result
	Final   map[string]any
}

var report = Report{Started: time.Now().UTC().Format(time.RFC3339)}
var token string
var client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 512, MaxIdleConnsPerHost: 256}}

const apiBase = "http://waf:8080/api/v1"
const siteBase = "http://waf:9000"
const attack = "/?id=1%20UNION%20SELECT%20username%20FROM%20users"

func request(method, target string, body []byte, auth string, ua string) (int, []byte, error) {
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", ua)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return res.StatusCode, b, err
}
func api(method, path string, body any) (map[string]any, error) {
	b, _ := json.Marshal(body)
	status, data, err := request(method, apiBase+path, b, token, "Mozilla/5.0")
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err = json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("status=%d body=%s", status, data)
	}
	if status != 200 || v["code"] != float64(0) {
		return v, fmt.Errorf("status=%d code=%v message=%v", status, v["code"], v["message"])
	}
	return v, nil
}
func must(method, path string, body any) map[string]any {
	v, e := api(method, path, body)
	if e != nil {
		panic(path + ": " + e.Error())
	}
	return v
}
func data(v map[string]any) map[string]any { return v["data"].(map[string]any) }
func check(name string, pass bool, detail any) {
	c := Check{name, pass, fmt.Sprint(detail)}
	report.Checks = append(report.Checks, c)
	fmt.Printf("CHECK %s pass=%v %v\n", name, pass, detail)
}
func expect(name, method, target string, body []byte, want int) {
	s, b, e := request(method, target, body, "", "Mozilla/5.0")
	check(name, e == nil && s == want, fmt.Sprintf("status=%d expected=%d error=%v bytes=%d", s, want, e, len(b)))
}
func stats() map[string]any {
	s, b, e := request("GET", "http://waf:8080/health/ready", nil, "", "Mozilla/5.0")
	if e != nil || s != 200 {
		return map[string]any{"error": fmt.Sprint(e)}
	}
	var v map[string]any
	json.Unmarshal(b, &v)
	return v["events"].(map[string]any)
}
func updatePolicy(extra map[string]any) {
	cfg := data(must("GET", "/waf/protection", nil))
	for k, v := range extra {
		cfg[k] = v
	}
	must("PUT", "/waf/protection", cfg)
}
func security(extra map[string]any) {
	v := map[string]any{"enabled": true, "rule_engine_enabled": true, "crawler_detection_enabled": true, "crawler_scanner_action": "log", "crawler_bot_action": "log", "crawler_crawler_action": "log", "cc_protection_enabled": true, "cc_requests_per_minute": 1000000, "cc_action": "block", "auto_block_enabled": false, "ip_blacklist_enabled": true, "ip_whitelist_enabled": true}
	for k, x := range extra {
		v[k] = x
	}
	updatePolicy(v)
}

func drain() {
	if os.Getenv("BENCH_SKIP_DRAIN") == "1" {
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		s := stats()
		accepted, _ := s["accepted"].(float64)
		recovered, _ := s["recovered"].(float64)
		if s["queued"] == float64(0) && accepted+recovered == s["published"] {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}
func benchmark(name, target, method string, body []byte, concurrency int, duration time.Duration, want int) {
	drain()
	r := Result{Name: name, Concurrency: concurrency, Statuses: map[int]int{}, Before: stats()}
	var mu sync.Mutex
	var latencies []float64
	var wg sync.WaitGroup
	start := time.Now()
	deadline := start.Add(duration)
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			local := make([]float64, 0, 10000)
			counts := map[int]int{}
			errs := 0
			unexpected := 0
			for time.Now().Before(deadline) {
				t := time.Now()
				s, _, e := request(method, target, body, "", "Mozilla/5.0")
				local = append(local, float64(time.Since(t).Microseconds())/1000)
				counts[s]++
				if e != nil {
					errs++
				} else if s != want {
					unexpected++
				}
			}
			mu.Lock()
			latencies = append(latencies, local...)
			for s, n := range counts {
				r.Statuses[s] += n
			}
			r.Errors += errs
			r.Unexpected += unexpected
			mu.Unlock()
		}()
	}
	wg.Wait()
	r.Seconds = time.Since(start).Seconds()
	r.Requests = len(latencies)
	r.RPS = float64(r.Requests) / r.Seconds
	sort.Float64s(latencies)
	percentile := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		return latencies[int(float64(len(latencies)-1)*p)]
	}
	r.P50Ms = percentile(.50)
	r.P95Ms = percentile(.95)
	r.P99Ms = percentile(.99)
	drain()
	r.After = stats()
	report.Results = append(report.Results, r)
	b, _ := json.Marshal(r)
	fmt.Printf("RESULT %s\n", b)
	save()
}
func save() {
	b, _ := json.MarshalIndent(report, "", "  ")
	name := os.Getenv("BENCH_REPORT")
	if name == "" {
		name = "report.json"
	}
	if e := os.WriteFile("/out/"+name, b, 0644); e != nil {
		fmt.Println(e)
	}
}

// Parent orchestrates faults only in the disposable Compose project.
func faultWatch() {
	token = data(must("POST", "/auth/login", map[string]any{"username": "admin", "password": "Bench-Setup!2026-Safe"}))["token"].(string)
	cfg := data(must("GET", "/monitor/config", nil))
	cfg["interval_seconds"] = 5
	cfg["consumer_timeout_seconds"] = 15
	must("PUT", "/monitor/config", cfg)
	warmDeadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(warmDeadline) {
		live := data(must("GET", "/monitor/status", nil))
		consumer, _ := live["consumer"].(map[string]any)
		deps, _ := live["dependencies"].(map[string]any)
		if consumer != nil && consumer["stale"] == false && deps["postgres"] == "ok" && deps["kafka"] == "ok" {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	for _, phase := range []string{"consumer-down", "consumer-up", "postgres-down", "postgres-up", "kafka-down", "kafka-up"} {
		fmt.Println("FAULT READY " + phase)
		deadline := time.Now().Add(75 * time.Second)
		observed := false
		for time.Now().Before(deadline) {
			value, err := api("GET", "/monitor/status", nil)
			if err == nil {
				live := data(value)
				deps, _ := live["dependencies"].(map[string]any)
				consumer, _ := live["consumer"].(map[string]any)
				switch phase {
				case "consumer-down":
					observed = consumer == nil || consumer["stale"] == true
				case "consumer-up":
					observed = consumer != nil && consumer["stale"] == false
				case "postgres-down":
					observed = deps["postgres"] == "unavailable" && live["alert_store_error"] == true
				case "postgres-up":
					observed = deps["postgres"] == "ok" && live["alert_store_error"] == false
				case "kafka-down":
					observed = deps["kafka"] == "unavailable"
				case "kafka-up":
					observed = deps["kafka"] == "ok"
				}
				if observed {
					check("fault "+phase, true, live)
					break
				}
			}
			time.Sleep(300 * time.Millisecond)
		}
		if !observed {
			check("fault "+phase, false, "timed out")
			return
		}
	}
	rows := data(must("GET", "/monitor/alerts?source=runtime&status=resolved&page_size=100", nil))["list"].([]any)
	keys := map[string]bool{}
	for _, row := range rows {
		keys[row.(map[string]any)["key"].(string)] = true
	}
	check("dependency failures and recoveries persisted", keys["consumer_stale"] && keys["postgres_unavailable"] && keys["kafka_unavailable"], keys)
	cfg["interval_seconds"] = 15
	cfg["consumer_timeout_seconds"] = 30
	must("PUT", "/monitor/config", cfg)
}
func detectionLoad() {
	token = data(must("POST", "/auth/login", map[string]any{"username": "admin", "password": "Bench-Setup!2026-Safe"}))["token"].(string)
	site := data(must("POST", "/sites", map[string]any{"name": "detection-load", "listen_port": 9000, "upstream_targets": []any{map[string]any{"host": "bench", "port": 8081, "weight": 1}}}))
	id := fmt.Sprintf("%.0f", site["id"])
	security(nil)
	cfg := data(must("GET", "/weak-password/config", nil))
	for round := 1; round <= 2; round++ {
		for _, enabled := range []bool{false, true} {
			cfg["enabled"] = enabled
			must("PUT", "/weak-password/config", cfg)
			label := "off"
			if enabled {
				label = "on"
			}
			benchmark(fmt.Sprintf("normal-detector-%s-%d", label, round), siteBase+"/", "GET", nil, 32, 4*time.Second, 200)
			benchmark(fmt.Sprintf("login-detector-%s-%d", label, round), siteBase+"/login", "POST", []byte(`{"password":"a unique strong passphrase here"}`), 32, 4*time.Second, 200)
		}
	}
	cfg["enabled"] = true
	must("PUT", "/weak-password/config", cfg)
	must("DELETE", "/sites/"+id, nil)
	_, v, _ := request("GET", apiBase+"/weak-password/events", nil, token, "Mozilla/5.0")
	var parsed map[string]any
	json.Unmarshal(v, &parsed)
	check("load detector stats available", parsed["code"] == float64(0), parsed["data"])
}

func detectionChecks() {
	_, err := api("POST", "/users", map[string]any{"username": "weak-account", "password": "123456", "role": "auditor"})
	check("management rejects weak password on create", err != nil, err)
	_, err = api("POST", "/auth/password", map[string]any{"old_password": "Bench-Setup!2026-Safe", "new_password": "Password12345!"})
	check("management rejects weak password on change", err != nil, err)
	user := data(must("POST", "/users", map[string]any{"username": "reset-check", "password": "Unique-Temporary!2026", "role": "auditor"}))
	uid := fmt.Sprintf("%.0f", user["id"])
	_, err = api("POST", "/users/"+uid+"/reset-password", map[string]any{"password": "111111111111"})
	check("management rejects weak password on reset", err != nil, err)
	must("DELETE", "/users/"+uid, nil)
	weak := data(must("GET", "/weak-password/config", nil))
	original, _ := json.Marshal(weak)
	weak["endpoints"] = []any{map[string]any{"name": "bench-login", "host": "", "path": "/login", "method": "POST", "kind": "login", "format": "auto", "password_fields": []string{"password"}}, map[string]any{"name": "bench-nested", "host": "", "path": "/api/login", "method": "POST", "kind": "login", "format": "json", "password_fields": []string{"data.password"}}, map[string]any{"name": "bench-echo", "host": "", "path": "/echo", "method": "POST", "kind": "register", "format": "auto", "password_fields": []string{"password"}}}
	weak["enabled"] = true
	must("PUT", "/weak-password/config", weak)
	security(map[string]any{"rule_engine_enabled": false, "crawler_detection_enabled": false, "cc_protection_enabled": false})
	md := md5.Sum([]byte("123456"))
	sha := sha1.Sum([]byte("123456"))
	sha256sum := sha256.Sum256([]byte("123456"))
	candidates := []string{"123456", strings.ToUpper(hex.EncodeToString(md[:])), hex.EncodeToString(sha[:]), hex.EncodeToString(sha256sum[:]), base64.StdEncoding.EncodeToString([]byte("password")), base64.RawURLEncoding.EncodeToString([]byte("admin123"))}
	for i, value := range candidates {
		body, _ := json.Marshal(map[string]string{"password": value})
		expect(fmt.Sprintf("weak representation %d keeps forwarding", i), "POST", siteBase+"/login", body, 200)
	}
	expect("nested password keeps forwarding", "POST", siteBase+"/api/login", []byte(`{"data":{"password":"123456"}}`), 200)
	body := []byte(`{"password":"123456","token":"private-response-token"}`)
	req, _ := http.NewRequest("POST", siteBase+"/echo", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "session=private-cookie")
	req.Header.Set("Authorization", "Bearer private-authorization")
	res, err := client.Do(req)
	rid := ""
	if err == nil {
		rid = res.Header.Get("X-Request-ID")
		response, _ := io.ReadAll(res.Body)
		res.Body.Close()
		check("authentication request forwards unchanged", res.StatusCode == 200 && bytes.Equal(response, body), res.StatusCode)
	} else {
		check("authentication request forwards unchanged", false, err)
	}
	form, _ := http.NewRequest("POST", siteBase+"/login", strings.NewReader("password=cGFzc3dvcmQ%3D"))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err = client.Do(form)
	if err == nil {
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}
	check("form weak password keeps forwarding", err == nil && res.StatusCode == 200, err)
	expect("strong password forwards", "POST", siteBase+"/login", []byte(`{"password":"a unique strong secret here"}`), 200)
	expect("weak text outside password forwards", "POST", siteBase+"/products", []byte(`{"password":"123456"}`), 200)
	expect("weak substring forwards", "POST", siteBase+"/login", []byte(`{"password":"x123456x"}`), 200)
	deadline := time.Now().Add(20 * time.Second)
	var eventsData map[string]any
	for time.Now().Before(deadline) {
		eventsData = data(must("GET", "/weak-password/events?page_size=100", nil))
		if eventsData["total"].(float64) >= 9 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	check("weak events persisted without false positives", eventsData["total"] == float64(9), eventsData["total"])
	rows := eventsData["list"].([]any)
	private := false
	unknown := true
	for _, row := range rows {
		v := row.(map[string]any)
		unknown = unknown && v["outcome"] == "unknown"
		raw, _ := json.Marshal(v)
		private = private || strings.Contains(string(raw), "123456") || strings.Contains(string(raw), "private-response-token")
	}
	check("weak events do not contain passwords", !private, "")
	check("weak events do not infer login success from 200", unknown, "")
	logs := data(must("GET", "/logs?page_size=100", nil))["list"].([]any)
	captured := false
	for _, row := range logs {
		v := row.(map[string]any)
		if v["request_id"] == rid {
			detail := data(must("GET", "/logs/"+fmt.Sprintf("%.0f", v["id"]), nil))
			raw, _ := json.Marshal(detail)
			text := string(raw)
			captured = strings.Contains(text, "private-cookie") && strings.Contains(text, "private-authorization") && strings.Contains(text, base64.StdEncoding.EncodeToString(body))
			break
		}
	}
	check("authentication logs preserve configured raw capture", captured, "")
	weak["enabled"] = false
	must("PUT", "/weak-password/config", weak)
	expect("disabled weak detection forwards", "POST", siteBase+"/login", []byte(`{"password":"123456"}`), 200)
	time.Sleep(600 * time.Millisecond)
	check("disabled weak detection adds no events", data(must("GET", "/weak-password/events", nil))["total"] == float64(9), "")
	var restore map[string]any
	json.Unmarshal(original, &restore)
	must("PUT", "/weak-password/config", restore)
	security(nil)
	alerts := data(must("GET", "/monitor/alerts?source=weak_password", nil))["list"].([]any)
	check("weak submissions create aggregated alerts", len(alerts) == 3, len(alerts))
	if len(alerts) > 0 {
		a := alerts[0].(map[string]any)
		aid := fmt.Sprintf("%.0f", a["id"])
		must("POST", "/monitor/alerts/"+aid+"/acknowledge", nil)
		must("POST", "/monitor/alerts/"+aid+"/resolve", nil)
		check("weak alert acknowledgement and resolution", true, "")
	}
	monitor := data(must("GET", "/monitor/config", nil))
	monitor["interval_seconds"] = 5
	monitor["heap_limit_mb"] = 1
	must("PUT", "/monitor/config", monitor)
	deadline = time.Now().Add(30 * time.Second)
	var live map[string]any
	for time.Now().Before(deadline) {
		live = data(must("GET", "/monitor/status", nil))
		conditions, _ := live["conditions"].([]any)
		hasHeap := false
		for _, c := range conditions {
			hasHeap = hasHeap || c.(map[string]any)["key"] == "heap"
		}
		if hasHeap {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	deps, _ := live["dependencies"].(map[string]any)
	check("monitor probes PostgreSQL Redis Kafka", deps["postgres"] == "ok" && deps["redis"] == "ok" && deps["kafka"] == "ok", deps)
	check("monitor measures Kafka consumer lag", live["kafka_lag"] != nil, live["kafka_lag"])
	consumer, _ := live["consumer"].(map[string]any)
	check("monitor sees consumer heartbeat", consumer != nil && consumer["stale"] == false, consumer)
	runtimeAlerts := data(must("GET", "/monitor/alerts?source=runtime&status=open", nil))["list"].([]any)
	heapID := ""
	for _, row := range runtimeAlerts {
		v := row.(map[string]any)
		if v["key"] == "heap" {
			heapID = fmt.Sprintf("%.0f", v["id"])
		}
	}
	check("runtime threshold creates alert", heapID != "", runtimeAlerts)
	if heapID != "" {
		must("POST", "/monitor/alerts/"+heapID+"/acknowledge", nil)
	}
	monitor["heap_limit_mb"] = 512
	must("PUT", "/monitor/config", monitor)
	deadline = time.Now().Add(15 * time.Second)
	recovered := false
	for time.Now().Before(deadline) {
		rows := data(must("GET", "/monitor/alerts?source=runtime&status=resolved", nil))["list"].([]any)
		for _, row := range rows {
			v := row.(map[string]any)
			if v["key"] == "heap" {
				recovered = true
			}
		}
		if recovered {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	check("runtime alert recovers automatically", recovered, "")
	monitor["interval_seconds"] = 15
	must("PUT", "/monitor/config", monitor)
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "backend" {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			if r.URL.Path == "/echo" {
				io.Copy(w, r.Body)
			} else {
				io.WriteString(w, strings.Repeat("x", 1024))
			}
		})
		panic(http.ListenAndServe(":8081", nil))
	}
	defer func() {
		if e := recover(); e != nil {
			check("harness completion", false, e)
		}
		report.Final = stats()
		save()
		failed := false
		for _, c := range report.Checks {
			failed = failed || !c.Pass
		}
		for _, r := range report.Results {
			failed = failed || r.Errors != 0 || r.Unexpected != 0
		}
		if failed {
			os.Exit(1)
		}
	}()
	if len(os.Args) > 1 && os.Args[1] == "fault-watch" {
		faultWatch()
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "readiness-load" || os.Args[1] == "readiness-fault") {
		readinessLoad(os.Args[1] == "readiness-fault")
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "detection-load" {
		detectionLoad()
		return
	}
	for i := 0; i < 60; i++ {
		s, _, e := request("GET", "http://waf:8080/health/ready", nil, "", "Mozilla/5.0")
		if e == nil && s == 200 {
			break
		}
		time.Sleep(time.Second)
	}
	_, e := api("GET", "/sites", nil)
	check("unauthenticated access rejected", e != nil, e)
	_, e = api("POST", "/auth/login", map[string]any{"username": "admin", "password": "wrong"})
	check("invalid password rejected", e != nil, e)
	login := must("POST", "/auth/login", map[string]any{"username": "admin", "password": "Bench-Setup!2026-Safe"})
	token = data(login)["token"].(string)
	check("admin login", true, "")
	for _, path := range []string{"/auth/info", "/sites", "/users", "/rules", "/rules/categories", "/rules/statistics", "/ip-blacklist", "/ip-whitelist", "/cc-protection", "/waf/status", "/operation-logs", "/operation-logs/statistics", "/operation-logs/actions", "/crawler/stats", "/crawler/logs", "/crawler/trend", "/crawler/top-ips"} {
		_, e := api("GET", path, nil)
		check("GET "+path, e == nil, e)
	}
	site := data(must("POST", "/sites", map[string]any{"name": "isolated-benchmark", "listen_port": 9000, "upstream_targets": []any{map[string]any{"host": "bench", "port": 8081, "weight": 1}}}))
	id := fmt.Sprintf("%.0f", site["id"])
	check("site create", true, id)
	updatePolicy(map[string]any{"waf_mode": "block", "score_threshold": 15, "disabled_rule_ids": []string{}, "enabled_rule_categories": []string{}})
	for _, name := range []string{"waf_mode", "score_threshold", "waf_enabled", "enabled_rule_categories", "disabled_rule_ids"} {
		_, exists := site[name]
		check("site does not expose "+name, !exists, "")
	}
	for _, tc := range []struct{ method, path string }{{"GET", "/sites/" + id + "/security"}, {"PUT", "/sites/" + id + "/security"}, {"PUT", "/sites/" + id + "/waf-status"}} {
		status, _, err := request(tc.method, apiBase+tc.path, []byte(`{}`), token, "Mozilla/5.0")
		check("removed site API "+tc.path, err == nil && status == 404, status)
	}
	second := data(must("POST", "/sites", map[string]any{"name": "second-shared-policy", "listen_port": 9002, "upstream_targets": []any{map[string]any{"host": "bench", "port": 8081, "weight": 1}}}))
	secondID := fmt.Sprintf("%.0f", second["id"])
	updatePolicy(map[string]any{"enabled": false})
	expect("global off keeps first site forwarding", "GET", siteBase+attack, nil, 200)
	expect("global off keeps second site forwarding", "GET", "http://waf:9002"+attack, nil, 200)
	security(nil)
	expect("global on blocks first site", "GET", siteBase+attack, nil, 403)
	expect("global on blocks second site", "GET", "http://waf:9002"+attack, nil, 403)
	updatePolicy(map[string]any{"waf_mode": "monitor"})
	expect("global monitor first site", "GET", siteBase+attack, nil, 200)
	expect("global monitor second site", "GET", "http://waf:9002"+attack, nil, 200)
	updatePolicy(map[string]any{"waf_mode": "block"})
	must("DELETE", "/sites/"+secondID, nil)
	security(nil)
	expect("normal GET", "GET", siteBase+"/", nil, 200)
	expect("JSON POST", "POST", siteBase+"/echo", []byte(`{"message":"hello"}`), 200)
	for name, payload := range map[string]string{"SQLi": "1 UNION SELECT username FROM users", "XSS": "<script>alert(1)</script>", "LFI": "../../../../etc/passwd", "command injection": ";cat /etc/passwd"} {
		expect(name, "GET", siteBase+"/?id="+url.QueryEscape(payload), nil, 403)
	}
	expect("request body limit", "POST", siteBase+"/echo", bytes.Repeat([]byte("a"), 10485761), 413)
	updatePolicy(map[string]any{"waf_mode": "monitor"})
	expect("monitor forwards attack", "GET", siteBase+attack, nil, 200)
	updatePolicy(map[string]any{"waf_mode": "block"})
	conflict, err := api("POST", "/sites", map[string]any{"name": "port-conflict", "listen_port": 9000, "upstream_targets": []any{map[string]any{"host": "bench", "port": 8081, "weight": 1}}})
	check("port conflict rejected", err != nil, conflict["message"])
	security(map[string]any{"cc_requests_per_minute": 1})
	expect("CC rejects over quota", "GET", siteBase+"/", nil, 429)
	security(nil)
	s, _, _ := request("GET", "http://bench:8081/", nil, "", "Mozilla/5.0")
	check("backend direct", s == 200, s)
	// Exercise writes and policy changes, not just read-only management routes.
	conn, err := net.Dial("udp", "waf:8080")
	if err != nil {
		panic(err)
	}
	clientIP := conn.LocalAddr().(*net.UDPAddr).IP.String()
	conn.Close()
	black := data(must("POST", "/ip-blacklist", map[string]any{"ip": clientIP, "reason": "isolated test"}))
	blackID := fmt.Sprintf("%.0f", black["id"])
	expect("IP blacklist blocks", "GET", siteBase+"/", nil, 403)
	white := data(must("POST", "/ip-whitelist", map[string]any{"ip": clientIP, "reason": "isolated test"}))
	whiteID := fmt.Sprintf("%.0f", white["id"])
	expect("IP whitelist takes precedence", "GET", siteBase+attack, nil, 200)
	must("DELETE", "/ip-whitelist/"+whiteID, nil)
	must("DELETE", "/ip-blacklist/"+blackID, nil)
	security(map[string]any{"crawler_scanner_action": "block"})
	s, _, err = request("GET", siteBase+"/", nil, "", "sqlmap/1.7")
	check("scanner UA blocked", err == nil && s == 403, s)
	security(nil)
	cc := data(must("GET", "/cc-protection", nil))
	cc["enabled"] = true
	cc["requests_per_minute"] = 1000000
	cc["action"] = "block"
	cc["uri_limits"] = `[{"uri":"/cc-test","requests_per_minute":1,"action":"block"}]`
	cc = data(must("PUT", "/cc-protection", cc))
	expect("URI quota first request", "GET", siteBase+"/cc-test", nil, 200)
	expect("URI quota second request", "GET", siteBase+"/cc-test", nil, 429)
	cc["uri_limits"] = "[]"
	must("PUT", "/cc-protection", cc)
	security(map[string]any{"cc_requests_per_minute": 1, "cc_action": "delay", "cc_delay_ms": 100})
	t := time.Now()
	expect("CC delay forwards", "GET", siteBase+"/", nil, 200)
	check("CC delay duration", time.Since(t) >= 80*time.Millisecond, time.Since(t))
	security(nil)
	rule := data(must("POST", "/rules", map[string]any{"rule_id": "300001", "enabled": true, "category": "custom", "severity": "CRITICAL", "rule_content": `SecRule REQUEST_URI "@contains benchmark-deny" "id:300001,phase:1,deny,status:403,severity:CRITICAL"`}))
	ruleID := fmt.Sprintf("%.0f", rule["id"])
	must("POST", "/rules/reload", nil)
	expect("custom rule reload", "GET", siteBase+"/benchmark-deny", nil, 403)
	updatePolicy(map[string]any{"disabled_rule_ids": []string{"300001"}})
	expect("global disabled rule", "GET", siteBase+"/benchmark-deny", nil, 200)
	updatePolicy(map[string]any{"disabled_rule_ids": []string{}, "enabled_rule_categories": []string{"sqli"}})
	expect("global category selection", "GET", siteBase+"/benchmark-deny", nil, 200)
	updatePolicy(map[string]any{"enabled_rule_categories": []string{}})
	must("DELETE", "/rules/"+ruleID, nil)
	must("POST", "/rules/reload", nil)
	auditor := data(must("POST", "/users", map[string]any{"username": "bench-auditor", "password": "Bench-test-only-123", "role": "auditor"}))
	adminToken := token
	token = data(must("POST", "/auth/login", map[string]any{"username": "bench-auditor", "password": "Bench-test-only-123"}))["token"].(string)
	_, err = api("GET", "/logs", nil)
	check("auditor can read logs", err == nil, err)
	_, err = api("POST", "/sites", map[string]any{"name": "forbidden"})
	check("auditor cannot create site", err != nil, err)
	_, err = api("GET", "/users", nil)
	check("auditor cannot list users", err != nil, err)
	_, err = api("GET", "/weak-password/events", nil)
	check("auditor can read weak events", err == nil, err)
	_, err = api("GET", "/monitor/status", nil)
	check("auditor can read monitoring", err == nil, err)
	_, err = api("PUT", "/weak-password/config", map[string]any{})
	check("auditor cannot change detection", err != nil, err)
	_, err = api("PUT", "/monitor/config", map[string]any{})
	check("auditor cannot change monitoring", err != nil, err)
	must("POST", "/auth/logout", nil)
	token = adminToken
	must("DELETE", "/users/"+fmt.Sprintf("%.0f", auditor["id"]), nil)
	security(map[string]any{"auto_block_enabled": true, "auto_block_threshold": 2, "auto_block_duration": 60, "auto_block_hours": 1})
	expect("auto-ban first attack", "GET", siteBase+attack, nil, 403)
	expect("auto-ban before threshold", "GET", siteBase+"/", nil, 200)
	expect("auto-ban second attack", "GET", siteBase+attack, nil, 403)
	expect("auto-ban blocks normal traffic", "GET", siteBase+"/", nil, 403)
	items := data(must("GET", "/ip-blacklist?ip="+clientIP, nil))["list"].([]any)
	for _, item := range items {
		must("DELETE", "/ip-blacklist/"+fmt.Sprintf("%.0f", item.(map[string]any)["id"]), nil)
	}
	security(nil)
	must("PUT", "/sites/"+id, map[string]any{"upstream_targets": []any{map[string]any{"host": "bench", "port": 65534, "weight": 1}}})
	expect("unavailable backend returns 502", "GET", siteBase+"/", nil, 502)
	must("PUT", "/sites/"+id, map[string]any{"upstream_targets": []any{map[string]any{"host": "bench", "port": 8081, "weight": 1}}, "listen_port": 9001})
	expect("updated site port forwards", "GET", "http://waf:9001/", nil, 200)
	s, _, err = request("GET", siteBase+"/", nil, "", "Mozilla/5.0")
	check("old site port released", err != nil, s)
	must("PUT", "/sites/"+id, map[string]any{"listen_port": 9000})
	detectionChecks()
	for _, path := range []string{"/", "/sites", "/weak-password", "/monitor", "/change-password"} {
		s, b, e := request("GET", "http://web"+path, nil, "", "Mozilla/5.0")
		check("web1 "+path, e == nil && s == 200 && strings.Contains(string(b), "<html"), s)
	}
	_, html, _ := request("GET", "http://web/", nil, "", "Mozilla/5.0")
	if parts := strings.Split(string(html), `src="`); len(parts) > 1 {
		asset := strings.Split(parts[1], `"`)[0]
		s, js, e := request("GET", "http://web"+asset, nil, "", "Mozilla/5.0")
		check("web1 JS asset", e == nil && s == 200 && len(js) > 1000 && !strings.Contains(string(js), "<!DOCTYPE html>"), s)
	} else {
		check("web1 JS asset", false, "missing script")
	}
	s, b, err := request("GET", "http://web/health", nil, "", "Mozilla/5.0")
	check("Nginx API proxy", err == nil && s == 200 && strings.Contains(string(b), "ok"), s)
	if os.Getenv("BENCH_SKIP_LOAD") != "1" {
		for _, c := range []int{1, 8, 32, 128} {
			benchmark("normal-full", siteBase+"/", "GET", nil, c, 10*time.Second, 200)
		}
		benchmark("backend-direct", "http://bench:8081/", "GET", nil, 128, 5*time.Second, 200)
		benchmark("SQLi-block", siteBase+attack, "GET", nil, 32, 10*time.Second, 403)
		benchmark("JSON-1KiB", siteBase+"/echo", "POST", []byte(`{"message":"`+strings.Repeat("x", 1000)+`"}`), 32, 10*time.Second, 200)
		security(map[string]any{"rule_engine_enabled": false, "crawler_detection_enabled": false, "cc_protection_enabled": false})
		benchmark("normal-no-rule-no-CC", siteBase+"/", "GET", nil, 128, 5*time.Second, 200)
	}
	security(nil)
	time.Sleep(3 * time.Second)
	for _, path := range []string{"/logs?page_size=1", "/logs/statistics", "/logs/daily", "/logs/trend", "/logs/attack-types", "/logs/attack-ips", "/crawler/recent"} {
		t := time.Now()
		v, e := api("GET", path, nil)
		check("GET "+path, e == nil, fmt.Sprintf("elapsed=%v error=%v", time.Since(t), e))
		if path == "/logs?page_size=1" && e == nil {
			list := data(v)["list"].([]any)
			if len(list) > 0 {
				lid := fmt.Sprintf("%.0f", list[0].(map[string]any)["id"])
				_, e = api("GET", "/logs/"+lid, nil)
				check("request log detail", e == nil, e)
			}
		}
	}
	must("PUT", "/sites/"+id+"/status", map[string]any{"enabled": false})
	s, _, e = request("GET", siteBase+"/", nil, "", "Mozilla/5.0")
	check("disabled site releases port", e != nil, fmt.Sprintf("status=%d error=%v", s, e))
	must("DELETE", "/sites/"+id, nil)
	check("site delete", true, "")
	must("POST", "/auth/logout", nil)
	_, e = api("GET", "/auth/info", nil)
	check("logout revokes session", e != nil, e)
}
