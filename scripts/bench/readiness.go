package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

func envInt(name string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(name)); err == nil && value > 0 {
		return value
	}
	return fallback
}

// Sustained acceptance distinguishes forwarding, durable acceptance, Kafka
// delivery and committed consumption. The orchestrator additionally verifies
// database counts and injects real dependency failures in a disposable stack.
func readinessLoad(fault bool) {
	for i := 0; i < 120; i++ {
		if _, err := api("POST", "/auth/login", map[string]any{"username": "admin", "password": "Bench-Setup!2026-Safe"}); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	token = data(must("POST", "/auth/login", map[string]any{"username": "admin", "password": "Bench-Setup!2026-Safe"}))["token"].(string)
	site := data(must("POST", "/sites", map[string]any{"name": "readiness-load", "listen_port": 9000, "upstream_targets": []any{map[string]any{"host": "bench", "port": 8081, "weight": 1}}}))
	id := fmt.Sprintf("%.0f", site["id"])
	defer func() { _, err := api("DELETE", "/sites/"+id, nil); check("load site cleanup", err == nil, err) }()
	security(nil)
	// Exercise the active detector without creating weak-password hits.
	weak := data(must("GET", "/weak-password/config", nil))
	weak["enabled"] = true
	weak["endpoints"] = []any{map[string]any{"name": "readiness-login", "host": "", "method": "POST", "path": "/login", "kind": "login", "format": "json", "password_fields": []string{"password"}}}
	must("PUT", "/weak-password/config", weak)
	duration := envInt("BENCH_SOAK_SECONDS", 600)
	concurrency := envInt("BENCH_CONCURRENCY", 32)
	stopQueries := make(chan struct{})
	var queryWG sync.WaitGroup
	if !fault {
		queryWG.Add(1)
		go func() {
			defer queryWG.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			calls, failures := 0, 0
			var max time.Duration
			for {
				select {
				case <-stopQueries:
					check("dashboard queries during sustained load", failures == 0, fmt.Sprintf("calls=%d failures=%d max=%v", calls, failures, max))
					return
				case <-ticker.C:
					for _, path := range []string{"/logs/statistics", "/logs/daily?days=30", "/logs/trend?hours=168", "/logs?page_size=20"} {
						started := time.Now()
						_, err := api("GET", path, nil)
						elapsed := time.Since(started)
						calls++
						if err != nil {
							failures++
						}
						if elapsed > max {
							max = elapsed
						}
					}
				}
			}
		}()
	}
	if fault {
		benchmark("fault-forwarding", siteBase+"/", "GET", nil, concurrency, time.Duration(duration)*time.Second, 200)
	} else {
		phase := time.Duration(duration/3) * time.Second
		benchmark("sustained-GET", siteBase+"/", "GET", nil, concurrency, phase, 200)
		benchmark("sustained-JSON", siteBase+"/echo", "POST", []byte(`{"message":"sustained normal JSON","value":123}`), concurrency, phase, 200)
		benchmark("sustained-login", siteBase+"/login", "POST", []byte(`{"username":"tester","password":"VeryStrong!Readiness2026"}`), concurrency, phase, 200)
	}
	close(stopQueries)
	queryWG.Wait()
	if os.Getenv("BENCH_SKIP_DRAIN") == "1" {
		pipeline := stats()
		check("outage accepts logs durably without dropping", pipeline["dropped"] == float64(0) && pipeline["durable"] == float64(1), pipeline)
		return
	}
	// Drain both stages, rather than treating an empty publisher as committed logs.
	deadline := time.Now().Add(3 * time.Minute)
	drained := false
	for time.Now().Before(deadline) {
		pipeline := stats()
		if pipeline["queued"] == float64(0) {
			monitor, err := api("GET", "/monitor/status", nil)
			if err == nil && data(monitor)["kafka_lag"] == float64(0) {
				drained = true
				break
			}
		}
		time.Sleep(time.Second)
	}
	pipeline := stats()
	check("durable publisher enabled", pipeline["durable"] == float64(1), pipeline)
	check("log queue and Kafka lag drain", drained, pipeline)
	check("no log drops", pipeline["dropped"] == float64(0), pipeline)
	accepted, _ := pipeline["accepted"].(float64)
	recovered, _ := pipeline["recovered"].(float64)
	check("all accepted events delivered", pipeline["published"] == accepted+recovered, pipeline)
}
