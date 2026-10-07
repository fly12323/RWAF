package monitor

import (
	"testing"
	"time"
)

func TestConditionsAndRecovery(t *testing.T) {
	c := DefaultConfig()
	lag := int64(20000)
	s := &Snapshot{Dependencies: map[string]string{"postgres": "unavailable", "redis": "ok", "kafka": "ok"}, Consumer: map[string]any{"stale": true}, KafkaLag: &lag, Pipeline: map[string]int64{"capacity": 100, "queued": 90, "dropped": 3, "errors": 2}, Detector: map[string]any{"dropped": int64(2), "skipped": int64(1), "publish_errors": int64(0), "config_error": ""}, Requests: map[string]any{"requests": int64(30), "error_percent": 20.0, "p99_bucket_ms": int64(5000)}, HeapMB: 600}
	conditions := evaluate(s, c, map[string]int64{})
	keys := map[string]bool{}
	for _, v := range conditions {
		keys[v.Key] = true
	}
	for _, key := range []string{"postgres_unavailable", "consumer_stale", "kafka_lag", "log_queue", "log_dropped", "log_errors", "weak_dropped", "weak_skipped", "heap", "proxy_errors", "proxy_latency"} {
		if !keys[key] {
			t.Errorf("missing %s", key)
		}
	}
	s.Dependencies["postgres"] = "ok"
	s.Consumer["stale"] = false
	lag = 0
	s.Pipeline["queued"] = 0
	s.HeapMB = 20
	s.Requests = map[string]any{"requests": int64(0)}
	previous := map[string]int64{"dropped": 3, "errors": 2, "weak_dropped": 2, "weak_skipped": 1}
	if got := evaluate(s, c, previous); len(got) != 0 {
		t.Fatalf("recovered counters generated alarms: %+v", got)
	}
}
func TestSnapshotInitialRead(t *testing.T) {
	s := Current()
	if s.SampledAt.After(time.Now()) {
		t.Fatal("invalid sample timestamp")
	}
}
