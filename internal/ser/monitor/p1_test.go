package monitor

import (
	"context"
	"fmt"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/pkg/telemetry"
	"testing"
	"time"
)

func TestHeartbeatMalformedAndNullAreUnavailable(t *testing.T) {
	now := time.Now()
	for _, body := range []string{"null", "[]", "{", `{}`, `{"heartbeat_at":"now"}`, `{"heartbeat_at":0}`} {
		if got := decodeHeartbeat([]byte(body), now, 30*time.Second); got != nil {
			t.Fatalf("%s accepted: %v", body, got)
		}
	}
	for _, tc := range []struct {
		delta time.Duration
		stale bool
	}{{-time.Minute, true}, {0, false}, {time.Minute, true}} {
		body := fmt.Sprintf(`{"heartbeat_at":%d,"state":"running"}`, now.Add(tc.delta).Unix())
		got := decodeHeartbeat([]byte(body), now, 30*time.Second)
		if got == nil || got["stale"] != tc.stale {
			t.Fatal(body, got)
		}
	}
}

func TestHealthTransitionsAndCachedFreshness(t *testing.T) {
	now := time.Now()
	if h := health(&Snapshot{}, now); h.Ready || h.Status != "starting" {
		t.Fatal(h)
	}
	healthy := func() *Snapshot {
		return &Snapshot{SampledAt: now, IntervalSeconds: 5, Dependencies: map[string]string{"postgres": "ok", "redis": "ok", "kafka": "ok"}, Consumer: map[string]any{"state": "running", "stale": false}, Pipeline: map[string]int64{"available": 1}}
	}
	if h := health(healthy(), now); !h.Ready || h.Status != "healthy" {
		t.Fatal(h)
	}
	for _, name := range []string{"postgres", "redis", "kafka"} {
		s := healthy()
		s.Dependencies[name] = "unavailable"
		if h := health(s, now); h.Ready || h.Status != "degraded" {
			t.Fatal(name, h)
		}
	}
	for _, state := range []string{"starting", "retrying", "stopped", "unknown"} {
		s := healthy()
		s.Consumer["state"] = state
		if h := health(s, now); h.Ready {
			t.Fatal(state, h)
		}
	}
	s := healthy()
	s.Consumer["stale"] = true
	if health(s, now).Ready {
		t.Fatal("stale consumer ready")
	}
	s = healthy()
	s.Pipeline["available"] = 0
	if health(s, now).Ready {
		t.Fatal("closed publisher ready")
	}
	s = healthy()
	s.Pipeline["spool_capacity_bytes"], s.Pipeline["spool_bytes"] = 100, 100
	if health(s, now).Ready {
		t.Fatal("full spool ready")
	}
	s = healthy()
	s.Conditions = []Condition{{"space", "critical", "low space"}}
	if health(s, now).Ready {
		t.Fatal("critical alarm ready")
	}
	s = healthy()
	s.Conditions = []Condition{{"slow", "warning", "slow query"}}
	if h := health(s, now); !h.Ready || h.Status != "degraded" {
		t.Fatal(h)
	}
	s = healthy()
	before := s.SampledAt
	prior := latest.Load()
	latest.Store(s)
	defer latest.Store(prior)
	if h := health(s, now.Add(21*time.Second)); h.Ready || !h.Stale {
		t.Fatal(h)
	}
	_ = Current()
	if s.SampledAt != before || s.Health.Status != "" {
		t.Fatal("current mutated stored sample")
	}
	if _, err := KafkaLag(context.Background(), config.KafkaConfig{}, nil); err == nil {
		t.Fatal("empty Kafka config accepted")
	}
}

func TestStorageThresholdsAndGrowthWindow(t *testing.T) {
	bytes := int64(80 * 1048576)
	free := uint64(256 * 1048576)
	s := Storage{DatabaseBytes: &bytes, SpoolDiskFreeBytes: &free}
	check := func(key, severity string, conditions []Condition) {
		t.Helper()
		for _, c := range conditions {
			if c.Key == key && c.Severity == severity {
				return
			}
		}
		t.Fatalf("missing %s/%s: %+v", key, severity, conditions)
	}
	check("database_capacity", "warning", storageConditions(s, telemetry.LogQuerySample{}, 100, 10, 256, 1000))
	bytes = 100 * 1048576
	check("database_capacity", "critical", storageConditions(s, telemetry.LogQuerySample{}, 100, 10, 256, 1000))
	check("spool_disk_space", "critical", storageConditions(s, telemetry.LogQuerySample{}, 100, 10, 256, 1000))
	b := growthBaseline{}
	now := time.Now()
	b.observe(&s, now)
	bytes += 1048576
	b.observe(&s, now.Add(59*time.Second))
	if s.GrowthMBHour != nil {
		t.Fatal("short sample produced misleading growth")
	}
	b.observe(&s, now.Add(time.Minute))
	if s.GrowthMBHour == nil || *s.GrowthMBHour != 60 || s.GrowthWindowSeconds != 60 {
		t.Fatal(s)
	}
	check("database_growth", "warning", storageConditions(s, telemetry.LogQuerySample{}, 100, 10, 256, 1000))
	q := telemetry.LogQuerySample{Count: 10, Errors: 1, P95MS: 1000}
	check("log_query_latency", "warning", storageConditions(Storage{}, q, 100, 10, 256, 1000))
	check("log_query_errors", "warning", storageConditions(Storage{}, q, 100, 10, 256, 1000))
	s.DatabaseError = true
	conditions := storageConditions(s, telemetry.LogQuerySample{}, 100, 10, 256, 1000)
	for _, c := range conditions {
		if c.Key == "database_capacity" {
			t.Fatal("failed sample asserted valid capacity")
		}
	}
	check("database_metrics", "warning", conditions)
	bytes = 0
	s = Storage{DatabaseBytes: &bytes}
	b.observe(&s, now.Add(2*time.Minute))
	if s.GrowthMBHour == nil || *s.GrowthMBHour != 0 {
		t.Fatal("negative growth", s)
	}
	bytes = b.bytes + 5*1048576
	b.observe(&s, now.Add(5*time.Minute))
	if s.GrowthMBHour == nil || *s.GrowthMBHour != 60 {
		t.Fatal("baseline rollover", s)
	}
	bytes += 1048576
	s = Storage{DatabaseBytes: &bytes}
	b.observe(&s, now.Add(5*time.Minute+10*time.Second))
	if s.GrowthMBHour == nil || *s.GrowthMBHour != 60 || s.GrowthWindowSeconds != 300 {
		t.Fatal("rollover lost last valid growth estimate", s)
	}
}

func BenchmarkCachedHealth(b *testing.B) {
	s := &Snapshot{SampledAt: time.Now(), IntervalSeconds: 15, Dependencies: map[string]string{"postgres": "ok", "redis": "ok", "kafka": "ok"}, Consumer: map[string]any{"state": "running"}, Pipeline: map[string]int64{"available": 1}}
	prior := latest.Load()
	latest.Store(s)
	defer latest.Store(prior)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = PublicHealth()
	}
}
