package monitor

import "time"

// Health is computed from an immutable cached sample; probes never run on an
// HTTP request. Unknown and expired samples cannot advertise readiness.
type Health struct {
	Status     string `json:"status"`
	Ready      bool   `json:"ready"`
	Stale      bool   `json:"stale"`
	AgeSeconds int64  `json:"age_seconds"`
}

func health(s *Snapshot, now time.Time) Health {
	if s.SampledAt.IsZero() {
		return Health{Status: "starting"}
	}
	age := now.Sub(s.SampledAt)
	h := Health{Status: "healthy", Ready: true, AgeSeconds: int64(age.Seconds())}
	if age < 0 {
		h.AgeSeconds = 0
	}
	// Sampling includes bounded probes and alert writes (up to ten seconds).
	limit := time.Duration(s.IntervalSeconds)*time.Second + 15*time.Second
	if age > limit {
		h.Status, h.Ready, h.Stale = "stale", false, true
		return h
	}
	for _, name := range []string{"postgres", "redis", "kafka"} {
		if s.Dependencies[name] != "ok" {
			h.Ready = false
		}
	}
	if s.Consumer == nil || s.Consumer["stale"] == true || s.Consumer["state"] != "running" {
		h.Ready = false
	}
	if s.Pipeline["available"] != 1 || s.Pipeline["spool_capacity_bytes"] > 0 && s.Pipeline["spool_bytes"] >= s.Pipeline["spool_capacity_bytes"] {
		h.Ready = false
	}
	for _, c := range s.Conditions {
		if c.Severity == "critical" {
			h.Ready = false
		}
	}
	if s.ConfigError || s.AlertStoreError || len(s.Conditions) > 0 || !h.Ready {
		h.Status = "degraded"
	}
	return h
}

func PublicHealth() Health {
	if stopping.Load() {
		return Health{Status: "stopping"}
	}
	s := latest.Load()
	if s == nil {
		return Health{Status: "starting"}
	}
	return health(s, time.Now())
}

// Called before HTTP shutdown so load balancers stop routing new requests.
func MarkStopping() { stopping.Store(true) }
