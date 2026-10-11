package telemetry

import (
	"sync"
	"time"
)

// LogQueries measures complete authenticated read operations, including cache
// hits and serialization. Fixed buckets avoid retaining queries or user data.
type LogQueries struct {
	mu                              sync.Mutex
	count, errors, canceled, micros int64
	buckets                         [12]int64
}

var logBounds = [...]int64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2000, 5000, 60000}
var Logs LogQueries

type LogQuerySample struct {
	Count     int64   `json:"count"`
	Errors    int64   `json:"errors"`
	Canceled  int64   `json:"canceled"`
	AverageMS float64 `json:"average_ms"`
	P95MS     int64   `json:"p95_bucket_ms"`
}

func (m *LogQueries) Observe(elapsed time.Duration, failed bool) {
	m.ObserveResult(elapsed, failed, false)
}

func (m *LogQueries) ObserveResult(elapsed time.Duration, failed, canceled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.count++
	m.micros += elapsed.Microseconds()
	if failed {
		m.errors++
	}
	if canceled {
		m.canceled++
	}
	for i, b := range logBounds {
		if elapsed <= time.Duration(b)*time.Millisecond || i == len(logBounds)-1 {
			m.buckets[i]++
			break
		}
	}
}

func (m *LogQueries) Sample() LogQuerySample {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := LogQuerySample{Count: m.count, Errors: m.errors, Canceled: m.canceled}
	if m.count > 0 {
		s.AverageMS = float64(m.micros) / float64(m.count) / 1000
		var seen int64
		for i, n := range m.buckets {
			seen += n
			if seen*100 >= m.count*95 {
				s.P95MS = logBounds[i]
				break
			}
		}
	}
	m.count, m.errors, m.canceled, m.micros = 0, 0, 0, 0
	m.buckets = [12]int64{}
	return s
}
