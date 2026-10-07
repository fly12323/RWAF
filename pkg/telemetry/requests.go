package telemetry

import (
	"sync/atomic"
	"time"
)

var count, failures, micros atomic.Int64
var buckets [11]atomic.Int64
var bounds = [...]int64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 60000}

func Observe(status int, elapsed time.Duration) {
	count.Add(1)
	if status >= 500 {
		failures.Add(1)
	}
	micros.Add(elapsed.Microseconds())
	ms := elapsed.Milliseconds()
	for i, b := range bounds {
		if ms <= b || i == len(bounds)-1 {
			buckets[i].Add(1)
			break
		}
	}
}
func Sample(seconds float64) map[string]any {
	n := count.Swap(0)
	errors := failures.Swap(0)
	total := micros.Swap(0)
	var seen, p99 int64
	for i := range buckets {
		seen += buckets[i].Swap(0)
		if p99 == 0 && n > 0 && seen*100 >= n*99 {
			p99 = bounds[i]
		}
	}
	rps, avg, ratio := 0.0, 0.0, 0.0
	if seconds > 0 {
		rps = float64(n) / seconds
	}
	if n > 0 {
		avg = float64(total) / float64(n) / 1000
		ratio = float64(errors) * 100 / float64(n)
	}
	return map[string]any{"requests": n, "errors_5xx": errors, "rps": rps, "average_ms": avg, "p99_bucket_ms": p99, "error_percent": ratio}
}
