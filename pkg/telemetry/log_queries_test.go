package telemetry

import (
	"sync"
	"testing"
	"time"
)

func TestLogQuerySampleBoundariesConcurrencyAndReset(t *testing.T) {
	m := &LogQueries{}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.Observe(time.Millisecond, false)
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 100; i++ {
		m.Observe(1001*time.Millisecond, true)
	}
	s := m.Sample()
	if s.Count != 2100 || s.Errors != 100 || s.P95MS != 1 {
		t.Fatal(s)
	}
	if s = m.Sample(); s.Count != 0 || s.P95MS != 0 {
		t.Fatal(s)
	}
	m.Observe(1001*time.Millisecond, true)
	if s = m.Sample(); s.P95MS != 2000 || s.AverageMS != 1001 {
		t.Fatal(s)
	}
	m.Observe(61*time.Second, false)
	if s = m.Sample(); s.P95MS != 60000 {
		t.Fatal(s)
	}
}

func BenchmarkLogQueryObserve(b *testing.B) {
	m := &LogQueries{}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Observe(time.Millisecond, false)
		}
	})
}
