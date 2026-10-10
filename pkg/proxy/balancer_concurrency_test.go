package proxy

import (
	"sync"
	"testing"
)

func TestWeightedBalancerConcurrentDistribution(t *testing.T) {
	b := NewWeightedRoundRobinBalancer()
	b.AddTarget(&Target{Host: "a", Weight: 1})
	b.AddTarget(&Target{Host: "b", Weight: 3})
	var workers sync.WaitGroup
	counts := make(chan int, 24)
	for i := 0; i < 24; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			count := 0
			for j := 0; j < 1000; j++ {
				if b.Next().Host == "a" {
					count++
				}
			}
			counts <- count
		}()
	}
	workers.Wait()
	close(counts)
	total := 0
	for n := range counts {
		total += n
	}
	if total != 6000 {
		t.Fatalf("weight distribution changed under concurrency: a=%d want=6000", total)
	}
}
