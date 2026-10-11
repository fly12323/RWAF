package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/fly12323/RWAF/internal/config"
	"sync/atomic"
	"testing"
	"time"
)

func TestStatisticsRangeKeysPreservePrecisionAndInstant(t *testing.T) {
	first := time.Date(2026, 10, 7, 0, 0, 0, 100, time.UTC)
	second := first.Add(time.Nanosecond)
	if logRangeKey(&first) == logRangeKey(&second) {
		t.Fatal("different query boundaries share a cache key")
	}
	same := first.In(time.FixedZone("Asia/Shanghai", 8*3600))
	if logRangeKey(&first) != logRangeKey(&same) {
		t.Fatal("same instant differs across zones")
	}
	if logRangeKey(nil) == logRangeKey(&first) {
		t.Fatal("unbounded range collides")
	}
}

func TestCoalescedLogQueryWaiterHonorsOwnCancellation(t *testing.T) {
	prior := config.GlobalConfig
	config.GlobalConfig = &config.Config{}
	config.GlobalConfig.Log.StatisticsCacheSeconds = 10
	defer func() { config.GlobalConfig = prior; invalidateLogCache() }()
	invalidateLogCache()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var calls atomic.Int64
	query := func() (int, error) { calls.Add(1); close(started); <-release; return 42, nil }
	go func() { _, err := cachedLogQueryContext(context.Background(), "p1-cancel-waiter", query); done <- err }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := cachedLogQueryContext(ctx, "p1-cancel-waiter", query)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("waiter ignored its deadline", err, time.Since(start))
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	value, err := cachedLogQuery("p1-cancel-waiter", func() (int, error) { t.Fatal("cancelled waiter discarded shared cache"); return 0, nil })
	if value != 42 || err != nil || calls.Load() != 1 {
		t.Fatal(value, err, calls.Load())
	}
}

func TestCanceledCacheInitiatorDoesNotFailIndependentWaiter(t *testing.T) {
	prior := config.GlobalConfig
	config.GlobalConfig = &config.Config{}
	config.GlobalConfig.Log.StatisticsCacheSeconds = 10
	defer func() { config.GlobalConfig = prior; invalidateLogCache() }()
	invalidateLogCache()
	leaderCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	leaderDone := make(chan struct{})
	waiterStarted := make(chan struct{})
	waiterDone := make(chan error, 1)
	go func() {
		defer close(leaderDone)
		_, _ = cachedLogQueryContext(leaderCtx, "review-canceled-leader", func() (int, error) { close(started); <-leaderCtx.Done(); return 0, leaderCtx.Err() })
	}()
	<-started
	go func() {
		close(waiterStarted)
		v, err := cachedLogQueryContext(context.Background(), "review-canceled-leader", func() (int, error) { return 42, nil })
		if err == nil && v != 42 {
			err = fmt.Errorf("unexpected value %d", v)
		}
		waiterDone <- err
	}()
	<-waiterStarted
	// Wait for the shared flight to register this waiter before cancellation.
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-leaderDone
	if err := <-waiterDone; err != nil {
		t.Fatal("independent waiter inherited another caller's cancellation", err)
	}
}
