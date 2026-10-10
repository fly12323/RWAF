package proxy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/ratelimit"
)

type testLimiter struct {
	calls atomic.Int32
	allow bool
}

type errorLimiter struct{}

func (errorLimiter) Evaluate(context.Context, uint, string, string, *model.CCProtectionConfig) (ratelimit.Result, error) {
	return ratelimit.Result{}, errors.New("redis unavailable")
}

type slowLimiter struct{}

func (slowLimiter) Evaluate(ctx context.Context, _ uint, _, _ string, _ *model.CCProtectionConfig) (ratelimit.Result, error) {
	<-ctx.Done()
	return ratelimit.Result{}, ctx.Err()
}

func TestCCWaitDeadlinePreservesRejectedRule(t *testing.T) {
	p := &ReverseProxy{ccProtection: slowLimiter{}, ccWaiters: make(chan struct{}, 1)}
	r, err := p.waitForCC(context.Background(), "ip", "/login", &model.CCProtectionConfig{DelayMs: 10}, ratelimit.Result{Action: "delay", Rule: "/login", RetryAfter: time.Millisecond})
	if err != nil || r.Allowed || r.Rule != "/login" || len(p.ccWaiters) != 0 {
		t.Fatalf("deadline lost original rejection: %+v %v", r, err)
	}
}

func (s *testLimiter) Evaluate(ctx context.Context, _ uint, _, _ string, _ *model.CCProtectionConfig) (ratelimit.Result, error) {
	s.calls.Add(1)
	return ratelimit.Result{Allowed: s.allow, Action: "delay", RetryAfter: time.Millisecond}, ctx.Err()
}

func TestCCWaitRequiresAdmissionAndIsBounded(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		limiter := &testLimiter{allow: allowed}
		p := &ReverseProxy{ccProtection: limiter, ccWaiters: make(chan struct{}, 1)}
		result, err := p.waitForCC(context.Background(), "ip", "/login", &model.CCProtectionConfig{DelayMs: 100}, ratelimit.Result{Action: "delay", RetryAfter: time.Millisecond})
		if err != nil || result.Allowed != allowed || limiter.calls.Load() == 0 {
			t.Fatalf("result=%+v err=%v calls=%d", result, err, limiter.calls.Load())
		}
	}
	limiter := &testLimiter{}
	p := &ReverseProxy{ccProtection: limiter, ccWaiters: make(chan struct{}, 1)}
	p.ccWaiters <- struct{}{}
	result, err := p.waitForCC(context.Background(), "ip", "/", &model.CCProtectionConfig{DelayMs: 1000}, ratelimit.Result{Action: "delay"})
	if err != nil || result.Allowed || limiter.calls.Load() != 0 {
		t.Fatal("full queue admitted request", result, err)
	}
}

func TestCCWaitCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &ReverseProxy{ccProtection: &testLimiter{}, ccWaiters: make(chan struct{}, 1)}
	_, err := p.waitForCC(ctx, "ip", "/", &model.CCProtectionConfig{DelayMs: 1000}, ratelimit.Result{Action: "delay", RetryAfter: time.Second})
	if err != context.Canceled || len(p.ccWaiters) != 0 {
		t.Fatal("waiter not released", err)
	}
}
