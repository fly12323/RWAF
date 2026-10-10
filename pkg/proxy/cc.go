package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/ratelimit"
)

type ccLimiter interface {
	Evaluate(context.Context, uint, string, string, *model.CCProtectionConfig) (ratelimit.Result, error)
}

// waitForCC bounds pending requests per site and rechecks the atomic limiter.
// Waiting does not grant admission: exhausted budgets still produce HTTP 429.
func (p *ReverseProxy) waitForCC(ctx context.Context, ip, uri string, cfg *model.CCProtectionConfig, result ratelimit.Result) (ratelimit.Result, error) {
	select {
	case p.ccWaiters <- struct{}{}:
		defer func() { <-p.ccWaiters }()
	default:
		return result, nil
	}
	deadline := time.Now().Add(time.Duration(cfg.DelayMs) * time.Millisecond)
	for !result.Allowed && result.Action == "delay" {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return result, nil
		}
		wait := result.RetryAfter
		if wait <= 0 {
			wait = time.Millisecond
		}
		if wait > remaining {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return result, ctx.Err()
		case <-timer.C:
		}
		if time.Until(deadline) <= 0 {
			return result, nil
		}
		checkCtx, cancel := context.WithDeadline(ctx, deadline)
		next, err := p.ccProtection.Evaluate(checkCtx, p.siteID, ip, uri, cfg)
		cancel()
		if err != nil {
			if ctx.Err() == nil && time.Until(deadline) <= 0 {
				return result, nil
			}
			return result, fmt.Errorf("CC recheck: %w", err)
		}
		result = next
	}
	return result, nil
}
