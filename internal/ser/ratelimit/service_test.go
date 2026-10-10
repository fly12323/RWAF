package ratelimit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/redis/go-redis/v9"
)

// Test the Redis-result contract without requiring a running dependency.
type resultHook struct{ result []interface{} }

func (h resultHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(context.Context, string, string) (net.Conn, error) { panic("unexpected network connection") }
}
func (h resultHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error { cmd.(*redis.Cmd).SetVal(h.result); return nil }
}
func (h resultHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestMatchedLimitControlsAction(t *testing.T) {
	old := dao.RDB
	defer func() { dao.RDB = old }()
	for _, tc := range []struct {
		index                   int64
		action, uriAction, rule string
		fail                    bool
	}{
		{2, "block", "delay", "/login", false},
		{2, "delay", "block", "/login", false},
		{2, "delay", "", "/login", false},
		{1, "block", "delay", "站点 / IP 总限额", false},
		{3, "block", "delay", "", true},
	} {
		client := redis.NewClient(&redis.Options{Addr: "unused"})
		dao.RDB = client
		client.AddHook(resultHook{result: []interface{}{int64(0), int64(20), tc.index, int64(1200)}})
		cfg := &model.CCProtectionConfig{Enabled: true, RequestsPerMinute: 100, Action: tc.action, URILimits: `[{"uri":"/login","requests_per_minute":20,"action":"` + tc.uriAction + `"}]`}
		r, err := NewCCProtectionService().Evaluate(context.Background(), 1, "192.0.2.1", "/login", cfg)
		client.Close()
		if (err != nil) != tc.fail {
			t.Fatalf("index=%d error=%v", tc.index, err)
		}
		if tc.fail {
			continue
		}
		expect := tc.uriAction
		if tc.index == 1 || expect == "" {
			expect = tc.action
		}
		if r.Allowed || r.Action != expect || r.Rule != tc.rule || r.RetryAfter != 1200*time.Millisecond {
			t.Fatalf("unexpected result: %+v", r)
		}
	}
}
