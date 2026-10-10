package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/protection"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"time"
)

type CCProtectionService struct{}

func NewCCProtectionService() *CCProtectionService { return &CCProtectionService{} }

// GetConfig returns the CC section of the shared policy.
func (s *CCProtectionService) GetConfig() (*model.CCProtectionConfig, error) {
	cfg, err := protection.GetConfig()
	if err != nil {
		return nil, err
	}
	return cfg.CCConfig(), nil
}
func (s *CCProtectionService) UpdateConfig(cfg *model.CCProtectionConfig) error {
	return protection.UpdateCC(cfg)
}

// Both global and matched URI limits are checked atomically before counting.
// Rejected traffic is not added, bounding each sorted set by its configured limit.
var limitScript = redis.NewScript(`
local clock=redis.call('TIME')
local now=clock[1]*1000+math.floor(clock[2]/1000)
local count=0
for i,key in ipairs(KEYS) do
 redis.call('ZREMRANGEBYSCORE',key,'-inf',now-60000)
 local n=redis.call('ZCARD',key)
 count=math.max(count,n)
 if n>=tonumber(ARGV[i+1]) then
  local oldest=redis.call('ZRANGE',key,0,0,'WITHSCORES')
  local retry=math.max(1,tonumber(oldest[2])+60000-now)
  return {0,n,i,retry}
 end
end
for _,key in ipairs(KEYS) do
 redis.call('ZADD',key,now,ARGV[1])
 redis.call('EXPIRE',key,60)
end
return {1,count+1,0,0}
`)

// Result describes the limit that rejected the request, not an HTTP response.
type Result struct {
	Allowed    bool
	Count      int
	Action     string
	Rule       string
	RetryAfter time.Duration
}

func (s *CCProtectionService) CheckLimitContext(ctx context.Context, siteID uint, ip, uri string, cfg *model.CCProtectionConfig) (bool, int, error) {
	r, err := s.Evaluate(ctx, siteID, ip, uri, cfg)
	return r.Allowed, r.Count, err
}

func (s *CCProtectionService) Evaluate(ctx context.Context, siteID uint, ip, uri string, cfg *model.CCProtectionConfig) (Result, error) {
	if !cfg.Enabled {
		return Result{Allowed: true}, nil
	}
	if cfg.RequestsPerMinute <= 0 {
		return Result{}, fmt.Errorf("invalid rate limit")
	}
	base := fmt.Sprintf("waf:cc:{%d:%s}", siteID, ip)
	keys := []string{base + ":global"}
	args := []interface{}{uuid.NewString(), cfg.RequestsPerMinute}
	actions := []string{cfg.Action}
	names := []string{"站点 / IP 总限额"}
	var rules []model.URILimitConfig
	if cfg.URILimits != "" {
		if err := json.Unmarshal([]byte(cfg.URILimits), &rules); err != nil {
			return Result{}, err
		}
	}
	for i, rule := range rules {
		if rule.URI != "" && matchURI(uri, rule.URI) {
			if rule.RequestsPerMinute <= 0 {
				return Result{}, fmt.Errorf("invalid URI rate limit")
			}
			keys = append(keys, fmt.Sprintf("%s:uri:%d", base, i))
			args = append(args, rule.RequestsPerMinute)
			action := rule.Action
			if action == "" {
				action = cfg.Action
			}
			actions = append(actions, action)
			names = append(names, rule.URI)
			break
		}
	}
	values, err := limitScript.Run(ctx, dao.RDB, keys, args...).Int64Slice()
	if err != nil {
		return Result{}, err
	}
	if len(values) != 4 {
		return Result{}, fmt.Errorf("invalid limiter response")
	}
	result := Result{Allowed: values[0] == 1, Count: int(values[1])}
	if !result.Allowed {
		index := int(values[2]) - 1
		if index < 0 || index >= len(actions) {
			return Result{}, fmt.Errorf("invalid limiter rule")
		}
		result.Action, result.Rule = actions[index], names[index]
		result.RetryAfter = time.Duration(values[3]) * time.Millisecond
	}
	return result, nil
}

// matchURI 匹配URI
func matchURI(requestURI, pattern string) bool {
	// 精确匹配
	if pattern == "*" {
		return true
	}
	if pattern == requestURI {
		return true
	}
	// 前缀匹配（支持 * 通配符）
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		if len(requestURI) >= len(prefix) && requestURI[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
