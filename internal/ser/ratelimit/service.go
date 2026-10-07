package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/protection"
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
 if n>=tonumber(ARGV[i+1]) then return {0,n} end
end
for _,key in ipairs(KEYS) do
 redis.call('ZADD',key,now,ARGV[1])
 redis.call('EXPIRE',key,60)
end
return {1,count+1}
`)

func (s *CCProtectionService) CheckLimitContext(ctx context.Context, siteID uint, ip, uri string, cfg *model.CCProtectionConfig) (bool, int, error) {
	if !cfg.Enabled {
		return true, 0, nil
	}
	if cfg.RequestsPerMinute <= 0 {
		return false, 0, fmt.Errorf("invalid rate limit")
	}
	base := fmt.Sprintf("waf:cc:{%d:%s}", siteID, ip)
	keys := []string{base + ":global"}
	args := []interface{}{uuid.NewString(), cfg.RequestsPerMinute}
	var rules []model.URILimitConfig
	if cfg.URILimits != "" {
		if err := json.Unmarshal([]byte(cfg.URILimits), &rules); err != nil {
			return false, 0, err
		}
	}
	for i, rule := range rules {
		if rule.URI != "" && matchURI(uri, rule.URI) {
			if rule.RequestsPerMinute <= 0 {
				return false, 0, fmt.Errorf("invalid URI rate limit")
			}
			keys = append(keys, fmt.Sprintf("%s:uri:%d", base, i))
			args = append(args, rule.RequestsPerMinute)
			break
		}
	}
	values, err := limitScript.Run(ctx, dao.RDB, keys, args...).Int64Slice()
	if err != nil {
		return false, 0, err
	}
	return values[0] == 1, int(values[1]), nil
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
