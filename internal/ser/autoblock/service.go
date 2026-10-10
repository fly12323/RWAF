package autoblock

import (
	"context"
	"fmt"
	"time"

	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/blacklist"
	"github.com/redis/go-redis/v9"
)

var attackCounter = redis.NewScript(`
local now=redis.call('TIME')
local stamp=now[1]*1000+math.floor(now[2]/1000)
redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',stamp-tonumber(ARGV[1])*1000)
redis.call('ZADD',KEYS[1],stamp,ARGV[2])
local count=redis.call('ZCARD',KEYS[1])
redis.call('EXPIRE',KEYS[1],ARGV[1])
if count>=tonumber(ARGV[3]) then redis.call('ZREM',KEYS[1],ARGV[2]) end
return count
`)

// RecordRuleBlock handles the explicit WAF-to-blacklist relationship. CC and
// crawler observations never implicitly become automatic IP bans.
func RecordRuleBlock(parent context.Context, siteID uint, ip, requestID string, cfg *model.AutoBlockConfig) error {
	if !cfg.Enabled || cfg.Duration <= 0 || cfg.Threshold <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	count, err := attackCounter.Run(ctx, dao.RDB, []string{fmt.Sprintf("waf:attacks:%d:%s", siteID, ip)}, cfg.Duration, requestID, cfg.Threshold).Int64()
	if err != nil {
		return err
	}
	if count < int64(cfg.Threshold) {
		return nil
	}
	return blacklist.NewIPBlacklistService().AutoBlock(ip, fmt.Sprintf("站点 %d 触发规则拦截阈值", siteID), cfg.BlockHours)
}
