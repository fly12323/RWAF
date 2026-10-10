package protection

import (
	"encoding/json"
	"fmt"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"strconv"
	"sync"
	"time"
)

var cacheMu sync.Mutex
var cached *model.ProtectionConfig
var expiry time.Time

func clone(c model.ProtectionConfig) *model.ProtectionConfig {
	c.EnabledRuleCategories = append([]string{}, c.EnabledRuleCategories...)
	c.DisabledRuleIDs = append([]string{}, c.DisabledRuleIDs...)
	return &c
}
func GetConfig() (*model.ProtectionConfig, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cached != nil && time.Now().Before(expiry) {
		return clone(*cached), nil
	}
	var c model.ProtectionConfig
	if err := dao.GetDB().First(&c, 1).Error; err != nil {
		return nil, err
	}
	cached = clone(c)
	expiry = time.Now().Add(5 * time.Second)
	return &c, nil
}
func Invalidate() { cacheMu.Lock(); cached = nil; cacheMu.Unlock() }

func ValidateCC(c *model.CCProtectionConfig) error {
	if c.RequestsPerMinute <= 0 || c.DelayMs < 0 || c.DelayMs > 30000 || (c.Action != "block" && c.Action != "delay") {
		return fmt.Errorf("无效的 CC 配置")
	}
	if c.URILimits == "" {
		c.URILimits = "[]"
	}
	var limits []model.URILimitConfig
	if err := json.Unmarshal([]byte(c.URILimits), &limits); err != nil {
		return fmt.Errorf("URI 限流配置格式错误: %w", err)
	}
	for _, r := range limits {
		if r.URI == "" || r.RequestsPerMinute <= 0 || (r.Action != "" && r.Action != "block" && r.Action != "delay") {
			return fmt.Errorf("无效的 URI 限流规则")
		}
	}
	return nil
}
func ValidateAutoBlock(c *model.AutoBlockConfig) error {
	if c.Threshold <= 0 || c.Duration <= 0 || c.BlockHours < 0 {
		return fmt.Errorf("无效的自动封禁配置")
	}
	return nil
}
func Validate(c *model.ProtectionConfig) error {
	if c.ParanoiaLevel == 0 {
		c.ParanoiaLevel = 1
	} // Existing clients default to the previous PL1 behavior.
	if c.ParanoiaLevel < 1 || c.ParanoiaLevel > 4 {
		return fmt.Errorf("规则检测级别必须在 PL1 到 PL4 之间")
	}
	if (c.WafMode != "block" && c.WafMode != "monitor") || c.ScoreThreshold <= 0 {
		return fmt.Errorf("无效的防护模式或评分阈值")
	}
	for _, a := range []string{c.CrawlerScannerAction, c.CrawlerBotAction, c.CrawlerCrawlerAction} {
		if a != "log" && a != "block" {
			return fmt.Errorf("爬虫动作只能是 log 或 block")
		}
	}
	cc := c.CCConfig()
	if err := ValidateCC(cc); err != nil {
		return err
	}
	c.CCURILimits = cc.URILimits
	if err := ValidateAutoBlock(c.AutoBlockConfig()); err != nil {
		return err
	}
	allowed := map[string]bool{"sqli": true, "xss": true, "lfi": true, "rfi": true, "rce": true, "php": true, "nodejs": true, "scanner": true, "session": true, "java": true, "custom": true, "protocol": true}
	for _, category := range c.EnabledRuleCategories {
		if !allowed[category] {
			return fmt.Errorf("未知规则分类: %s", category)
		}
	}
	for _, id := range c.DisabledRuleIDs {
		n, err := strconv.Atoi(id)
		if err != nil || n <= 0 {
			return fmt.Errorf("无效规则 ID: %s", id)
		}
		if n == 1000000001 {
			return fmt.Errorf("不能禁用系统策略初始化规则")
		}
	}
	if c.EnabledRuleCategories == nil {
		c.EnabledRuleCategories = []string{}
	}
	if c.DisabledRuleIDs == nil {
		c.DisabledRuleIDs = []string{}
	}
	return nil
}
func SaveConfig(c *model.ProtectionConfig) error {
	if err := Validate(c); err != nil {
		return err
	}
	c.ID = 1
	cacheMu.Lock()
	defer cacheMu.Unlock()
	defer func() { cached = nil }()
	result := dao.GetDB().Model(&model.ProtectionConfig{}).Where("id = 1").Select("*").Omit("id", "created_at").Updates(c)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("全局防护配置尚未初始化")
	}
	return nil
}
func update(values map[string]any) error {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	defer func() { cached = nil }()
	values["updated_at"] = time.Now()
	result := dao.GetDB().Model(&model.ProtectionConfig{}).Where("id = 1").Updates(values)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("全局防护配置尚未初始化")
	}
	return nil
}
func UpdateCC(c *model.CCProtectionConfig) error {
	if err := ValidateCC(c); err != nil {
		return err
	}
	c.ID = 1
	return update(map[string]any{"cc_protection_enabled": c.Enabled, "cc_requests_per_minute": c.RequestsPerMinute, "cc_action": c.Action, "cc_delay_ms": c.DelayMs, "cc_uri_limits": c.URILimits})
}
func UpdateAutoBlock(c *model.AutoBlockConfig) error {
	if err := ValidateAutoBlock(c); err != nil {
		return err
	}
	c.ID = 1
	return update(map[string]any{"auto_block_enabled": c.Enabled, "auto_block_threshold": c.Threshold, "auto_block_duration": c.Duration, "auto_block_hours": c.BlockHours})
}
