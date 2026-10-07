package model

import "time"

// ProtectionConfig is the single shared policy for every enabled site.
type ProtectionConfig struct {
	ID                      uint      `json:"id" gorm:"primaryKey;autoIncrement:false;check:protection_singleton,id = 1"`
	Enabled                 bool      `json:"enabled"`
	WafMode                 string    `json:"waf_mode"`
	ScoreThreshold          int       `json:"score_threshold"`
	EnabledRuleCategories   []string  `json:"enabled_rule_categories" gorm:"serializer:json;type:jsonb"`
	DisabledRuleIDs         []string  `json:"disabled_rule_ids" gorm:"serializer:json;type:jsonb"`
	RuleEngineEnabled       bool      `json:"rule_engine_enabled"`
	CrawlerDetectionEnabled bool      `json:"crawler_detection_enabled"`
	CrawlerScannerAction    string    `json:"crawler_scanner_action"`
	CrawlerBotAction        string    `json:"crawler_bot_action"`
	CrawlerCrawlerAction    string    `json:"crawler_crawler_action"`
	IPBlacklistEnabled      bool      `json:"ip_blacklist_enabled"`
	IPWhitelistEnabled      bool      `json:"ip_whitelist_enabled"`
	CCProtectionEnabled     bool      `json:"cc_protection_enabled"`
	CCRequestsPerMinute     int       `json:"cc_requests_per_minute"`
	CCAction                string    `json:"cc_action"`
	CCDelayMs               int       `json:"cc_delay_ms"`
	CCURILimits             string    `json:"cc_uri_limits" gorm:"type:jsonb"`
	AutoBlockEnabled        bool      `json:"auto_block_enabled"`
	AutoBlockThreshold      int       `json:"auto_block_threshold"`
	AutoBlockDuration       int       `json:"auto_block_duration"`
	AutoBlockHours          int       `json:"auto_block_hours"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

func (ProtectionConfig) TableName() string { return "global_protection_config" }

func DefaultProtectionConfig(mode string, threshold int) ProtectionConfig {
	if mode == "" {
		mode = "block"
	}
	if threshold <= 0 {
		threshold = 15
	}
	return ProtectionConfig{ID: 1, Enabled: true, WafMode: mode, ScoreThreshold: threshold,
		EnabledRuleCategories: []string{}, DisabledRuleIDs: []string{}, RuleEngineEnabled: true,
		CrawlerDetectionEnabled: true, CrawlerScannerAction: "log", CrawlerBotAction: "log", CrawlerCrawlerAction: "log",
		IPBlacklistEnabled: true, IPWhitelistEnabled: true, CCProtectionEnabled: true, CCRequestsPerMinute: 100,
		CCAction: "block", CCDelayMs: 1000, CCURILimits: "[]", AutoBlockEnabled: true, AutoBlockThreshold: 10, AutoBlockDuration: 60, AutoBlockHours: 24}
}

func (c ProtectionConfig) CCConfig() *CCProtectionConfig {
	return &CCProtectionConfig{ID: 1, Enabled: c.CCProtectionEnabled, RequestsPerMinute: c.CCRequestsPerMinute,
		Action: c.CCAction, DelayMs: c.CCDelayMs, URILimits: c.CCURILimits, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}
func (c ProtectionConfig) AutoBlockConfig() *AutoBlockConfig {
	return &AutoBlockConfig{ID: 1, Enabled: c.AutoBlockEnabled, Threshold: c.AutoBlockThreshold,
		Duration: c.AutoBlockDuration, BlockHours: c.AutoBlockHours, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}
