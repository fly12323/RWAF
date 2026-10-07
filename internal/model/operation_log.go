package model

import "time"

// OperationLog 操作日志模型
// 记录用户在管理平台的操作行为
type OperationLog struct {
	ID         uint      `json:"id" gorm:"primaryKey"`             // 主键ID
	UserID     uint      `json:"user_id" gorm:"index"`             // 操作人ID
	Username   string    `json:"username" gorm:"size:50"`          // 操作人用户名
	Action     string    `json:"action" gorm:"size:50;index"`      // 操作类型
	Resource   string    `json:"resource" gorm:"size:50;index"`    // 操作资源类型
	ResourceID uint      `json:"resource_id" gorm:"index"`         // 资源ID
	Details    string    `json:"details" gorm:"type:text"`         // 操作详情（JSON格式）
	IP         string    `json:"ip" gorm:"size:50"`                // 操作IP
	UserAgent  string    `json:"user_agent" gorm:"size:500"`       // 用户代理
	Result     string    `json:"result" gorm:"size:20;index"`      // 操作结果: success, failed
	ErrorMsg   string    `json:"error_msg" gorm:"size:500"`        // 错误信息
	CreatedAt  time.Time `json:"created_at" gorm:"autoCreateTime"` // 创建时间
}

// TableName 指定表名
func (OperationLog) TableName() string {
	return "operation_logs"
}

// 操作类型常量
const (
	// 认证操作
	ActionLogin        = "login"         // 登录
	ActionLogout       = "logout"        // 登出
	ActionRefreshToken = "refresh_token" // 刷新令牌

	// 用户管理
	ActionCreateUser       = "create_user"
	ActionUpdateUser       = "update_user"
	ActionDeleteUser       = "delete_user"
	ActionResetPassword    = "reset_password"
	ActionToggleUserStatus = "toggle_user_status"

	// 站点管理
	ActionCreateSite             = "create_site"
	ActionUpdateSite             = "update_site"
	ActionDeleteSite             = "delete_site"
	ActionToggleSiteStatus       = "toggle_site_status"
	ActionToggleWafStatus        = "toggle_waf_status"
	ActionUpdateProtectionConfig = "update_protection_config"

	// 规则管理
	ActionCreateRule       = "create_rule"
	ActionUpdateRule       = "update_rule"
	ActionDeleteRule       = "delete_rule"
	ActionToggleRuleStatus = "toggle_rule_status"
	ActionReloadRules      = "reload_rules"

	// 白名单管理
	ActionCreateWhitelist       = "create_whitelist"
	ActionUpdateWhitelist       = "update_whitelist"
	ActionDeleteWhitelist       = "delete_whitelist"
	ActionToggleWhitelistStatus = "toggle_whitelist_status"

	// IP黑名单管理
	ActionCreateIPBlacklist       = "create_ip_blacklist"
	ActionUpdateIPBlacklist       = "update_ip_blacklist"
	ActionDeleteIPBlacklist       = "delete_ip_blacklist"
	ActionToggleIPBlacklistStatus = "toggle_ip_blacklist_status"
	ActionUpdateAutoBlockConfig   = "update_auto_block_config"
	ActionCleanExpiredBlacklist   = "clean_expired_blacklist"

	// IP白名单管理
	ActionCreateIPWhitelist       = "create_ip_whitelist"
	ActionUpdateIPWhitelist       = "update_ip_whitelist"
	ActionDeleteIPWhitelist       = "delete_ip_whitelist"
	ActionToggleIPWhitelistStatus = "toggle_ip_whitelist_status"

	// CC防护
	ActionUpdateCCProtection = "update_cc_protection"

	// WAF管理
	ActionReloadWAF = "reload_waf"

	// 异常检测
	ActionTrainAnomaly = "train_anomaly"
)

// 资源类型常量
const (
	ResourceAuth         = "auth"
	ResourceUser         = "user"
	ResourceSite         = "site"
	ResourceRule         = "rule"
	ResourceWhitelist    = "whitelist"
	ResourceIPBlacklist  = "ip_blacklist"
	ResourceIPWhitelist  = "ip_whitelist"
	ResourceCCProtection = "cc_protection"
	ResourceWAF          = "waf"
	ResourceAnomaly      = "anomaly"
)

// 操作结果常量
const (
	ResultSuccess = "success"
	ResultFailed  = "failed"
)
