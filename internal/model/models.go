package model

import (
	"encoding/json"
	"time"
)

// Site 站点配置模型
// 存储需要防护的站点信息
type Site struct {
	TLSEnabled          bool      `gorm:"not null;default:false" json:"tls_enabled"`
	TLSCertificate      string    `gorm:"type:text" json:"tls_certificate,omitempty"`
	TLSPrivateKey       string    `gorm:"type:text" json:"-"`
	ID                  uint      `gorm:"primaryKey;autoIncrement" json:"id"`                                           // 主键ID
	Name                string    `gorm:"type:varchar(100);not null" json:"name"`                                       // 站点名称
	Domains             string    `gorm:"type:jsonb" json:"domains"`                                                    // 域名列表（JSON数组）
	ListenPort          int       `gorm:"not null;default:9000" json:"listen_port"`                                     // 监听端口
	Enabled             bool      `gorm:"not null;default:true" json:"enabled"`                                         // 是否启用
	UpstreamMode        string    `gorm:"type:varchar(20);not null;default:'ip'" json:"upstream_mode"`                  // 后端模式: ip, domain
	UpstreamTargets     string    `gorm:"type:jsonb;not null" json:"upstream_targets"`                                  // 后端服务器列表（JSON数组）
	LoadBalanceStrategy string    `gorm:"type:varchar(20);not null;default:'round_robin'" json:"load_balance_strategy"` // 负载均衡策略
	CreatedAt           time.Time `gorm:"autoCreateTime" json:"created_at"`                                             // 创建时间
	UpdatedAt           time.Time `gorm:"autoUpdateTime" json:"updated_at"`                                             // 更新时间
}

// MarshalJSON 自定义序列化，将 JSON 字符串字段解析为实际对象返回
func (s Site) MarshalJSON() ([]byte, error) {
	type Alias Site
	a := struct {
		Alias
		Domains         interface{} `json:"domains"`
		UpstreamTargets interface{} `json:"upstream_targets"`
	}{
		Alias: (Alias)(s),
	}

	var domains interface{}
	if err := json.Unmarshal([]byte(s.Domains), &domains); err != nil {
		domains = s.Domains
	}
	a.Domains = domains

	var targets interface{}
	if err := json.Unmarshal([]byte(s.UpstreamTargets), &targets); err != nil {
		targets = s.UpstreamTargets
	}
	a.UpstreamTargets = targets

	return json.Marshal(a)
}

// TableName 指定表名
func (Site) TableName() string {
	return "sites"
}

// Rule 规则模型
// 存储规则信息
type Rule struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`                          // 主键ID
	RuleID      string    `gorm:"type:varchar(50);uniqueIndex;not null" json:"rule_id"`        // 规则ID
	RuleFile    string    `gorm:"type:varchar(255);not null" json:"rule_file"`                 // 规则文件路径
	RuleContent string    `gorm:"type:text" json:"rule_content"`                               // 规则内容
	Category    string    `gorm:"type:varchar(50)" json:"category"`                            // 规则分类
	Severity    string    `gorm:"type:varchar(20);not null;default:'WARNING'" json:"severity"` // 严重级别
	Score       int       `gorm:"not null;default:5" json:"score"`                             // 风险分数
	Description string    `gorm:"type:varchar(500)" json:"description"`                        // 规则描述
	Enabled     bool      `gorm:"not null;default:true" json:"enabled"`                        // 是否启用
	IsCustom    bool      `gorm:"not null;default:false" json:"is_custom"`                     // 是否自定义
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`                            // 创建时间
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`                            // 更新时间
}

// TableName 指定表名
func (Rule) TableName() string {
	return "rules"
}

// RuleGroup 规则分组模型
type RuleGroup struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`     // 主键ID
	Name        string    `gorm:"type:varchar(100);not null" json:"name"` // 分组名称
	Description string    `gorm:"type:varchar(255)" json:"description"`   // 分组描述
	Enabled     bool      `gorm:"not null;default:true" json:"enabled"`   // 是否启用
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`       // 创建时间
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`       // 更新时间
}

// TableName 指定表名
func (RuleGroup) TableName() string {
	return "rule_groups"
}

// Whitelist 白名单模型
type Whitelist struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`                          // 主键ID
	SiteID      *uint     `gorm:"index" json:"site_id"`                                        // 站点ID（为空表示全局）
	Type        string    `gorm:"type:varchar(20);not null;index" json:"type"`                 // 类型: ip, url, param, ua
	Value       string    `gorm:"type:varchar(500);not null" json:"value"`                     // 白名单值
	MatchType   string    `gorm:"type:varchar(20);not null;default:'exact'" json:"match_type"` // 匹配方式
	Description string    `gorm:"type:varchar(255)" json:"description"`                        // 描述
	Enabled     bool      `gorm:"not null;default:true" json:"enabled"`                        // 是否启用
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`                            // 创建时间
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`                            // 更新时间
}

// TableName 指定表名
func (Whitelist) TableName() string {
	return "whitelists"
}

// RequestLog 请求日志模型
type RequestLog struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	RequestID       string    `json:"request_id" gorm:"size:64;index"`
	SiteID          uint      `json:"site_id"`
	ClientIP        string    `json:"client_ip" gorm:"size:50"`
	Method          string    `json:"method" gorm:"size:10"`
	URI             string    `json:"uri" gorm:"type:text"`
	Headers         string    `json:"headers" gorm:"type:text"`
	Body            string    `json:"body" gorm:"type:text"`
	ResponseCode    int       `json:"response_code"`
	ResponseHeaders string    `json:"response_headers" gorm:"type:text"`
	ResponseBody    string    `json:"response_body" gorm:"type:text"`
	RiskScore       int       `json:"risk_score"`
	Action          string    `json:"action" gorm:"size:20"`
	AttackType      string    `json:"attack_type" gorm:"size:50"` // 主要攻击类型
	DecisionSource  string    `json:"decision_source" gorm:"size:40"`
	DecisionReason  string    `json:"decision_reason" gorm:"type:text"`
	RuleEvaluated   bool      `json:"rule_evaluated"`
	SourceInferred  bool      `json:"source_inferred" gorm:"-"`
	UpstreamAddr    string    `json:"upstream_addr" gorm:"size:100"`
	Duration        int       `json:"duration"`
	CreatedAt       time.Time `json:"created_at" gorm:"index"`
}

// TableName 指定表名
func (RequestLog) TableName() string {
	return "request_logs"
}

// RuleMatch 规则匹配记录
type RuleMatch struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	RequestLogID uint      `json:"request_log_id" gorm:"index"`
	RuleID       string    `json:"rule_id" gorm:"size:20"`
	RuleFile     string    `json:"rule_file" gorm:"size:255"`
	RuleMsg      string    `json:"rule_msg" gorm:"size:500"`
	Severity     string    `json:"severity" gorm:"size:20"`
	Score        int       `json:"score"`
	MatchedData  string    `json:"matched_data" gorm:"type:text"`
	CreatedAt    time.Time `json:"created_at"`
}

// TableName 指定表名
func (RuleMatch) TableName() string {
	return "rule_matches"
}

// SystemConfig 系统配置模型
type SystemConfig struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`                       // 主键ID
	ConfigKey   string    `gorm:"type:varchar(100);uniqueIndex;not null" json:"config_key"` // 配置键
	ConfigValue string    `gorm:"type:text" json:"config_value"`                            // 配置值
	Description string    `gorm:"type:varchar(255)" json:"description"`                     // 配置描述
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`                         // 更新时间
}

// TableName 指定表名
func (SystemConfig) TableName() string {
	return "system_configs"
}
