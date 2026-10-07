package model

import "time"

// CCProtectionConfig CC防护配置
type CCProtectionConfig struct {
	ID                uint      `json:"id" gorm:"primaryKey"`
	Enabled           bool      `json:"enabled"`
	RequestsPerMinute int       `json:"requests_per_minute" gorm:"default:100"` // 每分钟请求限制
	URILimits         string    `json:"uri_limits" gorm:"type:text"`            // URI级别限制配置（JSON）
	Action            string    `json:"action" gorm:"default:'block'"`          // 超限动作：block, delay
	DelayMs           int       `json:"delay_ms" gorm:"default:1000"`           // 延迟时间（毫秒）
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// TableName 指定表名
func (CCProtectionConfig) TableName() string {
	return "cc_protection_config"
}

// URILimitConfig URI限制配置
type URILimitConfig struct {
	URI               string `json:"uri"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	Action            string `json:"action"` // block, delay
}
