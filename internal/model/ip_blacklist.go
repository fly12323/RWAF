package model

import "time"

// IPBlacklist IP黑名单模型
type IPBlacklist struct {
	ID        uint       `json:"id" gorm:"primaryKey"`
	IP        string     `json:"ip" gorm:"size:50;not null;uniqueIndex"`
	Reason    string     `json:"reason" gorm:"size:255"`
	Type      int8       `json:"type" gorm:"default:1"` // 1:手动 2:自动
	ExpireAt  *time.Time `json:"expire_at"`
	Status    int8       `json:"status" gorm:"default:1"` // 0:禁用 1:启用
	CreatedBy string     `json:"created_by" gorm:"size:50"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// TableName 指定表名
func (IPBlacklist) TableName() string {
	return "ip_blacklist"
}

// IsExpired 检查是否已过期
func (b *IPBlacklist) IsExpired() bool {
	if b.ExpireAt == nil {
		return false // 永久封禁
	}
	return time.Now().After(*b.ExpireAt)
}

// AutoBlockConfig 自动封禁配置
type AutoBlockConfig struct {
	ID         uint      `json:"id" gorm:"primaryKey"`
	Enabled    bool      `json:"enabled"`
	Threshold  int       `json:"threshold" gorm:"default:10"`   // 触发次数阈值
	Duration   int       `json:"duration" gorm:"default:60"`    // 统计时长（秒）
	BlockHours int       `json:"block_hours" gorm:"default:24"` // 封禁时长（小时）
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// TableName 指定表名
func (AutoBlockConfig) TableName() string {
	return "auto_block_config"
}
