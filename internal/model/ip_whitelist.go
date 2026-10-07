package model

import "time"

// IPWhitelist IP白名单模型
type IPWhitelist struct {
	ID        uint       `json:"id" gorm:"primaryKey"`
	IP        string     `json:"ip" gorm:"size:50;not null;uniqueIndex"`
	Reason    string     `json:"reason" gorm:"size:255"`
	ExpireAt  *time.Time `json:"expire_at"`
	Status    int8       `json:"status" gorm:"default:1"` // 0:禁用 1:启用
	CreatedBy string     `json:"created_by" gorm:"size:50"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// TableName 指定表名
func (IPWhitelist) TableName() string {
	return "ip_whitelist"
}

// IsExpired 检查是否已过期
func (w *IPWhitelist) IsExpired() bool {
	if w.ExpireAt == nil {
		return false // 永久有效
	}
	return time.Now().After(*w.ExpireAt)
}
