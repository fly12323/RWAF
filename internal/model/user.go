package model

import "time"

// User 用户模型
type User struct {
	ID                 uint       `json:"id" gorm:"primaryKey"`
	Username           string     `json:"username" gorm:"uniqueIndex;size:50;not null"`
	Password           string     `json:"-" gorm:"size:255;not null"`
	Nickname           string     `json:"nickname" gorm:"size:50"`
	Role               string     `json:"role" gorm:"size:20;default:operator"`
	Status             int8       `json:"status" gorm:"default:1"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLogin          *time.Time `json:"last_login"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// TableName 指定表名
func (User) TableName() string {
	return "users"
}

// 用户角色常量
const (
	RoleAdmin    = "admin"    // 管理员
	RoleOperator = "operator" // 操作员
	RoleAuditor  = "auditor"  // 审计员
)

// 用户状态常量
const (
	StatusDisabled = 0
	StatusEnabled  = 1
)
