package service

import (
	"encoding/json"
	"time"

	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
)

// OperationLogService 操作日志服务
type OperationLogService struct{}

// NewOperationLogService 创建操作日志服务实例
func NewOperationLogService() *OperationLogService {
	return &OperationLogService{}
}

// OperationLogItem 操作日志条目（用于创建）
type OperationLogItem struct {
	UserID     uint
	Username   string
	Action     string
	Resource   string
	ResourceID uint
	Details    map[string]interface{}
	IP         string
	UserAgent  string
	Result     string
	ErrorMsg   string
}

// Log 创建操作日志
func (s *OperationLogService) Log(item *OperationLogItem) error {
	detailsJSON := ""
	if item.Details != nil {
		data, err := json.Marshal(item.Details)
		if err == nil {
			detailsJSON = string(data)
		}
	}

	log := &model.OperationLog{
		UserID:     item.UserID,
		Username:   item.Username,
		Action:     item.Action,
		Resource:   item.Resource,
		ResourceID: item.ResourceID,
		Details:    detailsJSON,
		IP:         item.IP,
		UserAgent:  item.UserAgent,
		Result:     item.Result,
		ErrorMsg:   item.ErrorMsg,
	}

	return dao.GetDB().Create(log).Error
}

// GetList 获取操作日志列表
func (s *OperationLogService) GetList(page, pageSize int, userID uint, username, action, resource, result, startTime, endTime string) ([]model.OperationLog, int64, error) {
	var logs []model.OperationLog
	var total int64

	db := dao.GetDB().Model(&model.OperationLog{})

	// 筛选条件
	if userID > 0 {
		db = db.Where("user_id = ?", userID)
	}
	if username != "" {
		db = db.Where("username LIKE ?", "%"+username+"%")
	}
	if action != "" {
		db = db.Where("action = ?", action)
	}
	if resource != "" {
		db = db.Where("resource = ?", resource)
	}
	if result != "" {
		db = db.Where("result = ?", result)
	}
	if startTime != "" {
		db = db.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		db = db.Where("created_at <= ?", endTime)
	}

	// 统计总数
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	if err := db.Order("id DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

// GetStatistics 获取操作统计
func (s *OperationLogService) GetStatistics(startTime, endTime string) (map[string]interface{}, error) {
	var total int64
	var successCount int64
	var failedCount int64

	db := dao.GetDB().Model(&model.OperationLog{})

	if startTime != "" {
		db = db.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		db = db.Where("created_at <= ?", endTime)
	}

	db.Count(&total)

	// 成功次数
	dbSuccess := dao.GetDB().Model(&model.OperationLog{}).Where("result = ?", model.ResultSuccess)
	if startTime != "" {
		dbSuccess = dbSuccess.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		dbSuccess = dbSuccess.Where("created_at <= ?", endTime)
	}
	dbSuccess.Count(&successCount)

	// 失败次数
	dbFailed := dao.GetDB().Model(&model.OperationLog{}).Where("result = ?", model.ResultFailed)
	if startTime != "" {
		dbFailed = dbFailed.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		dbFailed = dbFailed.Where("created_at <= ?", endTime)
	}
	dbFailed.Count(&failedCount)

	// 按操作统计
	var byAction []struct {
		Action string `json:"action"`
		Count  int64  `json:"count"`
	}
	dbAction := dao.GetDB().Model(&model.OperationLog{})
	if startTime != "" {
		dbAction = dbAction.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		dbAction = dbAction.Where("created_at <= ?", endTime)
	}
	dbAction.Select("action, count(*) as count").
		Group("action").
		Order("count DESC").
		Scan(&byAction)

	// 按用户统计
	var byUser []struct {
		Username string `json:"username"`
		Count    int64  `json:"count"`
	}
	dbUser := dao.GetDB().Model(&model.OperationLog{})
	if startTime != "" {
		dbUser = dbUser.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		dbUser = dbUser.Where("created_at <= ?", endTime)
	}
	dbUser.Select("username, count(*) as count").
		Group("username").
		Order("count DESC").
		Limit(10).
		Scan(&byUser)

	return map[string]interface{}{
		"total":     total,
		"success":   successCount,
		"failed":    failedCount,
		"by_action": byAction,
		"by_user":   byUser,
	}, nil
}

// DeleteOldLogs 删除旧日志
func (s *OperationLogService) DeleteOldLogs(days int) (int64, error) {
	cutoffTime := time.Now().AddDate(0, 0, -days)
	result := dao.GetDB().Where("created_at < ?", cutoffTime).Delete(&model.OperationLog{})
	return result.RowsAffected, result.Error
}

// GetAllActions 获取所有操作类型（用于前端筛选）
func (s *OperationLogService) GetAllActions() []map[string]string {
	return []map[string]string{
		// 认证
		{"value": model.ActionLogin, "label": "登录", "category": "认证"},
		{"value": model.ActionLogout, "label": "登出", "category": "认证"},
		// 用户管理
		{"value": model.ActionCreateUser, "label": "创建用户", "category": "用户管理"},
		{"value": model.ActionUpdateUser, "label": "更新用户", "category": "用户管理"},
		{"value": model.ActionDeleteUser, "label": "删除用户", "category": "用户管理"},
		{"value": model.ActionResetPassword, "label": "重置密码", "category": "用户管理"},
		// 站点管理
		{"value": model.ActionCreateSite, "label": "创建站点", "category": "站点管理"},
		{"value": model.ActionUpdateSite, "label": "更新站点", "category": "站点管理"},
		{"value": model.ActionDeleteSite, "label": "删除站点", "category": "站点管理"},
		// 规则管理
		{"value": model.ActionReloadRules, "label": "重载规则", "category": "规则管理"},
		// IP管理
		{"value": model.ActionCreateIPBlacklist, "label": "添加IP黑名单", "category": "IP管理"},
		{"value": model.ActionDeleteIPBlacklist, "label": "删除IP黑名单", "category": "IP管理"},
		{"value": model.ActionCreateIPWhitelist, "label": "添加IP白名单", "category": "IP管理"},
		{"value": model.ActionDeleteIPWhitelist, "label": "删除IP白名单", "category": "IP管理"},
		// CC防护
		{"value": model.ActionUpdateCCProtection, "label": "更新CC防护", "category": "防护配置"},
		{"value": model.ActionUpdateProtectionConfig, "label": "更新全局防护配置", "category": "防护配置"},
		{"value": "update_weak_password_config", "label": "更新弱口令检测配置", "category": "防护配置"},
		{"value": "update_monitor_config", "label": "更新运行告警配置", "category": "系统"},
		{"value": "acknowledge_alert", "label": "确认告警", "category": "系统"},
		{"value": "resolve_weak_password_alert", "label": "处理弱口令告警", "category": "系统"},
		// WAF
		{"value": model.ActionReloadWAF, "label": "重载WAF", "category": "系统"},
	}
}
