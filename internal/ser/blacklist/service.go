package blacklist

import (
	"time"

	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/ipcache"
	"github.com/fly12323/RWAF/internal/ser/protection"
	"github.com/fly12323/RWAF/internal/utils"
)

// IPBlacklistService IP黑名单服务
type IPBlacklistService struct{}

// NewIPBlacklistService 创建IP黑名单服务实例
func NewIPBlacklistService() *IPBlacklistService {
	return &IPBlacklistService{}
}

// CreateRequest 创建请求
type IPBlacklistCreateRequest struct {
	IP       string     `json:"ip" binding:"required"`
	Reason   string     `json:"reason"`
	Duration int        `json:"duration"` // 封禁时长（小时），0表示永久
	ExpireAt *time.Time `json:"expire_at"`
}

// Create 创建黑名单
func (s *IPBlacklistService) Create(req *IPBlacklistCreateRequest, createdBy string) (*model.IPBlacklist, error) {
	defer ipcache.Invalidate()
	// 检查是否已存在
	var existing model.IPBlacklist
	if err := dao.GetDB().Where("ip = ?", req.IP).First(&existing).Error; err == nil {
		// 已存在，更新状态
		updates := map[string]interface{}{
			"reason":     req.Reason,
			"type":       1, // 手动
			"status":     1,
			"expire_at":  req.ExpireAt,
			"created_by": createdBy,
			"updated_at": time.Now(),
		}
		if req.Duration > 0 {
			expireAt := time.Now().Add(time.Duration(req.Duration) * time.Hour)
			updates["expire_at"] = &expireAt
		}
		dao.GetDB().Model(&existing).Updates(updates)
		return &existing, nil
	}

	// 创建新记录
	blacklist := &model.IPBlacklist{
		IP:        req.IP,
		Reason:    req.Reason,
		Type:      1, // 手动
		Status:    1,
		CreatedBy: createdBy,
	}

	if req.Duration > 0 {
		expireAt := time.Now().Add(time.Duration(req.Duration) * time.Hour)
		blacklist.ExpireAt = &expireAt
	} else if req.ExpireAt != nil {
		blacklist.ExpireAt = req.ExpireAt
	}

	if err := dao.GetDB().Create(blacklist).Error; err != nil {
		return nil, err
	}

	return blacklist, nil
}

// Update 更新黑名单
func (s *IPBlacklistService) Update(id uint, req *IPBlacklistCreateRequest) (*model.IPBlacklist, error) {
	defer ipcache.Invalidate()
	var blacklist model.IPBlacklist
	if err := dao.GetDB().First(&blacklist, id).Error; err != nil {
		return nil, err
	}

	updates := map[string]interface{}{
		"reason":     req.Reason,
		"updated_at": time.Now(),
	}

	if req.Duration > 0 {
		expireAt := time.Now().Add(time.Duration(req.Duration) * time.Hour)
		updates["expire_at"] = &expireAt
	} else if req.Duration == 0 {
		updates["expire_at"] = nil // 永久
	}

	dao.GetDB().Model(&blacklist).Updates(updates)
	return &blacklist, nil
}

// Delete 删除黑名单
func (s *IPBlacklistService) Delete(id uint) error {
	defer ipcache.Invalidate()
	return dao.GetDB().Delete(&model.IPBlacklist{}, id).Error
}

// ToggleStatus 切换状态
func (s *IPBlacklistService) ToggleStatus(id uint, status int8) error {
	defer ipcache.Invalidate()
	return dao.GetDB().Model(&model.IPBlacklist{}).Where("id = ?", id).Update("status", status).Error
}

// GetList 获取列表
func (s *IPBlacklistService) GetList(page, pageSize int, ip, blockType string, status int8) ([]model.IPBlacklist, int64, error) {
	var list []model.IPBlacklist
	var total int64

	db := dao.GetDB().Model(&model.IPBlacklist{})

	if ip != "" {
		db = db.Where("ip LIKE ?", "%"+ip+"%")
	}
	if blockType != "" {
		if blockType == "manual" {
			db = db.Where("type = ?", 1)
		} else if blockType == "auto" {
			db = db.Where("type = ?", 2)
		}
	}
	if status >= 0 {
		db = db.Where("status = ?", status)
	}

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := db.Order("id DESC").Offset(offset).Limit(pageSize).Find(&list).Error; err != nil {
		return nil, 0, err
	}

	return list, total, nil
}

// IsBlocked 检查IP是否被封禁
func (s *IPBlacklistService) IsBlocked(ip string) (bool, *model.IPBlacklist) {
	var blacklist model.IPBlacklist

	// 精确匹配
	err := dao.GetDB().Where("ip = ? AND status = 1", ip).First(&blacklist).Error
	if err == nil {
		// 检查是否过期
		if !blacklist.IsExpired() {
			return true, &blacklist
		}
		// 已过期，更新状态
		dao.GetDB().Model(&blacklist).Update("status", 0)
	}

	// CIDR 匹配（IP段）
	var cidrList []model.IPBlacklist
	dao.GetDB().Where("status = 1 AND ip LIKE '%/%'").Find(&cidrList)

	for _, item := range cidrList {
		if utils.MatchCIDR(ip, item.IP) {
			if !item.IsExpired() {
				return true, &item
			}
			dao.GetDB().Model(&item).Update("status", 0)
		}
	}

	return false, nil
}

// AutoBlock 自动封禁
// hours 为 0 表示永久封禁，不设置过期时间
func (s *IPBlacklistService) AutoBlock(ip, reason string, hours int) error {
	defer ipcache.Invalidate()
	// 检查是否已存在
	var existing model.IPBlacklist
	if err := dao.GetDB().Where("ip = ?", ip).First(&existing).Error; err == nil {
		// 已存在，更新过期时间
		updates := map[string]interface{}{
			"status":     1,
			"reason":     reason,
			"updated_at": time.Now(),
		}
		if hours > 0 {
			expireAt := time.Now().Add(time.Duration(hours) * time.Hour)
			updates["expire_at"] = &expireAt
		} else {
			updates["expire_at"] = nil // 永久封禁
		}
		return dao.GetDB().Model(&existing).Updates(updates).Error
	}

	// 创建新记录
	blacklist := &model.IPBlacklist{
		IP:     ip,
		Reason: reason,
		Type:   2, // 自动
		Status: 1,
	}
	if hours > 0 {
		expireAt := time.Now().Add(time.Duration(hours) * time.Hour)
		blacklist.ExpireAt = &expireAt
	}
	// hours == 0 时 ExpireAt 为 nil，表示永久封禁

	return dao.GetDB().Create(blacklist).Error
}

// CleanExpired 清理过期记录
func (s *IPBlacklistService) CleanExpired() (int64, error) {
	defer ipcache.Invalidate()
	result := dao.GetDB().Where("expire_at IS NOT NULL AND expire_at < ?", time.Now()).
		Delete(&model.IPBlacklist{})
	return result.RowsAffected, result.Error
}

// GetAutoBlockConfig returns the auto-ban section of the shared policy.
func (s *IPBlacklistService) GetAutoBlockConfig() (*model.AutoBlockConfig, error) {
	cfg, err := protection.GetConfig()
	if err != nil {
		return nil, err
	}
	return cfg.AutoBlockConfig(), nil
}
func (s *IPBlacklistService) UpdateAutoBlockConfig(cfg *model.AutoBlockConfig) error {
	return protection.UpdateAutoBlock(cfg)
}

// GetStats 获取统计数据
type Stats struct {
	Total         int64 `json:"total"`
	EnabledCount  int64 `json:"enabled_count"`
	DisabledCount int64 `json:"disabled_count"`
}

func (s *IPBlacklistService) GetByID(id uint) (*model.IPBlacklist, error) {
	var entry model.IPBlacklist
	if err := dao.GetDB().First(&entry, id).Error; err != nil {
		return nil, err
	}
	return &entry, nil
}

func (s *IPBlacklistService) GetStats(ip string) (*Stats, error) {
	var stats Stats

	// 统计总数
	countDB := dao.GetDB().Model(&model.IPBlacklist{})
	if ip != "" {
		countDB = countDB.Where("ip LIKE ?", "%"+ip+"%")
	}
	if err := countDB.Count(&stats.Total).Error; err != nil {
		return nil, err
	}

	// 统计启用数 (status = 1 AND 未过期)
	enabledDB := dao.GetDB().Model(&model.IPBlacklist{})
	if ip != "" {
		enabledDB = enabledDB.Where("ip LIKE ?", "%"+ip+"%")
	}
	if err := enabledDB.Where("status = 1").Where("expire_at IS NULL OR expire_at > ?", time.Now()).Count(&stats.EnabledCount).Error; err != nil {
		return nil, err
	}

	// 统计停用数 (status = 0 OR 已过期)
	disabledDB := dao.GetDB().Model(&model.IPBlacklist{})
	if ip != "" {
		disabledDB = disabledDB.Where("ip LIKE ?", "%"+ip+"%")
	}
	if err := disabledDB.Where("(status = 0) OR (expire_at IS NOT NULL AND expire_at <= ?)", time.Now()).Count(&stats.DisabledCount).Error; err != nil {
		return nil, err
	}

	return &stats, nil
}
