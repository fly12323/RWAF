package whitelist

import (
	"time"

	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/ipcache"
	"github.com/fly12323/RWAF/internal/utils"
)

// IPWhitelistService IP白名单服务
type IPWhitelistService struct{}

// NewIPWhitelistService 创建IP白名单服务实例
func NewIPWhitelistService() *IPWhitelistService {
	return &IPWhitelistService{}
}

// CreateRequest 创建请求
type IPWhitelistCreateRequest struct {
	IP       string `json:"ip" binding:"required"`
	Reason   string `json:"reason"`
	ExpireAt string `json:"expire_at"` // RFC3339 格式
}

// Create 创建白名单
func (s *IPWhitelistService) Create(req *IPWhitelistCreateRequest, createdBy string) (*model.IPWhitelist, error) {
	defer ipcache.Invalidate()
	// 检查是否已存在
	var existing model.IPWhitelist
	if err := dao.GetDB().Where("ip = ?", req.IP).First(&existing).Error; err == nil {
		// 已存在，更新状态
		updates := map[string]interface{}{
			"reason":     req.Reason,
			"status":     1,
			"created_by": createdBy,
			"updated_at": time.Now(),
		}
		if req.ExpireAt != "" {
			expireTime, parseErr := time.Parse(time.RFC3339, req.ExpireAt)
			if parseErr == nil {
				updates["expire_at"] = expireTime
			}
		}
		dao.GetDB().Model(&existing).Updates(updates)
		return &existing, nil
	}

	// 解析过期时间
	var expireAt *time.Time
	if req.ExpireAt != "" {
		expireTime, parseErr := time.Parse(time.RFC3339, req.ExpireAt)
		if parseErr == nil {
			expireAt = &expireTime
		}
	}

	// 创建新记录
	whitelist := &model.IPWhitelist{
		IP:        req.IP,
		Reason:    req.Reason,
		Status:    1,
		CreatedBy: createdBy,
		ExpireAt:  expireAt,
	}

	if err := dao.GetDB().Create(whitelist).Error; err != nil {
		return nil, err
	}

	return whitelist, nil
}

// Update 更新白名单
func (s *IPWhitelistService) Update(id uint, req *IPWhitelistCreateRequest) (*model.IPWhitelist, error) {
	defer ipcache.Invalidate()
	var whitelist model.IPWhitelist
	if err := dao.GetDB().First(&whitelist, id).Error; err != nil {
		return nil, err
	}

	updates := map[string]interface{}{
		"reason":     req.Reason,
		"updated_at": time.Now(),
	}

	dao.GetDB().Model(&whitelist).Updates(updates)
	return &whitelist, nil
}

// Delete 删除白名单
func (s *IPWhitelistService) Delete(id uint) error {
	defer ipcache.Invalidate()
	return dao.GetDB().Delete(&model.IPWhitelist{}, id).Error
}

// ToggleStatus 切换状态
func (s *IPWhitelistService) ToggleStatus(id uint, status int8) error {
	defer ipcache.Invalidate()
	return dao.GetDB().Model(&model.IPWhitelist{}).Where("id = ?", id).Update("status", status).Error
}

// GetList 获取列表
func (s *IPWhitelistService) GetList(page, pageSize int, ip string, status int8) ([]model.IPWhitelist, int64, error) {
	var list []model.IPWhitelist
	var total int64

	db := dao.GetDB().Model(&model.IPWhitelist{})

	if ip != "" {
		db = db.Where("ip LIKE ?", "%"+ip+"%")
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

// IsWhitelisted 检查IP是否在白名单中
func (s *IPWhitelistService) IsWhitelisted(ip string) bool {
	var whitelist model.IPWhitelist

	// 精确匹配
	err := dao.GetDB().Where("ip = ? AND status = 1", ip).First(&whitelist).Error
	if err == nil {
		return true
	}

	// CIDR 匹配（IP段）
	var cidrList []model.IPWhitelist
	dao.GetDB().Where("status = 1 AND ip LIKE '%/%'").Find(&cidrList)

	for _, item := range cidrList {
		if utils.MatchCIDR(ip, item.IP) {
			return true
		}
	}

	return false
}

// GetAllEnabled 获取所有启用的白名单
func (s *IPWhitelistService) GetAllEnabled() ([]model.IPWhitelist, error) {
	var list []model.IPWhitelist
	err := dao.GetDB().Where("status = 1").Find(&list).Error
	return list, err
}

// IsWhitelistedForSite 检查IP是否在站点白名单中
func (s *IPWhitelistService) IsWhitelistedForSite(ip string, siteID uint) bool {
	var whitelist model.IPWhitelist

	// 先检查站点独立白名单
	err := dao.GetDB().Where("ip = ? AND status = 1 AND site_id = ?", ip, siteID).First(&whitelist).Error
	if err == nil {
		return true
	}

	// 再检查全局白名单
	err = dao.GetDB().Where("ip = ? AND status = 1 AND site_id IS NULL", ip).First(&whitelist).Error
	if err == nil {
		return true
	}

	// CIDR 匹配
	var cidrList []model.IPWhitelist
	dao.GetDB().Where("status = 1 AND ip LIKE '%/%' AND (site_id = ? OR site_id IS NULL)", siteID).Find(&cidrList)

	for _, item := range cidrList {
		if utils.MatchCIDR(ip, item.IP) {
			return true
		}
	}

	return false
}

// GetByID 根据ID获取白名单
func (s *IPWhitelistService) GetByID(id uint) (*model.IPWhitelist, error) {
	var whitelist model.IPWhitelist
	if err := dao.GetDB().First(&whitelist, id).Error; err != nil {
		return nil, err
	}
	return &whitelist, nil
}

// Stats 数据统计
type Stats struct {
	Total         int64 `json:"total"`
	EnabledCount  int64 `json:"enabled_count"`
	DisabledCount int64 `json:"disabled_count"`
}

// GetStats 获取统计数据
func (s *IPWhitelistService) GetStats(ip string) (*Stats, error) {
	var stats Stats

	// 统计总数
	countDB := dao.GetDB().Model(&model.IPWhitelist{})
	if ip != "" {
		countDB = countDB.Where("ip LIKE ?", "%"+ip+"%")
	}
	if err := countDB.Count(&stats.Total).Error; err != nil {
		return nil, err
	}

	// 统计启用数 (status = 1 AND 未过期)
	enabledDB := dao.GetDB().Model(&model.IPWhitelist{})
	if ip != "" {
		enabledDB = enabledDB.Where("ip LIKE ?", "%"+ip+"%")
	}
	if err := enabledDB.Where("status = 1").Where("expire_at IS NULL OR expire_at > ?", time.Now()).Count(&stats.EnabledCount).Error; err != nil {
		return nil, err
	}

	// 统计停用数 (status = 0 OR 已过期)
	disabledDB := dao.GetDB().Model(&model.IPWhitelist{})
	if ip != "" {
		disabledDB = disabledDB.Where("ip LIKE ?", "%"+ip+"%")
	}
	if err := disabledDB.Where("(status = 0) OR (expire_at IS NOT NULL AND expire_at <= ?)", time.Now()).Count(&stats.DisabledCount).Error; err != nil {
		return nil, err
	}

	return &stats, nil
}
