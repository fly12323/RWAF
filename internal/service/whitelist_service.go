package service

import (
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
)

// WhitelistService 白名单服务
type WhitelistService struct{}

// NewWhitelistService 创建白名单服务实例
func NewWhitelistService() *WhitelistService {
	return &WhitelistService{}
}

// GetWhitelistList 获取白名单列表
func (s *WhitelistService) GetWhitelistList(page, pageSize int, whitelistType string, siteID *uint) ([]model.Whitelist, int64, error) {
	var whitelists []model.Whitelist
	var total int64

	db := dao.GetDB().Model(&model.Whitelist{})

	// 添加筛选条件
	if whitelistType != "" {
		db = db.Where("type = ?", whitelistType)
	}
	if siteID != nil {
		db = db.Where("site_id = ? OR site_id IS NULL", *siteID)
	}

	// 统计总数
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	if err := db.Offset(offset).Limit(pageSize).Order("id DESC").Find(&whitelists).Error; err != nil {
		return nil, 0, err
	}

	return whitelists, total, nil
}

// GetWhitelistByID 根据ID获取白名单详情
func (s *WhitelistService) GetWhitelistByID(id uint) (*model.Whitelist, error) {
	var whitelist model.Whitelist
	if err := dao.GetDB().First(&whitelist, id).Error; err != nil {
		return nil, err
	}
	return &whitelist, nil
}

// CreateWhitelistRequest 创建白名单请求
type CreateWhitelistRequest struct {
	SiteID      *uint  `json:"site_id"`
	Type        string `json:"type" binding:"required"`
	Value       string `json:"value" binding:"required"`
	MatchType   string `json:"match_type"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// CreateWhitelist 创建白名单
func (s *WhitelistService) CreateWhitelist(req *CreateWhitelistRequest) (*model.Whitelist, error) {
	// 设置默认值
	if req.MatchType == "" {
		req.MatchType = "exact"
	}

	whitelist := &model.Whitelist{
		SiteID:      req.SiteID,
		Type:        req.Type,
		Value:       req.Value,
		MatchType:   req.MatchType,
		Description: req.Description,
		Enabled:     req.Enabled,
	}

	if err := dao.GetDB().Create(whitelist).Error; err != nil {
		return nil, err
	}

	return whitelist, nil
}

// UpdateWhitelistRequest 更新白名单请求
type UpdateWhitelistRequest struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	MatchType   string `json:"match_type"`
	Description string `json:"description"`
	Enabled     *bool  `json:"enabled"`
}

// UpdateWhitelist 更新白名单
func (s *WhitelistService) UpdateWhitelist(id uint, req *UpdateWhitelistRequest) (*model.Whitelist, error) {
	whitelist, err := s.GetWhitelistByID(id)
	if err != nil {
		return nil, err
	}

	updates := make(map[string]interface{})

	if req.Type != "" {
		updates["type"] = req.Type
	}
	if req.Value != "" {
		updates["value"] = req.Value
	}
	if req.MatchType != "" {
		updates["match_type"] = req.MatchType
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}

	if err := dao.GetDB().Model(whitelist).Updates(updates).Error; err != nil {
		return nil, err
	}

	return s.GetWhitelistByID(id)
}

// DeleteWhitelist 删除白名单
func (s *WhitelistService) DeleteWhitelist(id uint) error {
	return dao.GetDB().Delete(&model.Whitelist{}, id).Error
}

// ToggleWhitelistStatus 切换白名单启用状态
func (s *WhitelistService) ToggleWhitelistStatus(id uint, enabled bool) error {
	return dao.GetDB().Model(&model.Whitelist{}).Where("id = ?", id).Update("enabled", enabled).Error
}

// CheckIPWhitelist 检查IP是否在白名单中
func (s *WhitelistService) CheckIPWhitelist(ip string, siteID *uint) bool {
	var whitelist model.Whitelist

	// 查询全局白名单或站点白名单
	query := dao.GetDB().Where("type = ? AND enabled = ?", "ip", true)
	if siteID != nil {
		query = query.Where("site_id = ? OR site_id IS NULL", *siteID)
	} else {
		query = query.Where("site_id IS NULL")
	}

	// 精确匹配
	if err := query.Where("value = ? AND match_type = ?", ip, "exact").First(&whitelist).Error; err == nil {
		return true
	}

	// CIDR 匹配（简化版，实际需要用 net.ContainsIP）
	// TODO: 实现 CIDR 匹配

	return false
}

// CheckURLWhitelist 检查URL是否在白名单中
func (s *WhitelistService) CheckURLWhitelist(url string, siteID *uint) bool {
	var whitelist model.Whitelist

	query := dao.GetDB().Where("type = ? AND enabled = ?", "url", true)
	if siteID != nil {
		query = query.Where("site_id = ? OR site_id IS NULL", *siteID)
	} else {
		query = query.Where("site_id IS NULL")
	}

	// 精确匹配
	if err := query.Where("value = ? AND match_type = ?", url, "exact").First(&whitelist).Error; err == nil {
		return true
	}

	// 正则匹配（简化版）
	// TODO: 实现正则匹配

	return false
}
