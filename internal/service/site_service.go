package service

import (
	"encoding/json"
	"errors"
	"sync"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/certificates"
	"github.com/fly12323/RWAF/pkg/proxy"

	"gorm.io/gorm"
)

// ProxyManager 全局代理管理器（在 main.go 中设置）
var ProxyManager *proxy.ProxyManager
var siteChanges sync.Mutex

// SetProxyManager 设置全局代理管理器
func SetProxyManager(pm *proxy.ProxyManager) {
	ProxyManager = pm
}

// SiteService 站点服务
type SiteService struct{}

// NewSiteService 创建站点服务实例
func NewSiteService() *SiteService {
	return &SiteService{}
}

// GetSiteList 获取站点列表
func (s *SiteService) GetSiteList(page, pageSize int, keyword string) ([]model.Site, int64, error) {
	var sites []model.Site
	var total int64

	db := dao.GetDB().Model(&model.Site{})

	if keyword != "" {
		db = db.Where("name ILIKE ? OR domains::text ILIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := db.Offset(offset).Limit(pageSize).Order("id DESC").Find(&sites).Error; err != nil {
		return nil, 0, err
	}

	return sites, total, nil
}

// GetSiteByID 根据ID获取站点详情
func (s *SiteService) GetSiteByID(id uint) (*model.Site, error) {
	var site model.Site
	if err := dao.GetDB().First(&site, id).Error; err != nil {
		return nil, err
	}
	return &site, nil
}

// CreateSiteRequest 创建站点请求结构
type CreateSiteRequest struct {
	TLSEnabled          bool           `json:"tls_enabled"`
	TLSCertificate      string         `json:"tls_certificate"`
	TLSPrivateKey       string         `json:"tls_private_key"`
	Name                string         `json:"name" binding:"required"`
	Domains             []string       `json:"domains"`
	ListenPort          int            `json:"listen_port"`
	UpstreamMode        string         `json:"upstream_mode"`
	UpstreamTargets     []proxy.Target `json:"upstream_targets" binding:"required"`
	LoadBalanceStrategy string         `json:"load_balance_strategy"`
}

// CreateSite 创建站点
func (s *SiteService) CreateSite(req *CreateSiteRequest) (*model.Site, error) {
	siteChanges.Lock()
	defer siteChanges.Unlock()
	domainsJSON, _ := json.Marshal(req.Domains)
	targetsJSON, _ := json.Marshal(req.UpstreamTargets)

	site := &model.Site{
		TLSEnabled:          req.TLSEnabled,
		TLSCertificate:      req.TLSCertificate,
		Name:                req.Name,
		Domains:             string(domainsJSON),
		ListenPort:          req.ListenPort,
		Enabled:             true,
		UpstreamMode:        req.UpstreamMode,
		UpstreamTargets:     string(targetsJSON),
		LoadBalanceStrategy: req.LoadBalanceStrategy,
	}
	if err := prepareSiteTLS(site, req.TLSPrivateKey); err != nil {
		return nil, err
	}

	if err := dao.GetDB().Create(site).Error; err != nil {
		return nil, err
	}

	// 热更新：添加到代理管理器
	if ProxyManager != nil && site.Enabled {
		if err := ProxyManager.AddSite(site); err != nil {
			rollback := dao.GetDB().Delete(site).Error
			return nil, errors.Join(err, rollback)
		}
	}

	return site, nil
}

// UpdateSiteRequest 更新站点请求结构
type UpdateSiteRequest struct {
	TLSEnabled          *bool          `json:"tls_enabled"`
	TLSCertificate      *string        `json:"tls_certificate"`
	TLSPrivateKey       string         `json:"tls_private_key"`
	Name                string         `json:"name"`
	Domains             []string       `json:"domains"`
	ListenPort          int            `json:"listen_port"`
	Enabled             *bool          `json:"enabled"`
	UpstreamMode        string         `json:"upstream_mode"`
	UpstreamTargets     []proxy.Target `json:"upstream_targets"`
	LoadBalanceStrategy string         `json:"load_balance_strategy"`
}

// UpdateSite 更新站点
func (s *SiteService) UpdateSite(id uint, req *UpdateSiteRequest) (*model.Site, error) {
	siteChanges.Lock()
	defer siteChanges.Unlock()
	site, err := s.GetSiteByID(id)
	if err != nil {
		return nil, err
	}

	previous := *site
	if req.TLSEnabled != nil {
		site.TLSEnabled = *req.TLSEnabled
	}
	if req.TLSCertificate != nil {
		site.TLSCertificate = *req.TLSCertificate
	}
	if req.Domains != nil {
		raw, _ := json.Marshal(req.Domains)
		site.Domains = string(raw)
	}
	if err := prepareSiteTLS(site, req.TLSPrivateKey); err != nil {
		return nil, err
	}
	updates := make(map[string]interface{})
	updates["tls_enabled"] = site.TLSEnabled
	updates["tls_certificate"] = site.TLSCertificate
	updates["tls_private_key"] = site.TLSPrivateKey
	updates["domains"] = site.Domains

	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.ListenPort > 0 {
		updates["listen_port"] = req.ListenPort
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.UpstreamMode != "" {
		updates["upstream_mode"] = req.UpstreamMode
	}
	if req.UpstreamTargets != nil {
		targetsJSON, _ := json.Marshal(req.UpstreamTargets)
		updates["upstream_targets"] = string(targetsJSON)
	}
	if req.LoadBalanceStrategy != "" {
		updates["load_balance_strategy"] = req.LoadBalanceStrategy
	}

	if err := dao.GetDB().Model(site).Updates(updates).Error; err != nil {
		return nil, err
	}

	site, err = s.GetSiteByID(id)
	if err != nil {
		return nil, err
	}

	// 热更新
	if ProxyManager != nil {
		if err := ProxyManager.UpdateSite(site); err != nil {
			rollback := dao.GetDB().Model(&model.Site{}).Where("id = ?", id).Select("*").Updates(&previous).Error
			return nil, errors.Join(err, rollback)
		}
	}

	return site, nil
}

// DeleteSite 删除站点
func (s *SiteService) DeleteSite(id uint) error {
	siteChanges.Lock()
	defer siteChanges.Unlock()

	result := dao.GetDB().Delete(&model.Site{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	if ProxyManager != nil {
		ProxyManager.RemoveSite(id)
	}
	return nil
}

// ToggleSiteStatus updates the database and reports listener failures.
func (s *SiteService) ToggleSiteStatus(id uint, enabled bool) error {
	siteChanges.Lock()
	defer siteChanges.Unlock()
	site, err := s.GetSiteByID(id)
	if err != nil {
		return err
	}
	old := site.Enabled
	site.Enabled = enabled
	if err := dao.GetDB().Model(&model.Site{}).Where("id = ?", id).Update("enabled", enabled).Error; err != nil {
		return err
	}
	if ProxyManager != nil {
		if err := ProxyManager.UpdateSite(site); err != nil {
			rollback := dao.GetDB().Model(&model.Site{}).Where("id = ?", id).Update("enabled", old).Error
			return errors.Join(err, rollback)
		}
	}
	return nil
}

func prepareSiteTLS(site *model.Site, privateKey string) error {
	domains, err := proxy.NormalizeDomains(site.Domains)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(domains)
	site.Domains = string(raw)
	if privateKey != "" {
		if _, err = certificates.Validate(site.TLSCertificate, privateKey, domains); err != nil {
			return err
		}
		site.TLSPrivateKey, err = certificates.Encrypt(privateKey)
		if err != nil {
			return err
		}
	}
	if site.TLSEnabled {
		if _, err = certificates.ForSite(site, domains); err != nil {
			return err
		}
	}
	return nil
}
