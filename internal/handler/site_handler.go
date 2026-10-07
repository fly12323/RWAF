package handler

import (
	"strconv"

	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/proxy"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// SiteHandler 站点处理器
type SiteHandler struct {
	siteService *service.SiteService
}

// NewSiteHandler 创建站点处理器实例
func NewSiteHandler() *SiteHandler {
	return &SiteHandler{
		siteService: service.NewSiteService(),
	}
}

// GetList 获取站点列表
// GET /api/v1/sites
func (h *SiteHandler) GetList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	keyword := c.Query("keyword")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	sites, total, err := h.siteService.GetSiteList(page, pageSize, keyword)
	if err != nil {
		response.Fail(c, 500, "获取站点列表失败: "+err.Error())
		return
	}

	response.Page(c, sites, total, page, pageSize)
}

// GetDetail 获取站点详情
// GET /api/v1/sites/:id
func (h *SiteHandler) GetDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的站点ID")
		return
	}

	site, err := h.siteService.GetSiteByID(uint(id))
	if err != nil {
		response.Fail(c, 404, "站点不存在")
		return
	}

	response.Success(c, site)
}

// Create 创建站点
// POST /api/v1/sites
func (h *SiteHandler) Create(c *gin.Context) {
	var req service.CreateSiteRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	// 设置默认值
	if req.ListenPort == 0 {
		req.ListenPort = 9000
	}
	if req.UpstreamMode == "" {
		req.UpstreamMode = "ip"
	}
	if req.LoadBalanceStrategy == "" {
		req.LoadBalanceStrategy = "round_robin"
	}

	site, err := h.siteService.CreateSite(&req)
	if err != nil {
		middleware.LogFailed(c, model.ActionCreateSite, model.ResourceSite, 0, map[string]interface{}{
			"name": req.Name,
		}, err.Error())
		response.Fail(c, 500, "创建站点失败: "+err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionCreateSite, model.ResourceSite, site.ID, map[string]interface{}{
		"name": req.Name,
	})
	response.SuccessWithMsg(c, "站点创建成功", site)
}

// Update 更新站点
// PUT /api/v1/sites/:id
func (h *SiteHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的站点ID")
		return
	}

	var req service.UpdateSiteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	site, err := h.siteService.UpdateSite(uint(id), &req)
	if err != nil {
		middleware.LogFailed(c, model.ActionUpdateSite, model.ResourceSite, uint(id), map[string]interface{}{
			"site_id": id,
		}, err.Error())
		response.Fail(c, 500, "更新站点失败: "+err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionUpdateSite, model.ResourceSite, uint(id), map[string]interface{}{
		"site_name": site.Name,
	})
	response.SuccessWithMsg(c, "站点更新成功", site)
}

// Delete 删除站点
// DELETE /api/v1/sites/:id
func (h *SiteHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的站点ID")
		return
	}

	// 获取站点信息用于日志
	site, _ := h.siteService.GetSiteByID(uint(id))

	if err := h.siteService.DeleteSite(uint(id)); err != nil {
		middleware.LogFailed(c, model.ActionDeleteSite, model.ResourceSite, uint(id), nil, err.Error())
		response.Fail(c, 500, "删除站点失败: "+err.Error())
		return
	}

	if site != nil {
		middleware.LogSuccess(c, model.ActionDeleteSite, model.ResourceSite, uint(id), map[string]interface{}{
			"site_name": site.Name,
		})
	} else {
		middleware.LogSuccess(c, model.ActionDeleteSite, model.ResourceSite, uint(id), nil)
	}
	response.SuccessWithMsg(c, "站点删除成功", nil)
}

// ToggleStatus 切换站点状态
// PUT /api/v1/sites/:id/status
func (h *SiteHandler) ToggleStatus(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的站点ID")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	if err := h.siteService.ToggleSiteStatus(uint(id), req.Enabled); err != nil {
		middleware.LogFailed(c, model.ActionToggleSiteStatus, model.ResourceSite, uint(id), map[string]interface{}{
			"enabled": req.Enabled,
		}, err.Error())
		response.Fail(c, 500, "更新状态失败: "+err.Error())
		return
	}

	message := "站点已启用"
	if !req.Enabled {
		message = "站点已禁用"
	}
	middleware.LogSuccess(c, model.ActionToggleSiteStatus, model.ResourceSite, uint(id), map[string]interface{}{
		"enabled": req.Enabled,
	})
	response.SuccessWithMsg(c, message, nil)
}

// GetSiteResponse 站点响应结构
type GetSiteResponse struct {
	*model.Site
	DomainsArr         []string       `json:"domains_arr"`
	UpstreamTargetsArr []proxy.Target `json:"upstream_targets_arr"`
}
