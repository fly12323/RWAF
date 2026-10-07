package handler

import (
	"strconv"

	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/blacklist"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// IPBlacklistHandler IP黑名单处理器
type IPBlacklistHandler struct {
	service *blacklist.IPBlacklistService
}

// NewIPBlacklistHandler 创建IP黑名单处理器实例
func NewIPBlacklistHandler() *IPBlacklistHandler {
	return &IPBlacklistHandler{
		service: blacklist.NewIPBlacklistService(),
	}
}

// GetList 获取黑名单列表
// GET /api/v1/ip-blacklist
func (h *IPBlacklistHandler) GetList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	ip := c.Query("ip")
	blockType := c.Query("type")
	status, _ := strconv.Atoi(c.DefaultQuery("status", "-1"))

	list, total, err := h.service.GetList(page, pageSize, ip, blockType, int8(status))
	if err != nil {
		response.Fail(c, 500, "获取列表失败: "+err.Error())
		return
	}

	response.Page(c, list, total, page, pageSize)
}

// Create 创建黑名单
// POST /api/v1/ip-blacklist
func (h *IPBlacklistHandler) Create(c *gin.Context) {
	var req blacklist.IPBlacklistCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	// 获取当前用户
	username, _ := c.Get("username")
	createdBy := ""
	if username != nil {
		createdBy = username.(string)
	}

	blacklistItem, err := h.service.Create(&req, createdBy)
	if err != nil {
		middleware.LogFailed(c, model.ActionCreateIPBlacklist, model.ResourceIPBlacklist, 0, map[string]interface{}{
			"ip": req.IP,
		}, err.Error())
		response.Fail(c, 500, "创建失败: "+err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionCreateIPBlacklist, model.ResourceIPBlacklist, blacklistItem.ID, map[string]interface{}{
		"ip":     req.IP,
		"reason": req.Reason,
	})
	response.Success(c, blacklistItem)
}

// Update 更新黑名单
// PUT /api/v1/ip-blacklist/:id
func (h *IPBlacklistHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的ID")
		return
	}

	var req blacklist.IPBlacklistCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	blacklistItem, err := h.service.Update(uint(id), &req)
	if err != nil {
		response.Fail(c, 500, "更新失败: "+err.Error())
		return
	}

	response.Success(c, blacklistItem)
}

// Delete 删除黑名单
// DELETE /api/v1/ip-blacklist/:id
func (h *IPBlacklistHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的ID")
		return
	}

	// 获取黑名单信息用于日志
	item, _ := h.service.GetByID(uint(id))

	if err := h.service.Delete(uint(id)); err != nil {
		middleware.LogFailed(c, model.ActionDeleteIPBlacklist, model.ResourceIPBlacklist, uint(id), nil, err.Error())
		response.Fail(c, 500, "删除失败: "+err.Error())
		return
	}

	if item != nil {
		middleware.LogSuccess(c, model.ActionDeleteIPBlacklist, model.ResourceIPBlacklist, uint(id), map[string]interface{}{
			"ip": item.IP,
		})
	} else {
		middleware.LogSuccess(c, model.ActionDeleteIPBlacklist, model.ResourceIPBlacklist, uint(id), nil)
	}
	response.Success(c, nil)
}

// ToggleStatus 切换状态
// PUT /api/v1/ip-blacklist/:id/status
func (h *IPBlacklistHandler) ToggleStatus(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的ID")
		return
	}

	var req struct {
		Status int8 `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	if err := h.service.ToggleStatus(uint(id), req.Status); err != nil {
		response.Fail(c, 500, "操作失败: "+err.Error())
		return
	}

	response.Success(c, nil)
}

// GetAutoBlockConfig 获取自动封禁配置
// GET /api/v1/ip-blacklist/auto-config
func (h *IPBlacklistHandler) GetAutoBlockConfig(c *gin.Context) {
	config, err := h.service.GetAutoBlockConfig()
	if err != nil {
		response.Fail(c, 500, "获取配置失败: "+err.Error())
		return
	}

	response.Success(c, config)
}

// UpdateAutoBlockConfig 更新自动封禁配置
// PUT /api/v1/ip-blacklist/auto-config
func (h *IPBlacklistHandler) UpdateAutoBlockConfig(c *gin.Context) {
	var config model.AutoBlockConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	if err := h.service.UpdateAutoBlockConfig(&config); err != nil {
		middleware.LogFailed(c, model.ActionUpdateAutoBlockConfig, model.ResourceIPBlacklist, 0, nil, err.Error())
		response.Fail(c, 500, "更新配置失败: "+err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionUpdateAutoBlockConfig, model.ResourceIPBlacklist, 0, map[string]interface{}{
		"enabled":   config.Enabled,
		"threshold": config.Threshold,
		"duration":  config.Duration,
	})
	response.Success(c, config)
}

// CleanExpired 清理过期记录
// DELETE /api/v1/ip-blacklist/expired
func (h *IPBlacklistHandler) CleanExpired(c *gin.Context) {
	count, err := h.service.CleanExpired()
	if err != nil {
		middleware.LogFailed(c, model.ActionCleanExpiredBlacklist, model.ResourceIPBlacklist, 0, nil, err.Error())
		response.Fail(c, 500, "清理失败: "+err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionCleanExpiredBlacklist, model.ResourceIPBlacklist, 0, map[string]interface{}{
		"cleaned_count": count,
	})
	response.Success(c, gin.H{
		"cleaned_count": count,
	})
}

// GetStats 获取统计数据
// GET /api/v1/ip-blacklist/stats
func (h *IPBlacklistHandler) GetStats(c *gin.Context) {
	ip := c.Query("ip")

	stats, err := h.service.GetStats(ip)
	if err != nil {
		response.Fail(c, 500, "获取统计失败: "+err.Error())
		return
	}

	response.Success(c, stats)
}
