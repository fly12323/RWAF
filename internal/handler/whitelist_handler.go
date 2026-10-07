package handler

import (
	"strconv"

	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// WhitelistHandler 白名单处理器
type WhitelistHandler struct {
	whitelistService *service.WhitelistService
}

// NewWhitelistHandler 创建白名单处理器实例
func NewWhitelistHandler() *WhitelistHandler {
	return &WhitelistHandler{
		whitelistService: service.NewWhitelistService(),
	}
}

// GetList 获取白名单列表
// GET /api/v1/whitelists
func (h *WhitelistHandler) GetList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	whitelistType := c.Query("type")

	var siteID *uint
	if siteIDStr := c.Query("site_id"); siteIDStr != "" {
		id, err := strconv.ParseUint(siteIDStr, 10, 64)
		if err == nil {
			uid := uint(id)
			siteID = &uid
		}
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	whitelists, total, err := h.whitelistService.GetWhitelistList(page, pageSize, whitelistType, siteID)
	if err != nil {
		response.Fail(c, 500, "获取白名单列表失败: "+err.Error())
		return
	}

	response.Page(c, whitelists, total, page, pageSize)
}

// GetDetail 获取白名单详情
// GET /api/v1/whitelists/:id
func (h *WhitelistHandler) GetDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的白名单ID")
		return
	}

	whitelist, err := h.whitelistService.GetWhitelistByID(uint(id))
	if err != nil {
		response.Fail(c, 404, "白名单不存在")
		return
	}

	response.Success(c, whitelist)
}

// Create 创建白名单
// POST /api/v1/whitelists
func (h *WhitelistHandler) Create(c *gin.Context) {
	var req service.CreateWhitelistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	whitelist, err := h.whitelistService.CreateWhitelist(&req)
	if err != nil {
		response.Fail(c, 500, "创建白名单失败: "+err.Error())
		return
	}

	response.SuccessWithMsg(c, "白名单创建成功", whitelist)
}

// Update 更新白名单
// PUT /api/v1/whitelists/:id
func (h *WhitelistHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的白名单ID")
		return
	}

	var req service.UpdateWhitelistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	whitelist, err := h.whitelistService.UpdateWhitelist(uint(id), &req)
	if err != nil {
		response.Fail(c, 500, "更新白名单失败: "+err.Error())
		return
	}

	response.SuccessWithMsg(c, "白名单更新成功", whitelist)
}

// Delete 删除白名单
// DELETE /api/v1/whitelists/:id
func (h *WhitelistHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的白名单ID")
		return
	}

	if err := h.whitelistService.DeleteWhitelist(uint(id)); err != nil {
		response.Fail(c, 500, "删除白名单失败: "+err.Error())
		return
	}

	response.SuccessWithMsg(c, "白名单删除成功", nil)
}

// ToggleStatus 切换白名单状态
// PUT /api/v1/whitelists/:id/status
func (h *WhitelistHandler) ToggleStatus(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的白名单ID")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	if err := h.whitelistService.ToggleWhitelistStatus(uint(id), req.Enabled); err != nil {
		response.Fail(c, 500, "更新状态失败: "+err.Error())
		return
	}

	message := "白名单已启用"
	if !req.Enabled {
		message = "白名单已禁用"
	}
	response.SuccessWithMsg(c, message, nil)
}
