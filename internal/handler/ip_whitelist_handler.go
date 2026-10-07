package handler

import (
	"strconv"

	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/whitelist"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// IPWhitelistHandler IP白名单处理器
type IPWhitelistHandler struct {
	service *whitelist.IPWhitelistService
}

// NewIPWhitelistHandler 创建IP白名单处理器实例
func NewIPWhitelistHandler() *IPWhitelistHandler {
	return &IPWhitelistHandler{
		service: whitelist.NewIPWhitelistService(),
	}
}

// GetList 获取白名单列表
// GET /api/v1/ip-whitelist
func (h *IPWhitelistHandler) GetList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	ip := c.Query("ip")
	status, _ := strconv.Atoi(c.DefaultQuery("status", "-1"))

	list, total, err := h.service.GetList(page, pageSize, ip, int8(status))
	if err != nil {
		response.Fail(c, 500, "获取列表失败: "+err.Error())
		return
	}

	response.Page(c, list, total, page, pageSize)
}

// Create 创建白名单
// POST /api/v1/ip-whitelist
func (h *IPWhitelistHandler) Create(c *gin.Context) {
	var req whitelist.IPWhitelistCreateRequest
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

	whitelistItem, err := h.service.Create(&req, createdBy)
	if err != nil {
		middleware.LogFailed(c, model.ActionCreateIPWhitelist, model.ResourceIPWhitelist, 0, map[string]interface{}{
			"ip": req.IP,
		}, err.Error())
		response.Fail(c, 500, "创建失败: "+err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionCreateIPWhitelist, model.ResourceIPWhitelist, whitelistItem.ID, map[string]interface{}{
		"ip": req.IP,
	})
	response.Success(c, whitelistItem)
}

// Update 更新白名单
// PUT /api/v1/ip-whitelist/:id
func (h *IPWhitelistHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的ID")
		return
	}

	var req whitelist.IPWhitelistCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	whitelistItem, err := h.service.Update(uint(id), &req)
	if err != nil {
		response.Fail(c, 500, "更新失败: "+err.Error())
		return
	}

	response.Success(c, whitelistItem)
}

// Delete 删除白名单
// DELETE /api/v1/ip-whitelist/:id
func (h *IPWhitelistHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的ID")
		return
	}

	// 获取白名单信息用于日志
	item, _ := h.service.GetByID(uint(id))

	if err := h.service.Delete(uint(id)); err != nil {
		middleware.LogFailed(c, model.ActionDeleteIPWhitelist, model.ResourceIPWhitelist, uint(id), nil, err.Error())
		response.Fail(c, 500, "删除失败: "+err.Error())
		return
	}

	if item != nil {
		middleware.LogSuccess(c, model.ActionDeleteIPWhitelist, model.ResourceIPWhitelist, uint(id), map[string]interface{}{
			"ip": item.IP,
		})
	} else {
		middleware.LogSuccess(c, model.ActionDeleteIPWhitelist, model.ResourceIPWhitelist, uint(id), nil)
	}
	response.Success(c, nil)
}

// ToggleStatus 切换状态
// PUT /api/v1/ip-whitelist/:id/status
func (h *IPWhitelistHandler) ToggleStatus(c *gin.Context) {
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

// GetStats 获取统计数据
// GET /api/v1/ip-whitelist/stats
func (h *IPWhitelistHandler) GetStats(c *gin.Context) {
	ip := c.Query("ip")

	stats, err := h.service.GetStats(ip)
	if err != nil {
		response.Fail(c, 500, "获取统计失败: "+err.Error())
		return
	}

	response.Success(c, stats)
}
