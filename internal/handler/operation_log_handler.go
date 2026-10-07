package handler

import (
	"strconv"

	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// OperationLogHandler 操作日志处理器
type OperationLogHandler struct {
	logService *service.OperationLogService
}

// NewOperationLogHandler 创建操作日志处理器实例
func NewOperationLogHandler() *OperationLogHandler {
	return &OperationLogHandler{
		logService: service.NewOperationLogService(),
	}
}

// GetList 获取操作日志列表
// GET /api/v1/operation-logs
func (h *OperationLogHandler) GetList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))

	userIDStr := c.Query("user_id")
	username := c.Query("username")
	action := c.Query("action")
	resource := c.Query("resource")
	result := c.Query("result")
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	var userID uint
	if userIDStr != "" {
		id, err := strconv.ParseUint(userIDStr, 10, 64)
		if err == nil {
			userID = uint(id)
		}
	}

	logs, total, err := h.logService.GetList(page, pageSize, userID, username, action, resource, result, startTime, endTime)
	if err != nil {
		response.Fail(c, 500, "获取操作日志列表失败: "+err.Error())
		return
	}

	response.Page(c, logs, total, page, pageSize)
}

// GetStatistics 获取操作统计
// GET /api/v1/operation-logs/statistics
func (h *OperationLogHandler) GetStatistics(c *gin.Context) {
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	stats, err := h.logService.GetStatistics(startTime, endTime)
	if err != nil {
		response.Fail(c, 500, "获取统计失败: "+err.Error())
		return
	}

	response.Success(c, stats)
}

// GetActions 获取所有操作类型
// GET /api/v1/operation-logs/actions
func (h *OperationLogHandler) GetActions(c *gin.Context) {
	actions := h.logService.GetAllActions()
	response.Success(c, actions)
}

// DeleteOldLogs 删除旧日志
// DELETE /api/v1/operation-logs/old
func (h *OperationLogHandler) DeleteOldLogs(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "90"))
	if days < 7 {
		days = 7
	}

	deletedCount, err := h.logService.DeleteOldLogs(days)
	if err != nil {
		response.Fail(c, 500, "删除日志失败: "+err.Error())
		return
	}

	response.Success(c, gin.H{
		"deleted_count": deletedCount,
	})
}
