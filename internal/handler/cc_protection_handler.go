package handler

import (
	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/ratelimit"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// CCProtectionHandler CC防护处理器
type CCProtectionHandler struct {
	service *ratelimit.CCProtectionService
}

// NewCCProtectionHandler 创建CC防护处理器实例
func NewCCProtectionHandler() *CCProtectionHandler {
	return &CCProtectionHandler{
		service: ratelimit.NewCCProtectionService(),
	}
}

// GetConfig 获取配置
// GET /api/v1/cc-protection
func (h *CCProtectionHandler) GetConfig(c *gin.Context) {
	config, err := h.service.GetConfig()
	if err != nil {
		response.Fail(c, 500, "获取配置失败: "+err.Error())
		return
	}

	response.Success(c, config)
}

// UpdateConfig 更新配置
// PUT /api/v1/cc-protection
func (h *CCProtectionHandler) UpdateConfig(c *gin.Context) {
	var config model.CCProtectionConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	if err := h.service.UpdateConfig(&config); err != nil {
		middleware.LogFailed(c, model.ActionUpdateCCProtection, model.ResourceCCProtection, 0, map[string]interface{}{
			"enabled": config.Enabled,
		}, err.Error())
		response.Fail(c, 500, "更新配置失败: "+err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionUpdateCCProtection, model.ResourceCCProtection, 0, map[string]interface{}{
		"enabled":             config.Enabled,
		"requests_per_minute": config.RequestsPerMinute,
		"action":              config.Action,
	})
	response.Success(c, config)
}
