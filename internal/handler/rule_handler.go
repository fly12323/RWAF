package handler

import (
	"errors"
	"strconv"

	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/coraza"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// RuleHandler 规则处理器
type RuleHandler struct {
	ruleService *service.RuleService
}

// NewRuleHandler 创建规则处理器实例
func NewRuleHandler() *RuleHandler {
	return &RuleHandler{
		ruleService: service.NewRuleService(),
	}
}

// GetList 获取规则列表
// GET /api/v1/rules
func (h *RuleHandler) GetList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	category := c.Query("category")
	severity := c.Query("severity")
	keyword := c.Query("keyword")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	rules, total, err := h.ruleService.GetRuleList(page, pageSize, category, severity, keyword, c.Query("false_positive_risk"), c.Query("scope"))
	if err != nil {
		response.Fail(c, 500, "获取规则列表失败: "+err.Error())
		return
	}

	response.Page(c, rules, total, page, pageSize)
}

// GetDetail 获取规则详情
// GET /api/v1/rules/:id
func (h *RuleHandler) GetDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的规则ID")
		return
	}

	rule, err := h.ruleService.GetRuleByID(uint(id))
	if err != nil {
		response.Fail(c, 404, "规则不存在")
		return
	}

	response.Success(c, rule)
}

// Create 创建自定义规则
// POST /api/v1/rules
func (h *RuleHandler) Create(c *gin.Context) {
	var req service.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	rule, err := h.ruleService.CreateRule(&req)
	if err != nil {
		response.Fail(c, 500, "创建规则失败: "+err.Error())
		return
	}

	response.SuccessWithMsg(c, "规则创建成功", rule)
}

// Update 更新规则
// PUT /api/v1/rules/:id
func (h *RuleHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的规则ID")
		return
	}

	var req service.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	rule, err := h.ruleService.UpdateRule(uint(id), &req)
	if err != nil {
		if errors.Is(err, service.ErrBuiltinRuleReadOnly) {
			response.Fail(c, 403, err.Error())
			return
		}
		response.Fail(c, 500, "更新规则失败: "+err.Error())
		return
	}

	response.SuccessWithMsg(c, "规则更新成功", rule)
}

// Delete 删除规则
// DELETE /api/v1/rules/:id
func (h *RuleHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的规则ID")
		return
	}

	if err := h.ruleService.DeleteRule(uint(id)); err != nil {
		if errors.Is(err, service.ErrBuiltinRuleReadOnly) {
			response.Fail(c, 403, err.Error())
			return
		}
		response.Fail(c, 500, "删除规则失败: "+err.Error())
		return
	}

	response.SuccessWithMsg(c, "规则删除成功", nil)
}

// ToggleStatus 切换规则状态
// PUT /api/v1/rules/:id/status
func (h *RuleHandler) ToggleStatus(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的规则ID")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	if err := h.ruleService.ToggleRuleStatus(uint(id), req.Enabled); err != nil {
		if errors.Is(err, service.ErrBuiltinRuleReadOnly) {
			response.Fail(c, 403, err.Error())
			return
		}
		response.Fail(c, 500, "更新状态失败: "+err.Error())
		return
	}

	message := "规则已启用"
	if !req.Enabled {
		message = "规则已禁用"
	}
	response.SuccessWithMsg(c, message, nil)
}

// GetCategories 获取规则分类
// GET /api/v1/rules/categories
func (h *RuleHandler) GetCategories(c *gin.Context) {
	categories, err := h.ruleService.GetRuleCategories()
	if err != nil {
		response.Fail(c, 500, "获取分类失败: "+err.Error())
		return
	}

	response.Success(c, categories)
}

// GetPresets exposes shared, read-only rule policy templates.
func (h *RuleHandler) GetPresets(c *gin.Context) { response.Success(c, model.RulePresets()) }

// GetStatistics 获取规则统计
// GET /api/v1/rules/statistics
func (h *RuleHandler) GetStatistics(c *gin.Context) {
	stats, err := h.ruleService.GetRuleStatistics()
	if err != nil {
		response.Fail(c, 500, "获取统计失败: "+err.Error())
		return
	}

	response.Success(c, stats)
}

// ReloadRules 重新加载规则（热加载）
// POST /api/v1/rules/reload
func (h *RuleHandler) ReloadRules(c *gin.Context) {
	engine := coraza.GetGlobalWAFEngine()
	if engine == nil {
		middleware.LogFailed(c, model.ActionReloadRules, model.ResourceRule, 0, nil, "WAF 引擎未初始化")
		response.Fail(c, 500, "WAF 引擎未初始化")
		return
	}

	if err := engine.ReloadNow(); err != nil {
		middleware.LogFailed(c, model.ActionReloadRules, model.ResourceRule, 0, nil, err.Error())
		response.Fail(c, 500, "热加载失败: "+err.Error())
		return
	}
	if err := h.ruleService.SyncBuiltinCatalog(); err != nil {
		response.Fail(c, 500, "规则已重载，但目录同步失败: "+err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionReloadRules, model.ResourceRule, 0, nil)
	response.SuccessWithMsg(c, "规则热加载成功", nil)
}
