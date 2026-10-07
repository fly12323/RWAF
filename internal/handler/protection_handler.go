package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/protection"
	"github.com/fly12323/RWAF/pkg/coraza"
	"github.com/fly12323/RWAF/pkg/response"
)

func GetProtectionConfig(c *gin.Context) {
	cfg, err := protection.GetConfig()
	if err != nil {
		response.Fail(c, 500, "获取全局防护配置失败")
		return
	}
	response.Success(c, cfg)
}
func UpdateProtectionConfig(c *gin.Context) {
	var cfg model.ProtectionConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		response.Fail(c, 400, "防护配置格式错误")
		return
	}
	if err := protection.Validate(&cfg); err != nil {
		response.Fail(c, 400, err.Error())
		return
	}
	engine := coraza.GetGlobalWAFEngine()
	if engine == nil {
		response.Fail(c, 503, "规则引擎尚未初始化")
		return
	}
	if _, err := engine.PolicyEngine(cfg.WafMode, cfg.DisabledRuleIDs, cfg.EnabledRuleCategories); err != nil {
		response.Fail(c, 400, "规则策略无效: "+err.Error())
		return
	}
	if err := protection.SaveConfig(&cfg); err != nil {
		response.Fail(c, 500, "保存全局防护配置失败")
		return
	}
	middleware.LogSuccess(c, model.ActionUpdateProtectionConfig, model.ResourceWAF, 0, map[string]any{"scope": "global"})
	response.Success(c, cfg)
}
