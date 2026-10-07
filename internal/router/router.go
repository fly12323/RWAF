package router

import (
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/handler"
	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/protection"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/jwt"
	"github.com/fly12323/RWAF/pkg/proxy"

	"github.com/gin-gonic/gin"
)

// SetupAPIRouter 设置管理 API 路由
func SetupAPIRouter(r *gin.Engine, proxyManager *proxy.ProxyManager, jwtInstance *jwt.JWT,
	tokenService *service.TokenService, userService *service.UserService) {

	// 创建处理器实例
	siteHandler := handler.NewSiteHandler()
	ruleHandler := handler.NewRuleHandler()
	whitelistHandler := handler.NewWhitelistHandler()
	logHandler := handler.NewLogHandler()
	authHandler := handler.NewAuthHandler(userService, jwtInstance)
	userHandler := handler.NewUserHandler(userService)
	ipBlacklistHandler := handler.NewIPBlacklistHandler()
	ipWhitelistHandler := handler.NewIPWhitelistHandler()
	ccProtectionHandler := handler.NewCCProtectionHandler()
	// 爬虫检测处理器
	crawlerHandler := handler.NewCrawlerHandler()
	// 操作日志处理器
	operationLogHandler := handler.NewOperationLogHandler()

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"message": "WAF 服务运行正常",
		})
	})

	// API v1 路由组
	api := r.Group("/api/v1")
	{
		// 认证接口（不需要认证）
		auth := api.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)
		}

		// 需要认证的接口
		authorized := api.Group("")
		authorized.Use(middleware.JWTAuthMiddleware(jwtInstance, tokenService))
		{
			readDetection := authorized.Group("")
			readDetection.Use(middleware.RequireAuditor())
			readDetection.GET("/weak-password/events", handler.GetWeakPasswordEvents)
			readDetection.GET("/weak-password/events/:id", handler.GetWeakPasswordEventDetail)
			readDetection.GET("/monitor/status", handler.GetMonitorStatus)
			readDetection.GET("/monitor/alerts", handler.GetAlerts)
			writeDetection := authorized.Group("")
			writeDetection.Use(middleware.RequireOperator())
			writeDetection.GET("/weak-password/config", handler.GetWeakPasswordConfig)
			writeDetection.POST("/weak-password/preview", handler.PreviewWeakPassword)
			writeDetection.PUT("/weak-password/config", handler.UpdateWeakPasswordConfig)
			writeDetection.GET("/monitor/config", handler.GetMonitorConfig)
			writeDetection.PUT("/monitor/config", handler.UpdateMonitorConfig)
			writeDetection.POST("/monitor/alerts/:id/acknowledge", handler.AcknowledgeAlert)
			writeDetection.POST("/monitor/alerts/:id/resolve", handler.ResolveWeakAlert)
			// 认证相关
			authorized.GET("/auth/info", authHandler.GetUserInfo)
			authorized.POST("/auth/logout", authHandler.Logout)
			authorized.POST("/auth/password", authHandler.ChangePassword)
			authorized.POST("/auth/refresh", authHandler.RefreshToken)

			// 用户管理（仅管理员）
			users := authorized.Group("/users")
			users.Use(middleware.RequireAdmin())
			{
				users.GET("", userHandler.GetUserList)
				users.GET("/:id", userHandler.GetUserDetail)
				users.POST("", userHandler.CreateUser)
				users.PUT("/:id", userHandler.UpdateUser)
				users.DELETE("/:id", userHandler.DeleteUser)
				users.POST("/:id/reset-password", userHandler.ResetPassword)
				users.PUT("/:id/status", userHandler.ToggleUserStatus)
			}

			// 站点管理
			sites := authorized.Group("/sites")
			sites.Use(middleware.RequireOperator()) // 操作员及以上可访问
			{
				sites.GET("", siteHandler.GetList) // 所有角色可查看
				sites.GET("/:id", siteHandler.GetDetail)
				sites.POST("", siteHandler.Create)       // 仅操作员可创建
				sites.PUT("/:id", siteHandler.Update)    // 仅操作员可更新
				sites.DELETE("/:id", siteHandler.Delete) // 仅操作员可删除
				sites.PUT("/:id/status", siteHandler.ToggleStatus)
			}

			// 规则管理
			rules := authorized.Group("/rules")
			rules.Use(middleware.RequireOperator())
			{
				rules.GET("", ruleHandler.GetList)
				rules.GET("/categories", ruleHandler.GetCategories)
				rules.GET("/statistics", ruleHandler.GetStatistics)
				rules.GET("/:id", ruleHandler.GetDetail)
				rules.POST("", ruleHandler.Create)
				rules.PUT("/:id", ruleHandler.Update)
				rules.DELETE("/:id", ruleHandler.Delete)
				rules.PUT("/:id/status", ruleHandler.ToggleStatus)
				rules.POST("/reload", ruleHandler.ReloadRules)
			}

			// 白名单管理
			whitelists := authorized.Group("/whitelists")
			whitelists.Use(middleware.RequireOperator())
			{
				whitelists.GET("", whitelistHandler.GetList)
				whitelists.GET("/:id", whitelistHandler.GetDetail)
				whitelists.POST("", whitelistHandler.Create)
				whitelists.PUT("/:id", whitelistHandler.Update)
				whitelists.DELETE("/:id", whitelistHandler.Delete)
				whitelists.PUT("/:id/status", whitelistHandler.ToggleStatus)
			}

			// IP黑名单管理
			ipBlacklist := authorized.Group("/ip-blacklist")
			ipBlacklist.Use(middleware.RequireOperator())
			{
				ipBlacklist.GET("", ipBlacklistHandler.GetList)
				ipBlacklist.POST("", ipBlacklistHandler.Create)
				ipBlacklist.PUT("/:id", ipBlacklistHandler.Update)
				ipBlacklist.DELETE("/:id", ipBlacklistHandler.Delete)
				ipBlacklist.PUT("/:id/status", ipBlacklistHandler.ToggleStatus)
				ipBlacklist.GET("/auto-config", ipBlacklistHandler.GetAutoBlockConfig)
				ipBlacklist.PUT("/auto-config", ipBlacklistHandler.UpdateAutoBlockConfig)
				ipBlacklist.DELETE("/expired", ipBlacklistHandler.CleanExpired)
				ipBlacklist.GET("/stats", ipBlacklistHandler.GetStats)
			}

			// 日志管理（所有角色可查看，删除仅操作员）
			logs := authorized.Group("/logs")
			logs.Use(middleware.RequireAuditor())
			{
				logs.GET("", logHandler.GetRequestLogList)
				logs.GET("/statistics", logHandler.GetStatistics)
				logs.GET("/daily", logHandler.GetDailyStatistics)
				logs.GET("/trend", logHandler.GetTrend)
				logs.GET("/attack-types", logHandler.GetAttackTypeStatistics)
				logs.GET("/attack-ips", logHandler.GetAttackIPs)
				logs.GET("/attack-geo", logHandler.GetAttackGeo)
				logs.GET("/:id", logHandler.GetRequestLogDetail)
				logs.DELETE("/old", logHandler.DeleteOldLogs) // 仅操作员可删除
			}

			// 操作日志管理（仅管理员可查看和删除）
			operationLogs := authorized.Group("/operation-logs")
			operationLogs.Use(middleware.RequireAdmin())
			{
				operationLogs.GET("", operationLogHandler.GetList)
				operationLogs.GET("/statistics", operationLogHandler.GetStatistics)
				operationLogs.GET("/actions", operationLogHandler.GetActions)
				operationLogs.DELETE("/old", operationLogHandler.DeleteOldLogs)
			}

			// IP白名单管理
			ipWhitelist := authorized.Group("/ip-whitelist")
			ipWhitelist.Use(middleware.RequireOperator())
			{
				ipWhitelist.GET("", ipWhitelistHandler.GetList)
				ipWhitelist.POST("", ipWhitelistHandler.Create)
				ipWhitelist.PUT("/:id", ipWhitelistHandler.Update)
				ipWhitelist.DELETE("/:id", ipWhitelistHandler.Delete)
				ipWhitelist.PUT("/:id/status", ipWhitelistHandler.ToggleStatus)
				ipWhitelist.GET("/stats", ipWhitelistHandler.GetStats)
			}

			// 爬虫检测路由（所有角色可查看）
			crawler := authorized.Group("/crawler")
			crawler.Use(middleware.RequireAuditor())
			{
				crawler.GET("/stats", crawlerHandler.GetStats)
				crawler.GET("/recent", crawlerHandler.GetRecent)
				crawler.GET("/trend", crawlerHandler.GetTrend)
				crawler.GET("/logs", crawlerHandler.GetLogs)
				crawler.GET("/logs/:id", crawlerHandler.GetLogDetail)
				crawler.GET("/top-ips", crawlerHandler.GetTopIPs)
			}

			// CC防护配置（所有角色可查看，操作员可修改）
			ccProtection := authorized.Group("/cc-protection")
			ccProtection.Use(middleware.RequireOperator())
			{
				ccProtection.GET("", ccProtectionHandler.GetConfig)
				ccProtection.PUT("", ccProtectionHandler.UpdateConfig)
			}

			// WAF 管理（状态所有角色可查看，重载仅管理员）
			waf := authorized.Group("/waf")
			waf.Use(middleware.RequireOperator())
			{
				waf.GET("/status", func(c *gin.Context) {
					policy, err := protection.GetConfig()
					if err != nil {
						c.JSON(503, gin.H{"code": 503, "message": "全局防护配置暂不可用"})
						return
					}
					engineMode := config.GetConfig().WAF.EngineMode
					if !policy.Enabled || !policy.RuleEngineEnabled {
						engineMode = "Off"
					} else if policy.WafMode == "monitor" && engineMode != "Off" {
						engineMode = "DetectionOnly"
					}
					onlineCount, _ := userService.GetOnlineUserCount()
					c.JSON(200, gin.H{
						"code":    0,
						"message": "success",
						"data": gin.H{
							"status":       "running",
							"site_count":   len(proxyManager.GetAllSites()),
							"waf_mode":     engineMode,
							"online_users": onlineCount,
							"log_pipeline": events.Stats(),
						},
					})
				})
				waf.GET("/protection", handler.GetProtectionConfig)
				waf.PUT("/protection", handler.UpdateProtectionConfig)
				waf.POST("/reload", func(c *gin.Context) {
					// 仅管理员可重载
					role, _ := c.Get("role")
					if role.(string) != middleware.RoleAdmin {
						middleware.LogFailed(c, model.ActionReloadWAF, model.ResourceWAF, 0, nil, "权限不足")
						c.JSON(403, gin.H{
							"code":    403,
							"message": "仅管理员可执行此操作",
						})
						return
					}
					if err := proxyManager.LoadSites(); err != nil {
						middleware.LogFailed(c, model.ActionReloadWAF, model.ResourceWAF, 0, nil, err.Error())
						c.JSON(500, gin.H{
							"code":    500,
							"message": "重载失败: " + err.Error(),
						})
						return
					}
					middleware.LogSuccess(c, model.ActionReloadWAF, model.ResourceWAF, 0, nil)
					c.JSON(200, gin.H{
						"code":    0,
						"message": "重载成功",
					})
				})
			}
		}
	}
}
