package middleware

import (
	"strings"

	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/jwt"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// 角色常量
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleAuditor  = "auditor"
)

// JWTAuthMiddleware JWT 认证中间件
func JWTAuthMiddleware(jwtInstance *jwt.JWT, tokenService *service.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 获取 Authorization Header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.Fail(c, 401, "未登录")
			c.Abort()
			return
		}

		// 2. 解析 Bearer Token
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			response.Fail(c, 401, "Token 格式错误")
			c.Abort()
			return
		}

		tokenString := parts[1]

		// 3. 解析 Token
		claims, err := jwtInstance.ParseToken(tokenString)
		if err != nil {
			response.Fail(c, 401, err.Error())
			c.Abort()
			return
		}

		// 4. 检查 Token 是否在黑名单中
		inBlacklist, _ := tokenService.IsInBlacklist(claims.ID)
		if inBlacklist {
			response.Fail(c, 401, "Token 已失效，请重新登录")
			c.Abort()
			return
		}

		// 5. 验证会话（单设备登录）
		valid, err := tokenService.ValidateSession(claims.UserID, claims.ID)
		if err != nil || !valid {
			response.Fail(c, 401, "登录已过期或已在其他设备登录")
			c.Abort()
			return
		}

		// 6. 将用户信息存入上下文
		if claims.MustChangePassword && c.Request.URL.Path != "/api/v1/auth/info" && c.Request.URL.Path != "/api/v1/auth/password" && c.Request.URL.Path != "/api/v1/auth/logout" {
			response.Fail(c, 403, "当前密码不符合要求，请先修改密码")
			c.Abort()
			return
		}
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Set("token_id", claims.ID)

		c.Next()
	}
}

// RequireRoles 角色权限中间件
func RequireRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("role")
		if !exists {
			response.Fail(c, 403, "无法获取角色信息")
			c.Abort()
			return
		}

		roleStr := userRole.(string)
		for _, role := range roles {
			if role == roleStr {
				c.Next()
				return
			}
		}

		response.Fail(c, 403, "权限不足")
		c.Abort()
	}
}

// RequireAdmin 管理员权限中间件
func RequireAdmin() gin.HandlerFunc {
	return RequireRoles(RoleAdmin)
}

// RequireOperator 操作员权限中间件（站点、规则、白名单、黑名单、CC防护等配置操作）
func RequireOperator() gin.HandlerFunc {
	return RequireRoles(RoleAdmin, RoleOperator)
}

// RequireAuditor 审计员权限中间件（仅可查看，不能操作）
func RequireAuditor() gin.HandlerFunc {
	return RequireRoles(RoleAdmin, RoleOperator, RoleAuditor)
}

// RequireWrite 操作员及以上才能进行写操作（POST/PUT/DELETE）
func RequireWrite() gin.HandlerFunc {
	return RequireRoles(RoleAdmin, RoleOperator)
}
