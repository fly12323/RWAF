package handler

import (
	"time"

	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/jwt"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// AuthHandler 认证处理器
type AuthHandler struct {
	userService *service.UserService
	jwt         *jwt.JWT
}

// NewAuthHandler 创建认证处理器实例
func NewAuthHandler(userService *service.UserService, jwtInstance *jwt.JWT) *AuthHandler {
	return &AuthHandler{
		userService: userService,
		jwt:         jwtInstance,
	}
}

// Login 用户登录
// POST /api/v1/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req service.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	resp, err := h.userService.Login(&req)
	if err != nil {
		middleware.LogFailed(c, model.ActionLogin, model.ResourceAuth, 0, map[string]interface{}{
			"username": req.Username,
		}, err.Error())
		response.Fail(c, 401, err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionLogin, model.ResourceAuth, 0, map[string]interface{}{
		"username": req.Username,
	})
	response.Success(c, resp)
}

// GetUserInfo 获取当前用户信息
// GET /api/v1/auth/info
func (h *AuthHandler) GetUserInfo(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		response.Fail(c, 401, "未登录")
		return
	}

	uid := userID.(uint)
	user, err := h.userService.GetUserByID(uid)
	if err != nil {
		response.Fail(c, 404, "用户不存在")
		return
	}

	response.Success(c, user)
}

// Logout 用户登出
// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		response.Fail(c, 401, "未登录")
		return
	}

	uid := userID.(uint)
	username, _ := c.Get("username")
	name, _ := username.(string)

	if err := h.userService.Logout(uid); err != nil {
		middleware.LogFailed(c, model.ActionLogout, model.ResourceAuth, 0, map[string]interface{}{
			"username": name,
		}, err.Error())
		response.Fail(c, 500, "登出失败")
		return
	}

	middleware.LogSuccess(c, model.ActionLogout, model.ResourceAuth, 0, map[string]interface{}{
		"username": name,
	})
	response.SuccessWithMsg(c, "登出成功", nil)
}

// ChangePassword 修改密码
// POST /api/v1/auth/password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req service.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	userID, _ := c.Get("user_id")
	tokenID, _ := c.Get("token_id")
	uid := userID.(uint)
	tid := tokenID.(string)

	if err := h.userService.ChangePassword(uid, tid, &req); err != nil {
		response.Fail(c, 400, err.Error())
		return
	}

	response.SuccessWithMsg(c, "密码修改成功，请重新登录", nil)
}

// RefreshToken 刷新 Token
// POST /api/v1/auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		response.Fail(c, 401, "未登录")
		return
	}

	tokenString := authHeader[7:]
	newToken, err := h.jwt.RefreshToken(tokenString)
	if err != nil {
		response.Fail(c, 401, "刷新令牌失败")
		return
	}

	response.Success(c, gin.H{
		"token":     newToken,
		"expire_at": time.Now().Add(24 * time.Hour).Unix(),
	})
}
