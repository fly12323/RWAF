package handler

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/password"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// UserHandler 用户处理器
type UserHandler struct {
	userService *service.UserService
}

// NewUserHandler 创建用户处理器实例
func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// CreateUser 创建用户
// POST /api/v1/users
func (h *UserHandler) CreateUser(c *gin.Context) {
	var req service.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		middleware.LogFailed(c, model.ActionCreateUser, model.ResourceUser, 0, map[string]interface{}{"username": req.Username}, err.Error())
		return
	}

	user, err := h.userService.CreateUser(&req)
	if err != nil {
		middleware.LogFailed(c, model.ActionCreateUser, model.ResourceUser, 0, map[string]interface{}{"username": req.Username}, err.Error())
		code := 500
		var policyError *password.PolicyError
		if errors.As(err, &policyError) {
			code = 400
		}
		response.Fail(c, code, err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionCreateUser, model.ResourceUser, user.ID, map[string]interface{}{
		"username": user.Username,
		"role":     user.Role,
	})
	response.SuccessWithMsg(c, "创建用户成功", user)
}

// GetUserList 获取用户列表
// GET /api/v1/users
func (h *UserHandler) GetUserList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	keyword := c.Query("keyword")

	users, total, err := h.userService.ListUsers(page, pageSize, keyword)
	if err != nil {
		response.Fail(c, 500, "获取用户列表失败")
		return
	}

	response.Page(c, users, total, page, pageSize)
}

// GetUserDetail 获取用户详情
// GET /api/v1/users/:id
func (h *UserHandler) GetUserDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的用户ID")
		return
	}

	user, err := h.userService.GetUserByID(uint(id))
	if err != nil {
		response.Fail(c, 404, "用户不存在")
		return
	}

	response.Success(c, user)
}

// UpdateUser 更新用户
// PUT /api/v1/users/:id
func (h *UserHandler) UpdateUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的用户ID")
		return
	}

	var req service.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	user, err := h.userService.UpdateUser(uint(id), &req)
	if err != nil {
		response.Fail(c, 500, err.Error())
		return
	}

	middleware.LogSuccess(c, model.ActionUpdateUser, model.ResourceUser, user.ID, map[string]interface{}{
		"username": user.Username,
		"role":     user.Role,
	})
	response.SuccessWithMsg(c, "更新用户成功", user)
}

// DeleteUser 删除用户
// DELETE /api/v1/users/:id
func (h *UserHandler) DeleteUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的用户ID")
		return
	}

	currentID, _ := c.Get("user_id")
	uid := currentID.(uint)

	// 获取要删除的用户信息用于日志
	user, _ := h.userService.GetUserByID(uint(id))

	if err := h.userService.DeleteUser(uint(id), uid); err != nil {
		middleware.LogFailed(c, model.ActionDeleteUser, model.ResourceUser, uint(id), nil, err.Error())
		response.Fail(c, 500, err.Error())
		return
	}

	if user != nil {
		middleware.LogSuccess(c, model.ActionDeleteUser, model.ResourceUser, uint(id), map[string]interface{}{
			"username": user.Username,
		})
	} else {
		middleware.LogSuccess(c, model.ActionDeleteUser, model.ResourceUser, uint(id), nil)
	}
	response.SuccessWithMsg(c, "删除用户成功", nil)
}

// ResetPassword 重置密码
// POST /api/v1/users/:id/reset-password
func (h *UserHandler) ResetPassword(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的用户ID")
		return
	}

	var req service.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	if err := h.userService.ResetPassword(uint(id), &req); err != nil {
		code := 500
		var policyError *password.PolicyError
		if errors.As(err, &policyError) {
			code = 400
		}
		response.Fail(c, code, err.Error())
		return
	}

	response.SuccessWithMsg(c, "密码重置成功", nil)
}

// ToggleUserStatus 切换用户状态
// PUT /api/v1/users/:id/status
func (h *UserHandler) ToggleUserStatus(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的用户ID")
		return
	}

	// 直接读取原始请求体
	body, err := c.GetRawData()
	if err != nil {
		response.Fail(c, 400, "读取请求体失败")
		return
	}

	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		response.Fail(c, 400, "参数错误: "+err.Error())
		return
	}

	statusValue, ok := req["status"]
	if !ok {
		response.Fail(c, 400, "状态值不能为空")
		return
	}

	var status int8
	switch v := statusValue.(type) {
	case float64:
		status = int8(v)
	case int:
		status = int8(v)
	default:
		response.Fail(c, 400, "状态值必须为数字类型")
		return
	}

	// 暂时跳过验证，直接使用状态值
	// if status != 0 && status != 1 {
	// 	response.Fail(c, 400, "状态值必须为0（禁用）或1（启用）")
	// 	return
	// }

	currentID, _ := c.Get("user_id")
	uid := currentID.(uint)

	if err := h.userService.ToggleUserStatus(uint(id), status, uid); err != nil {
		response.Fail(c, 400, err.Error())
		return
	}

	msg := "用户已禁用"
	if status == 1 {
		msg = "用户已启用"
	}
	response.SuccessWithMsg(c, msg, nil)
}
