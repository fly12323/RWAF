package service

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/pkg/jwt"
	"github.com/fly12323/RWAF/pkg/password"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// UserService 用户服务
type UserService struct {
	jwt          *jwt.JWT
	tokenService *TokenService
}

// NewUserService 创建用户服务实例
func NewUserService(jwtInstance *jwt.JWT, tokenSvc *TokenService) *UserService {
	return &UserService{
		jwt:          jwtInstance,
		tokenService: tokenSvc,
	}
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token    string      `json:"token"`
	User     *model.User `json:"user"`
	ExpireAt int64       `json:"expire_at"`
}

// Login 用户登录
func (s *UserService) Login(req *LoginRequest) (*LoginResponse, error) {
	// 1. 查找用户
	var user model.User
	if err := dao.GetDB().Where("username = ?", req.Username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("用户名或密码错误")
		}
		return nil, errors.New("登录失败")
	}

	// 2. 检查用户状态
	if user.Status != model.StatusEnabled {
		return nil, errors.New("账号已被禁用")
	}

	// 3. 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, errors.New("用户名或密码错误")
	}

	// 4. 生成 Token
	if password.ValidateAdmin(req.Password, user.Username) != nil && !user.MustChangePassword {
		if err := dao.GetDB().Model(&user).Update("must_change_password", true).Error; err != nil {
			return nil, errors.New("密码策略检查失败")
		}
		user.MustChangePassword = true
	}
	token, err := s.jwt.GenerateToken(user.ID, user.Username, user.Role, user.MustChangePassword)
	if err != nil {
		return nil, errors.New("生成令牌失败")
	}

	// 5. 获取 Token ID
	tokenID, _ := s.jwt.GetTokenID(token)

	// 6. 保存会话到 Redis
	expireDuration := time.Duration(s.jwt.GetExpireTime()) * time.Hour
	if err := s.tokenService.SaveSession(user.ID, tokenID, expireDuration); err != nil {
		return nil, errors.New("保存会话失败")
	}

	// 7. 更新最后登录时间
	now := time.Now()
	dao.GetDB().Model(&user).Update("last_login", now)

	// 8. 返回响应
	return &LoginResponse{
		Token:    token,
		User:     &user,
		ExpireAt: s.jwt.GetExpireAt(),
	}, nil
}

// Logout 用户登出
func (s *UserService) Logout(userID uint) error {
	return s.tokenService.DeleteSession(userID)
}

// CreateUserRequest 创建用户请求
type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Nickname string `json:"nickname"`
	Role     string `json:"role"`
}

// CreateUser 创建用户
func (s *UserService) CreateUser(req *CreateUserRequest) (*model.User, error) {
	if err := password.ValidateAdmin(req.Password, req.Username); err != nil {
		return nil, err
	}
	// 1. 检查用户名是否已存在
	var count int64
	dao.GetDB().Model(&model.User{}).Where("username = ?", req.Username).Count(&count)
	if count > 0 {
		return nil, errors.New("用户名已存在")
	}

	// 2. 密码加密
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("密码加密失败")
	}

	// 3. 设置默认角色
	if req.Role == "" {
		req.Role = model.RoleOperator
	}

	// 4. 创建用户
	user := &model.User{
		Username: req.Username,
		Password: string(hashedPassword),
		Nickname: req.Nickname,
		Role:     req.Role,
		Status:   model.StatusEnabled,
	}

	if err := dao.GetDB().Create(user).Error; err != nil {
		return nil, errors.New("创建用户失败")
	}

	return user, nil
}

// GetUserByID 根据 ID 获取用户
func (s *UserService) GetUserByID(id uint) (*model.User, error) {
	var user model.User
	if err := dao.GetDB().First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername 根据用户名获取用户
func (s *UserService) GetUserByUsername(username string) (*model.User, error) {
	var user model.User
	if err := dao.GetDB().Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// ListUsers 获取用户列表
func (s *UserService) ListUsers(page, pageSize int, keyword string) ([]model.User, int64, error) {
	var users []model.User
	var total int64

	db := dao.GetDB().Model(&model.User{})

	// 关键词搜索
	if keyword != "" {
		db = db.Where("username LIKE ? OR nickname LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	// 统计总数
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	if err := db.Select("id", "username", "nickname", "role", "status", "last_login", "created_at").
		Offset(offset).Limit(pageSize).Order("id DESC").Find(&users).Error; err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// UpdateUserRequest 更新用户请求
type UpdateUserRequest struct {
	Nickname string `json:"nickname"`
	Role     string `json:"role"`
}

// UpdateUser 更新用户
func (s *UserService) UpdateUser(id uint, req *UpdateUserRequest) (*model.User, error) {
	user, err := s.GetUserByID(id)
	if err != nil {
		return nil, errors.New("用户不存在")
	}

	updates := make(map[string]interface{})
	if req.Nickname != "" {
		updates["nickname"] = req.Nickname
	}
	if req.Role != "" {
		updates["role"] = req.Role
	}

	if len(updates) > 0 {
		if err := dao.GetDB().Model(user).Updates(updates).Error; err != nil {
			return nil, errors.New("更新用户失败")
		}
	}

	return s.GetUserByID(id)
}

// DeleteUser 删除用户
func (s *UserService) DeleteUser(id uint, currentID uint) error {
	// 不能删除自己
	if id == currentID {
		return errors.New("不能删除自己")
	}

	// 检查用户是否存在
	var user model.User
	if err := dao.GetDB().First(&user, id).Error; err != nil {
		return errors.New("用户不存在")
	}

	// 不能删除管理员
	if user.Role == model.RoleAdmin {
		return errors.New("不能删除管理员")
	}

	// 删除用户会话
	s.tokenService.DeleteSession(id)

	return dao.GetDB().Delete(&model.User{}, id).Error
}

// ChangePasswordRequest 修改密码请求
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ChangePassword 修改密码
func (s *UserService) ChangePassword(userID uint, tokenID string, req *ChangePasswordRequest) error {
	// 1. 获取用户
	user, err := s.GetUserByID(userID)
	if err != nil {
		return errors.New("用户不存在")
	}

	// 2. 验证旧密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword)); err != nil {
		return errors.New("旧密码错误")
	}

	// 3. 加密新密码
	if err := password.ValidateAdmin(req.NewPassword, user.Username); err != nil {
		return err
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("密码加密失败")
	}

	// 4. 更新密码
	if err := dao.GetDB().Model(user).Updates(map[string]any{"password": string(hashedPassword), "must_change_password": false}).Error; err != nil {
		return errors.New("密码更新失败")
	}

	// 5. 将当前 Token 加入黑名单
	expireDuration := time.Duration(s.jwt.GetExpireTime()) * time.Hour
	s.tokenService.AddToBlacklist(tokenID, expireDuration)

	// 6. 删除会话，强制重新登录
	s.tokenService.DeleteSession(userID)

	return nil
}

// ResetPasswordRequest 重置密码请求
type ResetPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

// ResetPassword 重置密码（管理员操作）
func (s *UserService) ResetPassword(id uint, req *ResetPasswordRequest) error {
	// 1. 检查用户是否存在
	var user model.User
	if err := dao.GetDB().First(&user, id).Error; err != nil {
		return errors.New("用户不存在")
	}

	// 2. 加密新密码
	if err := password.ValidateAdmin(req.Password, user.Username); err != nil {
		return err
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("密码加密失败")
	}

	// 3. 更新密码
	if err := dao.GetDB().Model(&user).Updates(map[string]any{"password": string(hashedPassword), "must_change_password": false}).Error; err != nil {
		return errors.New("密码更新失败")
	}

	// 4. 踢用户下线
	s.tokenService.DeleteSession(id)

	return nil
}

// ToggleUserStatus 切换用户状态
func (s *UserService) ToggleUserStatus(id uint, status int8, currentID uint) error {
	fmt.Printf("DEBUG Service: Received status value: %d, type: %T\n", status, status)

	// 不能禁用自己
	if id == currentID {
		return errors.New("不能禁用自己")
	}

	// 检查用户是否存在
	var user model.User
	if err := dao.GetDB().First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("用户不存在")
		}
		return errors.New("查询用户信息失败")
	}

	fmt.Printf("DEBUG Service: User current status: %d\n", user.Status)

	// 不能禁用管理员
	if user.Role == model.RoleAdmin {
		return errors.New("不能禁用管理员账户")
	}

	// 如果状态没有变化，直接返回成功
	if user.Status == status {
		return nil
	}

	// 开始事务
	tx := dao.GetDB().Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 如果是禁用，踢用户下线
	if status == 0 {
		if err := s.tokenService.DeleteSession(id); err != nil {
			tx.Rollback()
			return errors.New("清理用户会话失败")
		}
	}

	// 更新用户状态
	if err := tx.Model(&user).Update("status", status).Error; err != nil {
		tx.Rollback()
		return errors.New("更新用户状态失败")
	}

	// 提交事务
	return tx.Commit().Error
}

// InitAdminUser 初始化管理员用户
func (s *UserService) InitAdminUser() error {
	// 检查是否已存在管理员
	var count int64
	dao.GetDB().Model(&model.User{}).Where("role = ?", model.RoleAdmin).Count(&count)
	if count > 0 {
		return nil // 已存在管理员，跳过
	}

	// A fresh installation must supply a strong bootstrap password explicitly.
	initialPassword := os.Getenv("ADMIN_PASSWORD")
	if initialPassword == "" {
		return errors.New("首次启动请设置 ADMIN_PASSWORD，至少 12 个字符，不能使用弱口令")
	}
	if err := password.ValidateAdmin(initialPassword, "admin"); err != nil {
		return fmt.Errorf("ADMIN_PASSWORD 无效: %w", err)
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(initialPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	admin := &model.User{
		Username: "admin",
		Password: string(hashedPassword),
		Nickname: "管理员",
		Role:     model.RoleAdmin,
		Status:   model.StatusEnabled,
	}

	return dao.GetDB().Create(admin).Error
}

// KickUser 踢用户下线
func (s *UserService) KickUser(userID uint) error {
	return s.tokenService.KickUser(userID)
}

// GetOnlineUserCount 获取在线用户数量
func (s *UserService) GetOnlineUserCount() (int64, error) {
	return s.tokenService.GetOnlineUserCount()
}
