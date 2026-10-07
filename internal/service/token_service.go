package service

import (
	"context"
	"fmt"
	"time"

	"github.com/fly12323/RWAF/internal/dao"
)

// TokenService Token 管理服务
type TokenService struct{}

// NewTokenService 创建 Token 服务实例
func NewTokenService() *TokenService {
	return &TokenService{}
}

// 会话 Key 前缀
const (
	SessionKeyPrefix = "user_session:"
	BlacklistPrefix  = "token_blacklist:"
)

// SaveSession 保存用户会话（单设备登录）
func (s *TokenService) SaveSession(userID uint, tokenID string, expireTime time.Duration) error {
	ctx := context.Background()
	key := fmt.Sprintf("%s%d", SessionKeyPrefix, userID)
	return dao.RDB.Set(ctx, key, tokenID, expireTime).Err()
}

// GetSession 获取用户会话
func (s *TokenService) GetSession(userID uint) (string, error) {
	ctx := context.Background()
	key := fmt.Sprintf("%s%d", SessionKeyPrefix, userID)
	return dao.RDB.Get(ctx, key).Result()
}

// DeleteSession 删除用户会话（登出）
func (s *TokenService) DeleteSession(userID uint) error {
	ctx := context.Background()
	key := fmt.Sprintf("%s%d", SessionKeyPrefix, userID)
	return dao.RDB.Del(ctx, key).Err()
}

// ValidateSession 验证会话是否有效
func (s *TokenService) ValidateSession(userID uint, tokenID string) (bool, error) {
	storedTokenID, err := s.GetSession(userID)
	if err != nil {
		return false, err
	}
	return storedTokenID == tokenID, nil
}

// AddToBlacklist 将 Token 加入黑名单
func (s *TokenService) AddToBlacklist(tokenID string, expireTime time.Duration) error {
	ctx := context.Background()
	key := fmt.Sprintf("%s%s", BlacklistPrefix, tokenID)
	return dao.RDB.Set(ctx, key, "1", expireTime).Err()
}

// IsInBlacklist 检查 Token 是否在黑名单中
func (s *TokenService) IsInBlacklist(tokenID string) (bool, error) {
	ctx := context.Background()
	key := fmt.Sprintf("%s%s", BlacklistPrefix, tokenID)
	result, err := dao.RDB.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

// GetOnlineUserCount 获取在线用户数量
func (s *TokenService) GetOnlineUserCount() (int64, error) {
	ctx := context.Background()
	pattern := fmt.Sprintf("%s*", SessionKeyPrefix)
	keys, err := dao.RDB.Keys(ctx, pattern).Result()
	if err != nil {
		return 0, err
	}
	return int64(len(keys)), nil
}

// KickUser 踢用户下线
func (s *TokenService) KickUser(userID uint) error {
	return s.DeleteSession(userID)
}
