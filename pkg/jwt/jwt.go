package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrTokenExpired     = errors.New("令牌已过期")
	ErrTokenInvalid     = errors.New("令牌无效")
	ErrTokenMalformed   = errors.New("令牌格式错误")
	ErrTokenNotValidYet = errors.New("令牌尚未生效")
)

// JWTConfig JWT 配置
type JWTConfig struct {
	Secret     string
	ExpireTime int
	Issuer     string
}

// JWT JWT 工具结构体
type JWT struct {
	config JWTConfig
}

// NewJWT 创建 JWT 实例
func NewJWT(config JWTConfig) *JWT {
	return &JWT{config: config}
}

// CustomClaims 自定义 Claims
type CustomClaims struct {
	UserID             uint   `json:"user_id"`
	Username           string `json:"username"`
	Role               string `json:"role"`
	MustChangePassword bool   `json:"must_change_password,omitempty"`
	jwt.RegisteredClaims
}

// GenerateToken 生成 Token
func (j *JWT) GenerateToken(userID uint, username, role string, mustChange ...bool) (string, error) {
	claims := CustomClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    j.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(j.config.ExpireTime) * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	if len(mustChange) > 0 {
		claims.MustChangePassword = mustChange[0]
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.config.Secret))
}

// ParseToken 解析 Token
func (j *JWT) ParseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.config.Secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, ErrTokenMalformed
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotValidYet
		}
		return nil, ErrTokenInvalid
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrTokenInvalid
}

// RefreshToken 刷新 Token
func (j *JWT) RefreshToken(tokenString string) (string, error) {
	claims, err := j.ParseToken(tokenString)
	if err != nil {
		return "", err
	}
	return j.GenerateToken(claims.UserID, claims.Username, claims.Role, claims.MustChangePassword)
}

// GetTokenID 从 Token 中获取 ID
func (j *JWT) GetTokenID(tokenString string) (string, error) {
	claims, err := j.ParseToken(tokenString)
	if err != nil {
		return "", err
	}
	return claims.ID, nil
}

// GetExpireTime 获取过期时间（小时）
func (j *JWT) GetExpireTime() int {
	return j.config.ExpireTime
}

// GetExpireAt 获取过期时间戳
func (j *JWT) GetExpireAt() int64 {
	return time.Now().Add(time.Duration(j.config.ExpireTime) * time.Hour).Unix()
}
