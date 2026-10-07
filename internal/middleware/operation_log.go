package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/service"
)

// OperationLogger 操作日志记录器
var operationLogger = service.NewOperationLogService()

// LogOperation 记录操作日志
// 在 handler 中调用此函数来记录操作
func LogOperation(c *gin.Context, action, resource string, resourceID uint, details map[string]interface{}, result, errorMsg string) {
	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")

	var uid uint
	var name string
	if userID != nil {
		uid = userID.(uint)
	}
	if username != nil {
		name = username.(string)
	}

	item := &service.OperationLogItem{
		UserID:     uid,
		Username:   name,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
		IP:         c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
		Result:     result,
		ErrorMsg:   errorMsg,
	}

	// 异步记录，不阻塞主流程
	go operationLogger.Log(item)
}

// LogSuccess 记录成功操作
func LogSuccess(c *gin.Context, action, resource string, resourceID uint, details map[string]interface{}) {
	LogOperation(c, action, resource, resourceID, details, model.ResultSuccess, "")
}

// LogFailed 记录失败操作
func LogFailed(c *gin.Context, action, resource string, resourceID uint, details map[string]interface{}, errMsg string) {
	LogOperation(c, action, resource, resourceID, details, model.ResultFailed, errMsg)
}
