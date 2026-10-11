package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/response"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func GetQuarantinedEvents(c *gin.Context) {
	page, size := detectionPage(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	db := dao.GetDB().WithContext(ctx).Model(&model.QuarantinedEvent{})
	if status := c.Query("status"); status != "" {
		if status != "pending" && status != "replayed" {
			response.Fail(c, 400, "无效隔离状态")
			return
		}
		db = db.Where("status = ?", status)
	}
	var total int64
	var list []model.QuarantinedEvent
	if err := db.Count(&total).Error; err != nil {
		response.Fail(c, 503, "隔离记录暂不可用")
		return
	}
	// List responses never load potentially large raw message bytes.
	if err := db.Omit("payload", "message_key", "headers", "replay_payload").Order("id DESC").Limit(size).Offset((page - 1) * size).Find(&list).Error; err != nil {
		response.Fail(c, 503, "隔离记录暂不可用")
		return
	}
	response.Success(c, gin.H{"list": list, "total": total, "page": page, "page_size": size})
}

func GetQuarantinedEvent(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		response.Fail(c, 400, "无效隔离记录 ID")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	var q model.QuarantinedEvent
	if err := dao.GetDB().WithContext(ctx).First(&q, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Fail(c, 404, "隔离记录不存在")
		} else {
			response.Fail(c, 503, "隔离记录暂不可用")
		}
		return
	}
	response.Success(c, q)
}

func ReplayQuarantinedEvent(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		response.Fail(c, 400, "无效隔离记录 ID")
		return
	}
	limit := config.GetConfig().Kafka.MaxEventBytes
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, int64(limit)*6+4096)
	var request struct {
		Event  json.RawMessage `json:"event"`
		Reason string          `json:"reason"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, 400, "重放请求格式错误或超过大小限制")
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Reason == "" || len(request.Reason) > 500 {
		response.Fail(c, 400, "请填写不超过 500 字节的重放原因")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	audit := model.OperationLog{UserID: c.GetUint("user_id"), Username: c.GetString("username"), IP: c.ClientIP(), UserAgent: c.GetHeader("User-Agent")}
	q, err := events.ReplayQuarantinedEvent(ctx, dao.GetDB(), uint(id), request.Event, request.Reason, limit, audit)
	if err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			response.Fail(c, 404, "隔离记录不存在")
		case errors.Is(err, events.ErrAlreadyReplayed):
			response.Fail(c, 409, "该记录已重放，请刷新列表")
		case errors.Is(err, events.ErrInvalidReplay):
			response.Fail(c, 400, "事件仍不合法："+err.Error())
		default:
			response.Fail(c, 503, "重放未完成，原记录保留，可稍后重试")
		}
		return
	}
	q.Payload, q.ReplayPayload, q.MessageKey = nil, nil, nil
	q.Headers = ""
	response.Success(c, q)
}
