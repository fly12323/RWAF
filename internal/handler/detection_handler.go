package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/monitor"
	"github.com/fly12323/RWAF/internal/ser/weakpassword"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/password"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func GetWeakPasswordConfig(c *gin.Context) {
	cfg, err := weakpassword.GetConfig()
	if err != nil {
		response.Fail(c, 503, "检测配置暂不可用")
		return
	}
	response.Success(c, cfg)
}
func PreviewWeakPassword(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	var req struct {
		Value string `json:"value"`
	}
	if c.ShouldBindJSON(&req) != nil || len(req.Value) == 0 || len(req.Value) > 256 {
		response.Fail(c, 400, "请输入 1–256 字节的原始弱口令")
		return
	}
	values := map[string]string{}
	for _, format := range password.Formats {
		values[format] = password.Encode(req.Value, format)
	}
	response.Success(c, values)
}
func UpdateWeakPasswordConfig(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4*1024*1024)
	var cfg model.WeakPasswordConfig
	if c.ShouldBindJSON(&cfg) != nil {
		response.Fail(c, 400, "配置格式错误")
		return
	}
	if err := weakpassword.SaveConfig(&cfg); err != nil {
		response.Fail(c, 400, err.Error())
		return
	}
	middleware.LogSuccess(c, "update_weak_password_config", model.ResourceWAF, 0, map[string]any{"scope": "global", "dictionary_entries": len(cfg.Dictionary)})
	response.Success(c, cfg)
}
func GetMonitorStatus(c *gin.Context) { response.Success(c, monitor.Current()) }
func GetMonitorConfig(c *gin.Context) {
	cfg, err := monitor.GetConfig()
	if err != nil {
		response.Fail(c, 503, "监控配置暂不可用")
		return
	}
	response.Success(c, cfg)
}
func UpdateMonitorConfig(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024)
	var cfg model.MonitorConfig
	if c.ShouldBindJSON(&cfg) != nil {
		response.Fail(c, 400, "配置格式错误")
		return
	}
	if err := monitor.SaveConfig(&cfg); err != nil {
		response.Fail(c, 400, err.Error())
		return
	}
	middleware.LogSuccess(c, "update_monitor_config", model.ResourceWAF, 0, map[string]any{"scope": "global"})
	response.Success(c, cfg)
}
func detectionPage(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if page > 100000 {
		page = 100000
	}
	if size < 1 || size > 100 {
		size = 20
	}
	return page, size
}
func GetWeakPasswordEvents(c *gin.Context) {
	page, size := detectionPage(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	db := dao.GetDB().WithContext(ctx).Model(&model.WeakPasswordEvent{})
	if id, err := strconv.ParseUint(c.Query("site_id"), 10, 64); err == nil && id > 0 {
		db = db.Where("site_id = ?", id)
	}
	if kind := c.Query("kind"); kind != "" {
		db = db.Where("kind = ?", kind)
	}
	var total int64
	var list []model.WeakPasswordEvent
	if err := db.Count(&total).Error; err != nil {
		response.Fail(c, 503, "检测事件暂不可用")
		return
	}
	if err := db.Order("id DESC").Limit(size).Offset((page - 1) * size).Find(&list).Error; err != nil {
		response.Fail(c, 503, "检测事件暂不可用")
		return
	}
	response.Success(c, gin.H{"list": list, "total": total, "page": page, "page_size": size, "stats": weakpassword.Stats()})
}
func GetWeakPasswordEventDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		response.Fail(c, 400, "无效事件 ID")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	db := dao.GetDB().WithContext(ctx)
	var event model.WeakPasswordEvent
	if err := db.First(&event, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Fail(c, 404, "检测事件不存在")
		} else {
			response.Fail(c, 503, "检测事件暂不可用")
		}
		return
	}
	var request model.RequestLog
	err = db.Where("request_id = ? AND site_id = ?", event.RequestID, event.SiteID).First(&request).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		response.Success(c, gin.H{"event": event, "request": nil, "request_notice": "关联请求尚未入库或已超出日志保留期"})
		return
	}
	if err != nil {
		response.Fail(c, 503, "关联请求暂不可用")
		return
	}
	detail, err := service.NewLogService().GetRequestLogDetail(request.ID)
	if err != nil {
		response.Fail(c, 503, "关联请求详情暂不可用")
		return
	}
	var site model.Site
	siteName := ""
	if db.Select("id", "name").First(&site, event.SiteID).Error == nil {
		siteName = site.Name
	}
	response.Success(c, gin.H{"event": event, "request": detail, "site_name": siteName})
}

func GetAlerts(c *gin.Context) {
	page, size := detectionPage(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	db := dao.GetDB().WithContext(ctx).Model(&model.Alert{})
	if state := c.Query("status"); state != "" {
		db = db.Where("status = ?", state)
	}
	if source := c.Query("source"); source != "" {
		db = db.Where("source = ?", source)
	}
	var total int64
	var list []model.Alert
	if err := db.Count(&total).Error; err != nil {
		response.Fail(c, 503, "告警存储暂不可用，请查看实时监控")
		return
	}
	if err := db.Order("id DESC").Limit(size).Offset((page - 1) * size).Find(&list).Error; err != nil {
		response.Fail(c, 503, "告警存储暂不可用")
		return
	}
	response.Success(c, gin.H{"list": list, "total": total, "page": page, "page_size": size})
}
func AcknowledgeAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		response.Fail(c, 400, "无效告警 ID")
		return
	}
	result := dao.GetDB().Model(&model.Alert{}).Where("id = ? AND acknowledged_at IS NULL", id).Updates(map[string]any{"acknowledged_at": time.Now(), "acknowledged_by": c.GetString("username")})
	if result.Error != nil {
		response.Fail(c, 503, "确认告警失败")
		return
	}
	if result.RowsAffected == 0 {
		response.Fail(c, 404, "告警不存在或已确认")
		return
	}
	middleware.LogSuccess(c, "acknowledge_alert", model.ResourceWAF, uint(id), nil)
	response.Success(c, nil)
}
func ResolveWeakAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		response.Fail(c, 400, "无效告警 ID")
		return
	}
	result := dao.GetDB().Model(&model.Alert{}).Where("id = ? AND source = ? AND status = ?", id, "weak_password", "open").Updates(map[string]any{"status": "resolved", "resolved_at": time.Now()})
	if result.Error != nil {
		response.Fail(c, 503, "处理告警失败")
		return
	}
	if result.RowsAffected == 0 {
		response.Fail(c, 400, "仅未恢复的弱口令告警可手动处理；运行告警由健康探测自动恢复")
		return
	}
	middleware.LogSuccess(c, "resolve_weak_password_alert", model.ResourceWAF, uint(id), nil)
	response.Success(c, nil)
}
