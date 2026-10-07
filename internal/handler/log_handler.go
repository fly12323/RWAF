package handler

import (
	"context"
	"strconv"
	"time"

	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// LogHandler 日志处理器
type LogHandler struct {
	logService *service.LogService
	geoService *service.GeoIPService
}

// NewLogHandler 创建日志处理器实例
func NewLogHandler() *LogHandler {
	return &LogHandler{
		logService: service.NewLogService(),
		geoService: service.NewGeoIPService(),
	}
}

// parseTimeRange 解析时间范围参数
func parseTimeRange(c *gin.Context) (*time.Time, *time.Time) {
	var startTime, endTime *time.Time

	// 支持多种时间格式
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}

	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		for _, format := range formats {
			t, err := time.ParseInLocation(format, startTimeStr, time.Local)
			if err == nil {
				startTime = &t
				break
			}
		}
	}

	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		for _, format := range formats {
			t, err := time.ParseInLocation(format, endTimeStr, time.Local)
			if err == nil {
				endTime = &t
				break
			}
		}
	}

	return startTime, endTime
}

// GetRequestLogList 获取请求日志列表
// GET /api/v1/logs
func (h *LogHandler) GetRequestLogList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	action := c.Query("action")
	attackType := c.Query("attack_type")
	siteIDStr := c.Query("site_id")
	clientIP := c.Query("client_ip")
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	var siteID uint
	if siteIDStr != "" {
		id, err := strconv.ParseUint(siteIDStr, 10, 64)
		if err == nil {
			siteID = uint(id)
		}
	}

	logs, total, err := h.logService.GetRequestLogList(page, pageSize, action, attackType, siteID, clientIP, startTime, endTime)
	if err != nil {
		response.Fail(c, 500, "获取日志列表失败: "+err.Error())
		return
	}

	response.Page(c, logs, total, page, pageSize)
}

// GetRequestLogDetail 获取请求日志详情
// GET /api/v1/logs/:id
func (h *LogHandler) GetRequestLogDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, 400, "无效的日志ID")
		return
	}

	detail, err := h.logService.GetRequestLogDetail(uint(id))
	if err != nil {
		response.Fail(c, 404, "日志不存在")
		return
	}

	response.Success(c, detail)
}

// GetStatistics 获取日志统计
// GET /api/v1/logs/statistics
func (h *LogHandler) GetStatistics(c *gin.Context) {
	startTime, endTime := parseTimeRange(c)

	stats, err := h.logService.GetStatistics(startTime, endTime)
	if err != nil {
		response.Fail(c, 500, "获取统计失败: "+err.Error())
		return
	}

	response.Success(c, stats)
}

// GetDailyStatistics 获取每日统计
// GET /api/v1/logs/daily
func (h *LogHandler) GetDailyStatistics(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	if days > 30 {
		days = 30
	}

	stats, err := h.logService.GetDailyStatistics(days)
	if err != nil {
		response.Fail(c, 500, "获取每日统计失败: "+err.Error())
		return
	}

	response.Success(c, stats)
}

// GetTrend 获取请求趋势
// GET /api/v1/logs/trend
func (h *LogHandler) GetTrend(c *gin.Context) {
	startTime, endTime := parseTimeRange(c)

	// 如果没有时间参数，使用 hours 参数
	if startTime == nil {
		hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
		if hours > 168 {
			hours = 168
		}
		trend, err := h.logService.GetAttackTrend(hours)
		if err != nil {
			response.Fail(c, 500, "获取趋势失败: "+err.Error())
			return
		}
		response.Success(c, trend)
		return
	}

	trend, err := h.logService.GetTrend(startTime, endTime)
	if err != nil {
		response.Fail(c, 500, "获取趋势失败: "+err.Error())
		return
	}

	response.Success(c, trend)
}

// GetAttackTrend 获取攻击趋势（兼容旧接口）
// GET /api/v1/logs/attack-trend
func (h *LogHandler) GetAttackTrend(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours > 168 {
		hours = 168
	}

	trend, err := h.logService.GetAttackTrend(hours)
	if err != nil {
		response.Fail(c, 500, "获取攻击趋势失败: "+err.Error())
		return
	}

	response.Success(c, trend)
}

// GetAttackTypeStatistics 获取攻击类型统计
// GET /api/v1/logs/attack-types
func (h *LogHandler) GetAttackTypeStatistics(c *gin.Context) {
	startTime, endTime := parseTimeRange(c)

	stats, err := h.logService.GetAttackTypeStatistics(startTime, endTime)
	if err != nil {
		response.Fail(c, 500, "获取统计失败: "+err.Error())
		return
	}

	response.Success(c, stats)
}

// GetAttackIPs 获取攻击IP分析
// GET /api/v1/logs/attack-ips
func (h *LogHandler) GetAttackIPs(c *gin.Context) {
	startTime, endTime := parseTimeRange(c)

	ips, err := h.logService.GetAttackIPs(startTime, endTime)
	if err != nil {
		response.Fail(c, 500, "获取攻击IP失败: "+err.Error())
		return
	}

	response.Success(c, ips)
}

func (h *LogHandler) GetAttackGeo(c *gin.Context) {
	startTime, endTime := parseTimeRange(c)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	ips, err := h.logService.GetAttackIPsWithLimit(startTime, endTime, limit)
	if err != nil {
		response.Fail(c, 500, "获取攻击IP失败: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
	defer cancel()

	type item struct {
		service.AttackIPInfo
		Country string   `json:"country"`
		Region  string   `json:"region"`
		City    string   `json:"city"`
		Lat     *float64 `json:"lat"`
		Lon     *float64 `json:"lon"`
	}

	out := make([]item, 0, len(ips))
	for _, ip := range ips {
		geo, e := h.geoService.Lookup(ctx, ip.ClientIP)
		if e != nil || geo.Lat == nil || geo.Lon == nil {
			continue
		}
		out = append(out, item{
			AttackIPInfo: ip,
			Country:      geo.Country,
			Region:       geo.Region,
			City:         geo.City,
			Lat:          geo.Lat,
			Lon:          geo.Lon,
		})
	}

	response.Success(c, out)
}

// DeleteOldLogs 删除旧日志
// DELETE /api/v1/logs/old
func (h *LogHandler) DeleteOldLogs(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days < 7 {
		days = 7
	}

	deletedCount, err := h.logService.DeleteOldLogs(days)
	if err != nil {
		response.Fail(c, 500, "删除日志失败: "+err.Error())
		return
	}

	response.Success(c, gin.H{
		"deleted_count": deletedCount,
	})
}
