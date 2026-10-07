package handler

import (
	"encoding/json"
	"strconv"

	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/pkg/response"

	"github.com/gin-gonic/gin"
)

// CrawlerHandler 爬虫检测处理器
type CrawlerHandler struct{}

// NewCrawlerHandler 创建爬虫检测处理器
func NewCrawlerHandler() *CrawlerHandler {
	return &CrawlerHandler{}
}

// GetStats 获取统计信息
// GET /api/v1/crawler/stats
func (h *CrawlerHandler) GetStats(c *gin.Context) {
	var totalRequests int64
	var botCount int64
	var scannerCount int64
	var crawlerCount int64

	dao.GetDB().Model(&model.CrawlerLog{}).Count(&totalRequests)
	dao.GetDB().Model(&model.CrawlerLog{}).Where("crawler_type = ?", "bot").Count(&botCount)
	dao.GetDB().Model(&model.CrawlerLog{}).Where("crawler_type = ?", "scanner").Count(&scannerCount)
	dao.GetDB().Model(&model.CrawlerLog{}).Where("crawler_type = ?", "crawler").Count(&crawlerCount)

	botRate := float64(0)
	scannerRate := float64(0)
	if totalRequests > 0 {
		botRate = float64(botCount) / float64(totalRequests)
		scannerRate = float64(scannerCount) / float64(totalRequests)
	}

	response.Success(c, gin.H{
		"total_requests": totalRequests,
		"bot_count":      botCount,
		"scanner_count":  scannerCount,
		"crawler_count":  crawlerCount,
		"bot_rate":       botRate,
		"scanner_rate":   scannerRate,
	})
}

// GetRecent 获取最近的爬虫检测记录
// GET /api/v1/crawler/recent
func (h *CrawlerHandler) GetRecent(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))

	var logs []model.CrawlerLog
	dao.GetDB().Order("created_at DESC").Limit(limit).Find(&logs)

	result := make([]map[string]interface{}, len(logs))
	for i, log := range logs {
		var detectionRules []string
		if log.DetectionRules != "" {
			json.Unmarshal([]byte(log.DetectionRules), &detectionRules)
		}

		result[i] = map[string]interface{}{
			"id":              log.ID,
			"request_id":      log.RequestID,
			"site_id":         log.SiteID,
			"client_ip":       log.ClientIP,
			"user_agent":      log.UserAgent,
			"method":          log.Method,
			"uri":             log.URI,
			"crawler_type":    log.CrawlerType,
			"crawler_name":    log.CrawlerName,
			"confidence":      log.Confidence,
			"detection_rules": detectionRules,
			"action":          log.Action,
			"created_at":      log.CreatedAt,
		}
	}

	response.Success(c, result)
}

// GetTrend 获取趋势数据
// GET /api/v1/crawler/trend
func (h *CrawlerHandler) GetTrend(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))

	type TrendResult struct {
		Hour         string
		Count        int64
		BotCount     int64
		ScannerCount int64
		CrawlerCount int64
	}

	var results []TrendResult

	query := `
		SELECT 
			to_char(created_at, 'YYYY-MM-DD HH24:00:00') as hour,
			COUNT(*) as count,
			SUM(CASE WHEN crawler_type = 'bot' THEN 1 ELSE 0 END) as bot_count,
			SUM(CASE WHEN crawler_type = 'scanner' THEN 1 ELSE 0 END) as scanner_count,
			SUM(CASE WHEN crawler_type = 'crawler' THEN 1 ELSE 0 END) as crawler_count
		FROM crawler_logs
		WHERE created_at > NOW() - (? * INTERVAL '1 hour')
		GROUP BY hour
		ORDER BY hour
	`

	dao.GetDB().Raw(query, hours).Scan(&results)

	trend := make([]map[string]interface{}, len(results))
	for i, r := range results {
		trend[i] = map[string]interface{}{
			"hour":          r.Hour,
			"count":         r.Count,
			"bot_count":     r.BotCount,
			"scanner_count": r.ScannerCount,
			"crawler_count": r.CrawlerCount,
		}
	}

	response.Success(c, trend)
}

// GetLogs 获取爬虫检测日志列表
// GET /api/v1/crawler/logs
func (h *CrawlerHandler) GetLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	crawlerType := c.Query("type")
	minConfidence := c.Query("min_confidence")

	var logs []model.CrawlerLog
	var total int64

	db := dao.GetDB().Model(&model.CrawlerLog{})

	if crawlerType != "" {
		db = db.Where("crawler_type = ?", crawlerType)
	}

	if minConfidence != "" {
		minConf, err := strconv.ParseFloat(minConfidence, 64)
		if err == nil {
			db = db.Where("confidence >= ?", minConf)
		}
	}

	db.Count(&total)

	offset := (page - 1) * pageSize
	if err := db.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		response.Fail(c, 500, "获取数据失败")
		return
	}

	result := make([]map[string]interface{}, len(logs))
	for i, log := range logs {
		var detectionRules []string
		if log.DetectionRules != "" {
			json.Unmarshal([]byte(log.DetectionRules), &detectionRules)
		}

		result[i] = map[string]interface{}{
			"id":              log.ID,
			"request_id":      log.RequestID,
			"site_id":         log.SiteID,
			"client_ip":       log.ClientIP,
			"user_agent":      log.UserAgent,
			"method":          log.Method,
			"uri":             log.URI,
			"crawler_type":    log.CrawlerType,
			"crawler_name":    log.CrawlerName,
			"confidence":      log.Confidence,
			"detection_rules": detectionRules,
			"action":          log.Action,
			"created_at":      log.CreatedAt,
		}
	}

	response.Page(c, result, total, page, pageSize)
}

// GetLogDetail 获取爬虫检测日志详情
// GET /api/v1/crawler/logs/:id
func (h *CrawlerHandler) GetLogDetail(c *gin.Context) {
	id := c.Param("id")

	var log model.CrawlerLog
	if err := dao.GetDB().First(&log, id).Error; err != nil {
		response.Fail(c, 404, "记录不存在")
		return
	}

	var detectionRules []string
	if log.DetectionRules != "" {
		json.Unmarshal([]byte(log.DetectionRules), &detectionRules)
	}

	result := map[string]interface{}{
		"id":              log.ID,
		"request_id":      log.RequestID,
		"site_id":         log.SiteID,
		"client_ip":       log.ClientIP,
		"user_agent":      log.UserAgent,
		"method":          log.Method,
		"uri":             log.URI,
		"crawler_type":    log.CrawlerType,
		"crawler_name":    log.CrawlerName,
		"confidence":      log.Confidence,
		"detection_rules": detectionRules,
		"action":          log.Action,
		"created_at":      log.CreatedAt,
	}

	response.Success(c, result)
}

// GetTopIPs 获取Top攻击IP
// GET /api/v1/crawler/top-ips
func (h *CrawlerHandler) GetTopIPs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	type TopIPResult struct {
		ClientIP     string
		Count        int64
		BotCount     int64
		ScannerCount int64
	}

	var results []TopIPResult

	query := `
		SELECT 
			client_ip,
			COUNT(*) as count,
			SUM(CASE WHEN crawler_type = 'bot' THEN 1 ELSE 0 END) as bot_count,
			SUM(CASE WHEN crawler_type = 'scanner' THEN 1 ELSE 0 END) as scanner_count
		FROM crawler_logs
		WHERE crawler_type IN ('bot', 'scanner')
		GROUP BY client_ip
		ORDER BY count DESC
		LIMIT ?
	`

	dao.GetDB().Raw(query, limit).Scan(&results)

	topIPs := make([]map[string]interface{}, len(results))
	for i, r := range results {
		topIPs[i] = map[string]interface{}{
			"client_ip":     r.ClientIP,
			"count":         r.Count,
			"bot_count":     r.BotCount,
			"scanner_count": r.ScannerCount,
		}
	}

	response.Success(c, topIPs)
}
