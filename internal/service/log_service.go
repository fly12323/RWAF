package service

import (
	"fmt"
	"github.com/fly12323/RWAF/internal/config"
	"gorm.io/gorm"
	"time"

	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
)

// LogService 日志服务
type LogService struct{}

// NewLogService 创建日志服务实例
func NewLogService() *LogService {
	return &LogService{}
}

// StatisticsResponse 统计响应
type StatisticsResponse struct {
	Total        int64             `json:"total"`
	ByAction     []ActionCount     `json:"by_action"`
	BySite       []SiteCount       `json:"by_site"`
	ByAttackType []AttackTypeCount `json:"by_attack_type"`
	AvgScore     float64           `json:"avg_score"`
	AvgDuration  float64           `json:"avg_duration"`
	TopAttackIPs []IPCount         `json:"top_attack_ips"`
	TopRules     []RuleCount       `json:"top_rules"`
}

// ActionCount 动作统计
type ActionCount struct {
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

// SiteCount 站点统计
type SiteCount struct {
	SiteID uint  `json:"site_id"`
	Count  int64 `json:"count"`
}

// AttackTypeCount 攻击类型统计
type AttackTypeCount struct {
	AttackType string `json:"attack_type"`
	Count      int64  `json:"count"`
}

// IPCount IP统计
type IPCount struct {
	ClientIP string `json:"client_ip"`
	Count    int64  `json:"count"`
}

// RuleCount 规则统计
type RuleCount struct {
	RuleID string `json:"rule_id"`
	Count  int64  `json:"count"`
}

// AttackIPInfo 攻击IP信息
type AttackIPInfo struct {
	ClientIP    string `json:"client_ip"`
	AttackCount int64  `json:"attack_count"`
	AttackTypes string `json:"attack_types"`
	FirstAttack string `json:"first_attack"`
	LastAttack  string `json:"last_attack"`
}

// TrendStatistics 趋势统计
type TrendStatistics struct {
	Hour       string `json:"hour"`
	Total      int64  `json:"total"`
	BlockCount int64  `json:"block_count"`
}

// formatTimeToString 将 time.Time 格式化为字符串
func formatTimeToString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

// GetAttackTypeByRuleID 根据规则ID判断攻击类型
func GetAttackTypeByRuleID(ruleID string) string {
	if len(ruleID) < 3 {
		return "Unknown"
	}
	prefix := ruleID[:3]
	switch prefix {
	case "942":
		return "SQL Injection"
	case "941":
		return "XSS"
	case "930":
		return "LFI"
	case "931":
		return "RFI"
	case "932":
		return "RCE"
	case "933":
		return "PHP Injection"
	case "934":
		return "Node.js Injection"
	case "921":
		return "Protocol Attack"
	case "920":
		return "Protocol Issue"
	case "943":
		return "Session Fixation"
	case "944":
		return "Java Attack"
	default:
		return "Unknown"
	}
}

// GetMainAttackType 获取主要攻击类型（触发次数最多的）
func GetMainAttackType(logID uint) string {
	var matches []model.RuleMatch
	dao.GetDB().Where("request_log_id = ?", logID).Find(&matches)

	if len(matches) == 0 {
		return ""
	}

	// 统计每种攻击类型的次数
	attackTypeCount := make(map[string]int)
	for _, m := range matches {
		attackType := GetAttackTypeByRuleID(m.RuleID)
		// 排除 Protocol Issue
		if attackType != "Protocol Issue" {
			attackTypeCount[attackType]++
		}
	}

	// 找出次数最多的
	var maxCount int
	var mainType string
	for attackType, count := range attackTypeCount {
		if count > maxCount {
			maxCount = count
			mainType = attackType
		}
	}

	return mainType
}

// GetStatistics 获取日志统计
func (s *LogService) GetStatistics(startTime, endTime *time.Time) (*StatisticsResponse, error) {
	key := fmt.Sprintf("statistics:%s:%s", logRangeKey(startTime), logRangeKey(endTime))
	return cachedLogQuery(key, func() (*StatisticsResponse, error) {
		result := &StatisticsResponse{ByAction: []ActionCount{}, BySite: []SiteCount{}, ByAttackType: []AttackTypeCount{}, TopAttackIPs: []IPCount{}, TopRules: []RuleCount{}}
		// GROUPING SETS calculates totals, averages and all three breakdowns in one scan.
		var rows []struct {
			Action      *string
			SiteID      *uint
			AttackType  *string
			Grouping    int
			Count       int64
			AvgScore    float64
			AvgDuration float64
		}
		query := `SELECT action, site_id, attack_type, GROUPING(action, site_id, attack_type) AS grouping,
   COUNT(*) AS count, COALESCE(AVG(risk_score),0) AS avg_score, COALESCE(AVG(duration),0) AS avg_duration
   FROM request_logs WHERE (?::timestamptz IS NULL OR created_at >= ?::timestamptz)
   AND (?::timestamptz IS NULL OR created_at <= ?::timestamptz)
   GROUP BY GROUPING SETS ((), (action), (site_id), (attack_type))`
		if err := dao.GetDB().Raw(query, startTime, startTime, endTime, endTime).Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			switch row.Grouping {
			case 7:
				result.Total = row.Count
				result.AvgScore = row.AvgScore
				result.AvgDuration = row.AvgDuration
			case 3:
				if row.Action != nil {
					result.ByAction = append(result.ByAction, ActionCount{*row.Action, row.Count})
				}
			case 5:
				if row.SiteID != nil {
					result.BySite = append(result.BySite, SiteCount{*row.SiteID, row.Count})
				}
			case 6:
				if row.AttackType != nil && *row.AttackType != "" {
					result.ByAttackType = append(result.ByAttackType, AttackTypeCount{*row.AttackType, row.Count})
				}
			}
		}
		db := logTimeRange(dao.GetDB().Model(&model.RequestLog{}), startTime, endTime)
		if err := db.Select("client_ip, count(*) as count").Where("action = ?", "block").Group("client_ip").Order("count DESC, client_ip").Limit(10).Scan(&result.TopAttackIPs).Error; err != nil {
			return nil, err
		}
		db = logTimeRange(dao.GetDB().Model(&model.RuleMatch{}), startTime, endTime)
		if err := db.Select("rule_id, count(*) as count").Group("rule_id").Order("count DESC, rule_id").Limit(10).Scan(&result.TopRules).Error; err != nil {
			return nil, err
		}
		return result, nil
	})
}

func logTimeRange(db *gorm.DB, start, end *time.Time) *gorm.DB {
	if start != nil {
		db = db.Where("created_at >= ?", *start)
	}
	if end != nil {
		db = db.Where("created_at <= ?", *end)
	}
	return db
}

// GetAttackTypeStatistics 获取攻击类型统计
func (s *LogService) GetAttackTypeStatistics(startTime, endTime *time.Time) ([]map[string]interface{}, error) {
	var result []map[string]interface{}

	// 格式化时间为字符串
	startStr := formatTimeToString(startTime)
	endStr := formatTimeToString(endTime)

	db := dao.GetDB().Model(&model.RequestLog{})
	if startStr != "" {
		db = db.Where("created_at >= ?", startStr)
	}
	if endStr != "" {
		db = db.Where("created_at <= ?", endStr)
	}

	err := db.Select("attack_type, count(*) as count").
		Where("attack_type != ''").
		Group("attack_type").
		Order("count DESC").
		Scan(&result).Error

	return result, err
}

// GetAttackIPs 获取攻击IP分析
func (s *LogService) GetAttackIPs(startTime, endTime *time.Time) ([]AttackIPInfo, error) {
	return s.GetAttackIPsWithLimit(startTime, endTime, 20)
}

func (s *LogService) GetAttackIPsWithLimit(startTime, endTime *time.Time, limit int) ([]AttackIPInfo, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("invalid IP result limit")
	}
	key := fmt.Sprintf("attack-ips:%s:%s:%d", logRangeKey(startTime), logRangeKey(endTime), limit)
	return cachedLogQuery(key, func() ([]AttackIPInfo, error) {
		result := []AttackIPInfo{}
		err := logTimeRange(dao.GetDB().Model(&model.RequestLog{}), startTime, endTime).
			Select(`client_ip, count(*) AS attack_count, MIN(created_at) AS first_attack, MAX(created_at) AS last_attack,
    COALESCE(json_agg(DISTINCT attack_type) FILTER (WHERE attack_type != ''), '[]'::json)::text AS attack_types`).
			Where("action = ?", "block").Group("client_ip").Order("attack_count DESC, client_ip").Limit(limit).Scan(&result).Error
		return result, err
	})
}

// GetRequestLogList 获取请求日志列表
func (s *LogService) GetRequestLogList(page, pageSize int, action, attackType string, siteID uint, clientIP, startTime, endTime string) ([]model.RequestLog, int64, error) {
	var logs []model.RequestLog
	var total int64

	db := dao.GetDB().Model(&model.RequestLog{})

	// 筛选条件
	if action != "" {
		db = db.Where("action = ?", action)
	}
	if attackType != "" {
		db = db.Where("attack_type = ?", attackType)
	}
	if siteID > 0 {
		db = db.Where("site_id = ?", siteID)
	}
	if clientIP != "" {
		db = db.Where("client_ip = ?", clientIP)
	}
	if startTime != "" {
		db = db.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		db = db.Where("created_at <= ?", endTime)
	}

	// 统计总数
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	if err := db.Order("id DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	for i := range logs {
		DescribeDecision(&logs[i])
	}
	return logs, total, nil
}

// LogDetailResponse 日志详情响应
type LogDetailResponse struct {
	Log         model.RequestLog  `json:"log"`
	Matches     []model.RuleMatch `json:"matches"`
	AttackTypes map[string]int    `json:"attack_types"`
	TotalScore  int               `json:"total_score"`
	Action      string            `json:"action"`
}

// GetRequestLogDetail 获取请求日志详情
func (s *LogService) GetRequestLogDetail(id uint) (*LogDetailResponse, error) {
	var log model.RequestLog
	if err := dao.GetDB().First(&log, id).Error; err != nil {
		return nil, err
	}
	DescribeDecision(&log)

	// 获取匹配的规则
	var matches []model.RuleMatch
	dao.GetDB().Where("request_log_id = ?", id).Find(&matches)

	// 统计攻击类型（排除 Protocol Issue）
	attackTypes := make(map[string]int)
	for _, m := range matches {
		attackType := GetAttackTypeByRuleID(m.RuleID)
		// 排除 Protocol Issue
		if attackType != "Protocol Issue" {
			attackTypes[attackType]++
		}
	}

	// 计算总分
	var totalScore int
	for _, m := range matches {
		totalScore += m.Score
	}
	if log.ScoreBasis == "crs_anomaly" {
		totalScore = log.RiskScore
	}

	return &LogDetailResponse{
		Log:         log,
		Matches:     matches,
		AttackTypes: attackTypes,
		TotalScore:  totalScore,
		Action:      log.Action,
	}, nil
}

// DailyStatistics 每日统计
type DailyStatistics struct {
	Date       string `json:"date"`
	Total      int64  `json:"total"`
	BlockCount int64  `json:"block_count"`
	PassCount  int64  `json:"pass_count"`
}

// GetDailyStatistics 获取每日统计
func (s *LogService) GetDailyStatistics(days int) ([]DailyStatistics, error) {
	if days < 1 || days > 366 {
		return nil, fmt.Errorf("days 必须在 1–366 之间")
	}
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	start := today.AddDate(0, 0, -days+1)
	return cachedLogQuery(fmt.Sprintf("daily:%s:%d", today.Format("2006-01-02"), days), func() ([]DailyStatistics, error) {
		var rows []DailyStatistics
		err := dao.GetDB().Model(&model.RequestLog{}).Select(`to_char(created_at AT TIME ZONE 'Asia/Shanghai','YYYY-MM-DD') AS date, count(*) AS total,
    count(*) FILTER (WHERE action='block') AS block_count, count(*) FILTER (WHERE action='pass') AS pass_count`).
			Where("created_at >= ? AND created_at < ?", start, today.AddDate(0, 0, 1)).Group("date").Order("date").Scan(&rows).Error
		if err != nil {
			return nil, err
		}
		byDate := map[string]DailyStatistics{}
		for _, row := range rows {
			byDate[row.Date] = row
		}
		result := make([]DailyStatistics, 0, days)
		for i := 0; i < days; i++ {
			date := start.AddDate(0, 0, i).Format("2006-01-02")
			row := byDate[date]
			row.Date = date
			result = append(result, row)
		}
		return result, nil
	})
}

// GetTrend performs one indexed range scan and fills empty buckets in memory.
func (s *LogService) GetTrend(startTime, endTime *time.Time) ([]TrendStatistics, error) {
	now := time.Now()
	start, end := now.Add(-24*time.Hour), now
	if startTime != nil {
		start = *startTime
	}
	if endTime != nil {
		end = *endTime
	}
	if !start.Before(end) || end.Sub(start) > 366*24*time.Hour {
		return nil, fmt.Errorf("趋势时间范围必须大于零且不超过 366 天")
	}
	interval := trendInterval(end.Sub(start))
	// Normalize defaults to seconds so repeated dashboard refreshes share the cache.
	start = start.Truncate(time.Second)
	end = end.Truncate(time.Second)
	ttl := logCacheTTL()
	keyStart, keyEnd := start, end
	if ttl > 0 && startTime == nil && endTime == nil {
		keyStart = start.Truncate(ttl)
		keyEnd = end.Truncate(ttl)
		start, end = keyStart, keyEnd
	}
	key := fmt.Sprintf("trend:%d:%d:%d", keyStart.Unix(), keyEnd.Unix(), int64(interval))
	return cachedLogQuery(key, func() ([]TrendStatistics, error) {
		var rows []struct {
			Bucket     int
			Total      int64
			BlockCount int64
		}
		err := dao.GetDB().Model(&model.RequestLog{}).Select(`floor(extract(epoch FROM (created_at - ?::timestamptz)) / ?)::int AS bucket,
   count(*) AS total, count(*) FILTER (WHERE action='block') AS block_count`, start, interval.Seconds()).
			Where("created_at >= ? AND created_at <= ?", start, end).Group("bucket").Order("bucket").Scan(&rows).Error
		if err != nil {
			return nil, err
		}
		result := make([]TrendStatistics, int(end.Sub(start)/interval)+1)
		for i := range result {
			result[i].Hour = start.Add(time.Duration(i) * interval).Format("2006-01-02 15:04:05")
		}
		for _, row := range rows {
			if row.Bucket >= 0 && row.Bucket < len(result) {
				result[row.Bucket].Total = row.Total
				result[row.Bucket].BlockCount = row.BlockCount
			}
		}
		return result, nil
	})
}

func trendInterval(duration time.Duration) time.Duration {
	switch {
	case duration <= 2*time.Hour:
		return 5 * time.Minute
	case duration <= 6*time.Hour:
		return 15 * time.Minute
	case duration <= 24*time.Hour:
		return time.Hour
	case duration <= 7*24*time.Hour:
		return 4 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// GetAttackTrend 获取攻击趋势（兼容旧接口）
func (s *LogService) GetAttackTrend(hours int) ([]TrendStatistics, error) {
	end := time.Now()
	if ttl := logCacheTTL(); ttl > 0 {
		end = end.Truncate(ttl)
	}
	start := end.Add(-time.Duration(hours) * time.Hour)
	return s.GetTrend(&start, &end)
}

// DeleteOldLogs 删除旧日志
func (s *LogService) DeleteOldLogs(days int) (int64, error) {
	if days < 1 {
		return 0, fmt.Errorf("保留天数必须大于零")
	}
	batch := 1000
	if c := config.GetConfig(); c != nil && c.Log.CleanupBatchSize > 0 {
		batch = c.Log.CleanupBatchSize
	}
	return deleteRequestLogs(dao.GetDB(), time.Now().AddDate(0, 0, -days), batch)
}

// UpdateAttackType 更新日志的攻击类型
func (s *LogService) UpdateAttackType(logID uint) {
	attackType := GetMainAttackType(logID)
	if attackType != "" {
		dao.GetDB().Model(&model.RequestLog{}).Where("id = ?", logID).Update("attack_type", attackType)
	}
}

// UpdateAllAttackTypes 更新所有日志的攻击类型
func (s *LogService) UpdateAllAttackTypes() error {
	var logs []model.RequestLog
	dao.GetDB().Where("attack_type = ''").Find(&logs)

	for _, log := range logs {
		s.UpdateAttackType(log.ID)
	}

	return nil
}
