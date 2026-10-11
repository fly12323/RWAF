package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/fly12323/RWAF/pkg/telemetry"
	"gorm.io/gorm"
)

type TableStorage struct {
	Name          string `json:"name"`
	Bytes         int64  `json:"bytes"`
	EstimatedRows int64  `json:"estimated_rows"`
}
type Storage struct {
	DatabaseBytes       *int64         `json:"database_bytes"`
	Tables              []TableStorage `json:"tables"`
	GrowthMBHour        *float64       `json:"growth_mb_hour"`
	GrowthWindowSeconds int64          `json:"growth_window_seconds"`
	SpoolDiskFreeBytes  *uint64        `json:"spool_disk_free_bytes"`
	DatabaseError       bool           `json:"database_error"`
	SpoolDiskError      bool           `json:"spool_disk_error"`
}

// ReadStorage uses PostgreSQL catalog estimates, never COUNT(*) over retained
// logs. The free-space figure belongs to the API's spool filesystem, not the
// (possibly remote) PostgreSQL host. Database capacity is a configured budget.
func ReadStorage(ctx context.Context, db *gorm.DB, spoolDir string) Storage {
	s := Storage{Tables: []TableStorage{}}
	var bytes int64
	if err := db.WithContext(ctx).Raw("SELECT pg_database_size(current_database())").Scan(&bytes).Error; err != nil {
		s.DatabaseError = true
	} else {
		s.DatabaseBytes = &bytes
		err := db.WithContext(ctx).Raw(`SELECT c.relname AS name, pg_total_relation_size(c.oid) AS bytes,
          GREATEST(c.reltuples,0)::bigint AS estimated_rows
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname=current_schema() AND c.relkind='r' AND c.relname IN
          ('request_logs','rule_matches','processed_events','quarantined_events','crawler_logs','weak_password_events','operation_logs')
          ORDER BY bytes DESC`).Scan(&s.Tables).Error
		if err != nil {
			s.DatabaseError = true
		}
	}
	if spoolDir != "" {
		free, err := diskFree(spoolDir)
		if err != nil {
			s.SpoolDiskError = true
		} else {
			s.SpoolDiskFreeBytes = &free
		}
	}
	return s
}

type growthBaseline struct {
	at     time.Time
	bytes  int64
	rate   *float64
	window int64
}

func (b *growthBaseline) observe(s *Storage, now time.Time) {
	if s.DatabaseBytes == nil || s.DatabaseError {
		return
	}
	if b.at.IsZero() {
		b.at, b.bytes = now, *s.DatabaseBytes
		return
	}
	elapsed := now.Sub(b.at)
	if elapsed < time.Minute {
		s.GrowthMBHour, s.GrowthWindowSeconds = b.rate, b.window
		return
	}
	delta := *s.DatabaseBytes - b.bytes
	if delta < 0 {
		delta = 0
	}
	rate := float64(delta) / 1048576 / elapsed.Hours()
	s.GrowthMBHour, s.GrowthWindowSeconds = &rate, int64(elapsed.Seconds())
	b.rate, b.window = &rate, int64(elapsed.Seconds())
	if elapsed >= 5*time.Minute {
		b.at, b.bytes = now, *s.DatabaseBytes
	}
}

func storageConditions(s Storage, queries telemetry.LogQuerySample, cBudget, cGrowth, cFree, cP95 int) []Condition {
	result := []Condition{}
	add := func(k, severity, m string) { result = append(result, Condition{k, severity, m}) }
	if s.DatabaseError {
		add("database_metrics", "warning", "数据库容量采样失败，容量与增长数据暂不可用")
	}
	if !s.DatabaseError && s.DatabaseBytes != nil && *s.DatabaseBytes >= int64(cBudget)*1048576*80/100 {
		severity := "warning"
		if *s.DatabaseBytes >= int64(cBudget)*1048576 {
			severity = "critical"
		}
		add("database_capacity", severity, fmt.Sprintf("数据库占用 %.1f MiB，配置预算 %d MiB（保留日志，不自动删除）", float64(*s.DatabaseBytes)/1048576, cBudget))
	}
	if !s.DatabaseError && s.GrowthMBHour != nil && *s.GrowthMBHour >= float64(cGrowth) {
		add("database_growth", "warning", fmt.Sprintf("数据库增长 %.1f MiB/小时，观测窗口 %d 秒", *s.GrowthMBHour, s.GrowthWindowSeconds))
	}
	if s.SpoolDiskError {
		add("spool_disk_metrics", "warning", "日志缓冲所在文件系统剩余空间采样失败")
	}
	if s.SpoolDiskFreeBytes != nil && *s.SpoolDiskFreeBytes <= uint64(cFree)*1048576 {
		add("spool_disk_space", "critical", "日志缓冲所在文件系统剩余空间低于阈值")
	}
	if queries.Count > 0 && queries.P95MS >= int64(cP95) {
		add("log_query_latency", "warning", "日志查询接口 P95 延迟桶超过阈值")
	}
	if queries.Errors > 0 {
		add("log_query_errors", "warning", "本采样周期日志查询接口出现服务端错误")
	}
	return result
}
