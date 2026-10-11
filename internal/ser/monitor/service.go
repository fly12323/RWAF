package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/weakpassword"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/telemetry"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Condition struct {
	Key      string `json:"key"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}
type Snapshot struct {
	Health          Health                   `json:"health"`
	IntervalSeconds int                      `json:"interval_seconds"`
	Storage         Storage                  `json:"storage"`
	LogQueries      telemetry.LogQuerySample `json:"log_queries"`
	SampledAt       time.Time                `json:"sampled_at"`
	UptimeSeconds   int64                    `json:"uptime_seconds"`
	Dependencies    map[string]string        `json:"dependencies"`
	KafkaLag        *int64                   `json:"kafka_lag"`
	Consumer        map[string]any           `json:"consumer"`
	Pipeline        map[string]int64         `json:"log_pipeline"`
	Detector        map[string]any           `json:"weak_password"`
	Requests        map[string]any           `json:"requests"`
	HeapMB          uint64                   `json:"heap_mb"`
	Goroutines      int                      `json:"goroutines"`
	Conditions      []Condition              `json:"conditions"`
	ConfigError     bool                     `json:"config_error"`
	AlertStoreError bool                     `json:"alert_store_error"`
	AlertsEnabled   bool                     `json:"alerts_enabled"`
}

var latest atomic.Pointer[Snapshot]
var stopping atomic.Bool
var started = time.Now()

func DefaultConfig() model.MonitorConfig {
	return model.MonitorConfig{ID: 1, Enabled: true, IntervalSeconds: 15, KafkaLagThreshold: 10000, QueuePercent: 80, ConsumerTimeoutSeconds: 30, HeapLimitMB: 512, ProxyErrorPercent: 10, ProxyMinRequests: 20, ProxyP99MS: 1000, DatabaseBudgetMB: 10240, DatabaseGrowthMBHour: 1024, SpoolDiskFreeMB: 256, LogQueryP95MS: 1000}
}
func GetConfig() (*model.MonitorConfig, error) {
	var c model.MonitorConfig
	err := dao.GetDB().First(&c, 1).Error
	return &c, err
}
func SaveConfig(c *model.MonitorConfig) error {
	if c.DatabaseBudgetMB < 1 || c.DatabaseBudgetMB > 1073741824 || c.DatabaseGrowthMBHour < 1 || c.DatabaseGrowthMBHour > 1073741824 || c.SpoolDiskFreeMB < 1 || c.SpoolDiskFreeMB > 1073741824 || c.LogQueryP95MS < 1 || c.LogQueryP95MS > 60000 {
		return fmt.Errorf("数据库预算、增长和缓冲磁盘空间阈值须为正数，日志查询 P95 阈值为 1–60000 ms")
	}
	if c.IntervalSeconds < 5 || c.IntervalSeconds > 300 || c.KafkaLagThreshold < 1 || c.KafkaLagThreshold > 1000000000 || c.QueuePercent < 1 || c.QueuePercent > 100 || c.ConsumerTimeoutSeconds < 15 || c.ConsumerTimeoutSeconds > 300 || c.HeapLimitMB < 1 || c.HeapLimitMB > 1048576 || c.ProxyErrorPercent < 1 || c.ProxyErrorPercent > 100 || c.ProxyMinRequests < 1 || c.ProxyMinRequests > 1000000000 || c.ProxyP99MS < 1 || c.ProxyP99MS > 60000 {
		return fmt.Errorf("监控间隔 5–300 秒、队列阈值 1–100%%、心跳超时 15–300 秒，其余阈值须为正数")
	}
	c.ID = 1
	result := dao.GetDB().Model(&model.MonitorConfig{}).Where("id=1").Select("*").Omit("id").Updates(c)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("监控配置尚未初始化")
	}
	return nil
}
func Current() *Snapshot {
	s := latest.Load()
	if s == nil {
		s = &Snapshot{IntervalSeconds: 15, Dependencies: map[string]string{"postgres": "unknown", "redis": "unknown", "kafka": "unknown"}, Conditions: []Condition{}, Pipeline: map[string]int64{}, Detector: map[string]any{}, Requests: map[string]any{}, Storage: Storage{Tables: []TableStorage{}}}
	}
	copy := *s
	copy.Health = health(s, time.Now())
	if stopping.Load() {
		copy.Health.Status, copy.Health.Ready = "stopping", false
	}
	return &copy
}

// KafkaLag compares current topic offsets with this configured consumer group's commits.
func KafkaLag(ctx context.Context, cfg config.KafkaConfig, transport *kafka.Transport) (int64, error) {
	if len(cfg.Brokers) == 0 {
		return 0, fmt.Errorf("Kafka brokers are not configured")
	}
	conn, err := kafka.DialContext(ctx, "tcp", cfg.Brokers[0])
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	parts, err := conn.ReadPartitions(cfg.Topic)
	if err != nil {
		return 0, err
	}
	if len(parts) == 0 {
		return 0, fmt.Errorf("topic has no partitions")
	}
	ids := []int{}
	queries := []kafka.OffsetRequest{}
	for _, p := range parts {
		ids = append(ids, p.ID)
		queries = append(queries, kafka.FirstOffsetOf(p.ID), kafka.LastOffsetOf(p.ID))
	}
	client := kafka.Client{Addr: kafka.TCP(cfg.Brokers...), Transport: transport}
	ends, err := client.ListOffsets(ctx, &kafka.ListOffsetsRequest{Topics: map[string][]kafka.OffsetRequest{cfg.Topic: queries}})
	if err != nil {
		return 0, err
	}
	commits, err := client.OffsetFetch(ctx, &kafka.OffsetFetchRequest{GroupID: cfg.GroupID, Topics: map[string][]int{cfg.Topic: ids}})
	if err != nil {
		return 0, err
	}
	if commits.Error != nil {
		return 0, commits.Error
	}
	positions := map[int]int64{}
	for _, p := range commits.Topics[cfg.Topic] {
		if p.Error != nil {
			return 0, p.Error
		}
		positions[p.Partition] = p.CommittedOffset
	}
	var lag int64
	for _, p := range ends.Topics[cfg.Topic] {
		if p.Error != nil {
			return 0, p.Error
		}
		position, ok := positions[p.Partition]
		if !ok {
			return 0, fmt.Errorf("partition offsets missing")
		}
		if position < p.FirstOffset {
			position = p.FirstOffset
		}
		if position < p.LastOffset {
			lag += p.LastOffset - position
		}
	}
	if len(ends.Topics[cfg.Topic]) != len(parts) {
		return 0, fmt.Errorf("partition offsets missing")
	}
	return lag, nil
}

func HeartbeatKey(group string) string { return "waf:consumer:heartbeat:" + group }

func decodeHeartbeat(value []byte, now time.Time, timeout time.Duration) map[string]any {
	var heartbeat map[string]any
	if json.Unmarshal(value, &heartbeat) != nil || heartbeat == nil {
		return nil
	}
	stamp, ok := heartbeat["heartbeat_at"].(float64)
	if !ok || stamp <= 0 {
		return nil
	}
	age := now.Sub(time.Unix(int64(stamp), 0))
	heartbeat["stale"] = age < -5*time.Second || age > timeout
	return heartbeat
}

// ConsumerHeartbeat runs independently of database writes, including retry periods.
func ConsumerHeartbeat(ctx context.Context, group string) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		payload := events.ConsumerStats()
		payload["heartbeat_at"] = time.Now().Unix()
		body, _ := json.Marshal(payload)
		writeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := dao.RDB.Set(writeCtx, HeartbeatKey(group), body, 5*time.Minute).Err()
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Printf("consumer heartbeat failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func evaluate(s *Snapshot, c model.MonitorConfig, previous map[string]int64) []Condition {
	conditions := storageConditions(s.Storage, s.LogQueries, c.DatabaseBudgetMB, c.DatabaseGrowthMBHour, c.SpoolDiskFreeMB, c.LogQueryP95MS)
	add := func(key, severity, message string) {
		conditions = append(conditions, Condition{key, severity, message})
	}
	for _, name := range []string{"postgres", "redis", "kafka"} {
		if s.Dependencies[name] != "ok" {
			add(name+"_unavailable", "critical", name+" 探测失败")
		}
	}
	if s.Dependencies["redis"] == "ok" {
		if s.Consumer == nil || s.Consumer["stale"] == true {
			add("consumer_stale", "critical", "日志消费者心跳缺失或超时")
		} else if s.Consumer["state"] == "retrying" {
			add("consumer_retrying", "warning", "日志消费者正在重试入库或提交 offset")
		} else if s.Consumer["state"] != "running" {
			add("consumer_not_running", "critical", "日志消费者尚未开始工作或已经停止")
		}
	}
	if s.Pipeline["available"] != 1 {
		add("log_publisher", "critical", "日志发送器尚未初始化或已关闭")
	}
	if s.KafkaLag != nil && *s.KafkaLag >= c.KafkaLagThreshold {
		add("kafka_lag", "warning", fmt.Sprintf("Kafka 消费积压 %d 条", *s.KafkaLag))
	}
	if capacity := s.Pipeline["capacity"]; capacity > 0 && s.Pipeline["queued"]*100 >= capacity*int64(c.QueuePercent) {
		add("log_queue", "warning", "日志发送队列超过占用阈值")
	}
	if capacity := s.Pipeline["spool_capacity_bytes"]; capacity > 0 && s.Pipeline["spool_bytes"]*100 >= capacity*int64(c.QueuePercent) {
		add("log_spool", "warning", "日志持久化缓冲超过容量阈值")
	}
	for _, key := range []string{"dropped", "errors"} {
		if s.Pipeline[key] > previous[key] {
			add("log_"+key, "warning", "本采样周期出现日志丢弃或 Kafka 发送错误")
		}
	}
	for _, key := range []string{"dropped", "publish_errors", "skipped"} {
		n, _ := s.Detector[key].(int64)
		if n > previous["weak_"+key] {
			add("weak_"+key, "warning", "本采样周期存在弱口令检测丢弃、未完成或事件投递失败")
		}
	}
	if s.Detector["config_error"] != "" && s.Detector["config_error"] != nil {
		add("weak_config", "warning", "弱口令检测配置刷新失败")
	}
	if s.HeapMB >= uint64(c.HeapLimitMB) {
		add("heap", "warning", "WAF 进程 Go 堆内存超过阈值")
	}
	n, _ := s.Requests["requests"].(int64)
	ratio, _ := s.Requests["error_percent"].(float64)
	p99, _ := s.Requests["p99_bucket_ms"].(int64)
	if n >= int64(c.ProxyMinRequests) && ratio >= float64(c.ProxyErrorPercent) {
		add("proxy_errors", "warning", "代理 5xx 比例超过阈值")
	}
	if n >= int64(c.ProxyMinRequests) && p99 >= int64(c.ProxyP99MS) {
		add("proxy_latency", "warning", "代理 P99 延迟桶超过阈值")
	}
	return conditions
}
func Reconcile(ctx context.Context, conditions []Condition) error {
	return dao.GetDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(73921402)").Error; err != nil {
			return err
		}
		var open []model.Alert
		if err := tx.Where("source = ? AND status = ?", "runtime", "open").Find(&open).Error; err != nil {
			return err
		}
		byKey := map[string]model.Alert{}
		for _, a := range open {
			byKey[a.Key] = a
		}
		now := time.Now()
		active := map[string]bool{}
		for _, c := range conditions {
			active[c.Key] = true
			a, ok := byKey[c.Key]
			if !ok {
				a = model.Alert{Key: c.Key, Source: "runtime", Severity: c.Severity, Message: c.Message, Status: "open", Occurrences: 1, CreatedAt: now, LastSeen: now}
				if err := tx.Create(&a).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Model(&a).Updates(map[string]any{"severity": c.Severity, "message": c.Message, "last_seen": now, "occurrences": gorm.Expr("occurrences + 1")}).Error; err != nil {
					return err
				}
			}
		}
		for _, a := range open {
			if !active[a.Key] {
				if err := tx.Model(&a).Updates(map[string]any{"status": "resolved", "resolved_at": now}).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}
func Start(ctx context.Context) (func(), error) {
	stopping.Store(false)
	latest.Store(nil)
	c := DefaultConfig()
	if err := dao.GetDB().Clauses(clause.OnConflict{DoNothing: true}).Create(&c).Error; err != nil {
		return nil, err
	}
	stored, err := GetConfig()
	if err != nil {
		return nil, err
	}
	c = *stored
	done := make(chan struct{})
	transport := &kafka.Transport{DialTimeout: 3 * time.Second}
	go func() {
		defer MarkStopping()
		defer close(done)
		defer transport.CloseIdleConnections()
		previous := map[string]int64{}
		baseline := growthBaseline{}
		pending := map[string]Condition{}
		last := time.Now()
		for {
			if ctx.Err() != nil {
				return
			}
			configCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			var updated model.MonitorConfig
			configErr := dao.GetDB().WithContext(configCtx).First(&updated, 1).Error
			cancel()
			if configErr == nil {
				c = updated
			}
			s := &Snapshot{SampledAt: time.Now(), IntervalSeconds: c.IntervalSeconds, UptimeSeconds: int64(time.Since(started).Seconds()), Dependencies: map[string]string{}, Conditions: []Condition{}, Pipeline: events.Stats(), Detector: weakpassword.Stats(), ConfigError: configErr != nil, AlertsEnabled: c.Enabled, LogQueries: telemetry.Logs.Sample()}
			// Independent probes each have deadlines; management reads never run probes.
			var wg sync.WaitGroup
			var dbState, redisState, kafkaState string
			var heartbeat map[string]any
			var lag int64
			wg.Add(3)
			go func() {
				defer wg.Done()
				probe, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				db, err := dao.GetDB().DB()
				if err == nil {
					err = db.PingContext(probe)
				}
				dbState = "ok"
				if err != nil {
					dbState = "unavailable"
				}
				s.Storage = ReadStorage(probe, dao.GetDB(), config.GetConfig().Kafka.SpoolDir)
			}()
			go func() {
				defer wg.Done()
				probe, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				redisState = "ok"
				if dao.RDB.Ping(probe).Err() != nil {
					redisState = "unavailable"
					return
				}
				value, err := dao.RDB.Get(probe, HeartbeatKey(config.GetConfig().Kafka.GroupID)).Bytes()
				if err == nil {
					heartbeat = decodeHeartbeat(value, time.Now(), time.Duration(c.ConsumerTimeoutSeconds)*time.Second)
				}
			}()
			go func() {
				defer wg.Done()
				probe, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				var err error
				lag, err = KafkaLag(probe, config.GetConfig().Kafka, transport)
				kafkaState = "ok"
				if err != nil {
					kafkaState = "unavailable"
				}
			}()
			wg.Wait()
			baseline.observe(&s.Storage, s.SampledAt)
			s.Dependencies = map[string]string{"postgres": dbState, "redis": redisState, "kafka": kafkaState}
			s.Consumer = heartbeat
			if kafkaState == "ok" {
				s.KafkaLag = &lag
			}
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			s.HeapMB = mem.HeapAlloc / 1024 / 1024
			s.Goroutines = runtime.NumGoroutine()
			s.Requests = telemetry.Sample(time.Since(last).Seconds())
			last = time.Now()
			s.Conditions = evaluate(s, c, previous)
			// A failed measurement is not evidence that an earlier capacity alarm
			// recovered. Keep it open until the relevant metric is available.
			if prior := latest.Load(); prior != nil {
				for _, condition := range prior.Conditions {
					if s.Storage.DatabaseError && (condition.Key == "database_capacity" || condition.Key == "database_growth") || s.Storage.SpoolDiskError && condition.Key == "spool_disk_space" {
						s.Conditions = append(s.Conditions, condition)
					}
				}
			}
			for _, key := range []string{"dropped", "errors"} {
				previous[key] = s.Pipeline[key]
			}
			for _, key := range []string{"dropped", "publish_errors", "skipped"} {
				n, _ := s.Detector[key].(int64)
				previous["weak_"+key] = n
			}
			if c.Enabled && ctx.Err() == nil {
				writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				var err error
				if len(pending) > 0 {
					combined := map[string]Condition{}
					for key, value := range pending {
						combined[key] = value
					}
					for _, condition := range s.Conditions {
						combined[condition.Key] = condition
					}
					replay := []Condition{}
					for _, condition := range combined {
						replay = append(replay, condition)
					}
					err = Reconcile(writeCtx, replay)
				}
				if err == nil {
					err = Reconcile(writeCtx, s.Conditions)
				}
				cancel()
				s.AlertStoreError = err != nil
				if err != nil {
					for _, condition := range s.Conditions {
						pending[condition.Key] = condition
					}
				} else {
					clear(pending)
				}
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("runtime alert store unavailable: %v", err)
				}
			} else if !c.Enabled {
				clear(pending)
			}
			latest.Store(s)
			timer := time.NewTimer(time.Duration(c.IntervalSeconds) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return func() { <-done }, nil
}
