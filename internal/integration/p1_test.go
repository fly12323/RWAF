package integration

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/handler"
	"github.com/fly12323/RWAF/internal/middleware"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/router"
	"github.com/fly12323/RWAF/internal/ser/monitor"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/jwt"
	"github.com/fly12323/RWAF/pkg/proxy"
	"github.com/fly12323/RWAF/pkg/telemetry"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Disconnect existing sockets as well as new connections. Fault injection stays
// inside this test process and cannot stop or change the deployed services.
func dependencyProxy(t *testing.T, target string) (int, func(bool)) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	blocked := false
	connections := map[net.Conn]bool{}
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				mu.Lock()
				if blocked {
					mu.Unlock()
					client.Close()
					return
				}
				connections[client] = true
				mu.Unlock()
				defer func() { client.Close(); mu.Lock(); delete(connections, client); mu.Unlock() }()
				upstream, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				mu.Lock()
				if blocked {
					mu.Unlock()
					return
				}
				connections[upstream] = true
				mu.Unlock()
				defer func() { mu.Lock(); delete(connections, upstream); mu.Unlock() }()
				done := make(chan struct{})
				go func() { io.Copy(upstream, client); upstream.Close(); close(done) }()
				io.Copy(client, upstream)
				client.Close()
				<-done
			}()
		}
	}()
	set := func(value bool) {
		mu.Lock()
		defer mu.Unlock()
		blocked = value
		if value {
			for conn := range connections {
				conn.Close()
			}
		}
	}
	t.Cleanup(func() { listener.Close(); set(true) })
	return listener.Addr().(*net.TCPAddr).Port, set
}

func TestP1HealthDependencyFaultsAndRecovery(t *testing.T) {
	original := quarantineDB(t)
	cfg := config.GetConfig()
	pgPort, pgFault := dependencyProxy(t, "127.0.0.1:15432")
	redisPort, redisFault := dependencyProxy(t, "127.0.0.1:16379")
	kafkaPort, kafkaFault := dependencyProxy(t, "127.0.0.1:29094")
	cfg.Database.Port = pgPort
	cfg.Redis.Port = redisPort
	cfg.Kafka.Brokers = []string{"127.0.0.1:" + strconv.Itoa(kafkaPort)}
	cfg.Kafka.Topic = "waf-test-events"
	cfg.Kafka.GroupID = "p1-monitor-" + uuid.NewString()
	cfg.Kafka.ConsumerWorkers = 1
	cfg.Kafka.SpoolDir = t.TempDir()
	db, err := gorm.Open(postgres.Open(cfg.Database.DSN()), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	dao.DB = db
	t.Cleanup(func() { sql, _ := db.DB(); sql.Close(); dao.DB = original })
	if err := dao.InitRedis(); err != nil {
		t.Fatal(err)
	}
	defer dao.CloseRedis()
	stored, err := monitor.GetConfig()
	if err != nil {
		storedPtr := monitor.DefaultConfig()
		stored = &storedPtr
		if err := db.Create(stored).Error; err != nil {
			t.Fatal(err)
		}
	}
	c := monitor.DefaultConfig()
	c.IntervalSeconds = 5
	if err := monitor.SaveConfig(&c); err != nil {
		t.Fatal(err)
	}
	defer monitor.SaveConfig(stored)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	publisher, err := events.OpenPublisher(cfg.Kafka)
	if err != nil {
		t.Fatal(err)
	}
	events.SetPublisher(publisher)
	defer func() {
		events.SetPublisher(nil)
		closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		publisher.Close(closeCtx)
	}()
	consumeDone := make(chan error, 1)
	go func() { consumeDone <- events.ConsumeGroup(ctx, db, cfg.Kafka) }()
	heartbeatDone := make(chan struct{})
	go func() { defer close(heartbeatDone); monitor.ConsumerHeartbeat(ctx, cfg.Kafka.GroupID) }()
	waitMonitor, err := monitor.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); waitMonitor(); <-consumeDone; <-heartbeatDone }()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	tokens := service.NewTokenService()
	j := jwt.NewJWT(jwt.JWTConfig{Secret: "p1-integration-32-character-secret", ExpireTime: 1})
	manager := proxy.NewProxyManager(nil)
	defer manager.StopAll()
	router.SetupAPIRouter(r, manager, j, tokens, service.NewUserService(j, tokens))
	check := func(path string, expected int) {
		t.Helper()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != expected {
			t.Fatalf("%s %d: %s", path, w.Code, w.Body)
		}
	}
	wait := func(label string, predicate func(*monitor.Snapshot) bool) {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			if predicate(monitor.Current()) {
				t.Log(label, monitor.Current().Health)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		raw, _ := json.Marshal(monitor.Current())
		t.Fatalf("timeout %s: %s", label, raw)
	}
	check("/health/live", 200)
	wait("healthy baseline", func(s *monitor.Snapshot) bool { return s.Health.Ready })
	check("/health/ready", 200)
	// Corrupted Redis heartbeat data must degrade readiness without killing the
	// monitoring goroutine; a normal heartbeat must restore readiness afterwards.
	for _, payload := range []string{"null", `{"heartbeat_at":"invalid"}`} {
		faultCtx, stopHeartbeat := context.WithCancel(context.Background())
		writerDone := make(chan struct{})
		defer func() { stopHeartbeat(); <-writerDone }()
		go func() {
			defer close(writerDone)
			for {
				dao.RDB.Set(faultCtx, monitor.HeartbeatKey(cfg.Kafka.GroupID), payload, time.Minute)
				select {
				case <-faultCtx.Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		}()
		wait("malformed heartbeat unavailable", func(s *monitor.Snapshot) bool {
			return s.Dependencies["redis"] == "ok" && s.Consumer == nil && !s.Health.Ready
		})
		check("/health/ready", 503)
		check("/health/live", 200)
		stopHeartbeat()
		<-writerDone
		wait("heartbeat restored", func(s *monitor.Snapshot) bool { return s.Health.Ready })
	}
	for _, fault := range []struct {
		name string
		set  func(bool)
	}{{"postgres", pgFault}, {"redis", redisFault}, {"kafka", kafkaFault}} {
		fault.set(true)
		wait(fault.name+" unavailable", func(s *monitor.Snapshot) bool { return s.Dependencies[fault.name] == "unavailable" && !s.Health.Ready })
		check("/health/ready", 503)
		check("/health", 503)
		check("/health/live", 200)
		fault.set(false)
		wait(fault.name+" recovered", func(s *monitor.Snapshot) bool { return s.Health.Ready })
		check("/health/ready", 200)
	}
	// Keep a real capacity alert active when catalog measurements fail, then
	// restore the budget and verify automatic recovery in PostgreSQL.
	c.DatabaseBudgetMB = 1
	if err := monitor.SaveConfig(&c); err != nil {
		t.Fatal(err)
	}
	wait("capacity threshold", func(s *monitor.Snapshot) bool {
		for _, v := range s.Conditions {
			if v.Key == "database_capacity" && v.Severity == "critical" {
				return true
			}
		}
		return false
	})
	pgFault(true)
	wait("capacity unknown retains alert", func(s *monitor.Snapshot) bool {
		if !s.Storage.DatabaseError {
			return false
		}
		for _, v := range s.Conditions {
			if v.Key == "database_capacity" {
				return true
			}
		}
		return false
	})
	pgFault(false)
	wait("database recovered with capacity alert", func(s *monitor.Snapshot) bool { return s.Dependencies["postgres"] == "ok" && !s.Storage.DatabaseError })
	c.DatabaseBudgetMB = 10240
	if err := monitor.SaveConfig(&c); err != nil {
		t.Fatal(err)
	}
	wait("capacity recovered", func(s *monitor.Snapshot) bool { return s.Health.Ready })
	var open int64
	if err := db.Model(&model.Alert{}).Where("source='runtime' AND status='open' AND key IN ?", []string{"database_capacity", "postgres_unavailable", "redis_unavailable", "kafka_unavailable"}).Count(&open).Error; err != nil || open != 0 {
		t.Fatal("alerts did not recover", open, err)
	}
	monitor.MarkStopping()
	check("/health/ready", 503)
	check("/health/live", 200)
}

func TestP1StorageCatalogQueryBudgetAndAlertEscalation(t *testing.T) {
	db := quarantineDB(t)
	ctx := context.Background()
	// Retain this synthetic log in the disposable test database, as agreed.
	id := "p1-retained-" + uuid.NewString()
	entry := model.RequestLog{RequestID: id, Method: "GET", URI: "/p1-retained", Action: "pass", CreatedAt: time.Now().AddDate(-2, 0, 0)}
	if err := db.Create(&entry).Error; err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	s := monitor.ReadStorage(ctx, db, t.TempDir())
	if s.DatabaseError || s.SpoolDiskError || s.DatabaseBytes == nil || s.SpoolDiskFreeBytes == nil || len(s.Tables) < 7 {
		t.Fatal(s)
	}
	t.Logf("catalog sampling took %s; database bytes=%d tables=%d", time.Since(start), *s.DatabaseBytes, len(s.Tables))
	for _, state := range []struct{ severity string }{{"warning"}, {"critical"}} {
		if err := monitor.Reconcile(ctx, []monitor.Condition{{Key: "p1-escalation", Severity: state.severity, Message: "test escalation"}}); err != nil {
			t.Fatal(err)
		}
	}
	var alert model.Alert
	if err := db.Where("key='p1-escalation' AND status='open'").First(&alert).Error; err != nil || alert.Severity != "critical" || alert.Occurrences != 2 {
		t.Fatal(alert, err)
	}
	if err := monitor.Reconcile(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.First(&alert, alert.ID).Error; err != nil || alert.Status != "resolved" {
		t.Fatal(alert, err)
	}
	// PostgreSQL sleeps inside a callback to prove cancellation reaches the DB,
	// rather than merely terminating the HTTP response while SQL keeps running.
	callback := "p1:query-delay"
	if err := db.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Table == "request_logs" {
			result := tx.Exec("SELECT pg_sleep(2)")
			if result.Error != nil {
				tx.AddError(result.Error)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer db.Callback().Query().Remove(callback)
	queryCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, _, err := service.NewLogService().WithContext(queryCtx).GetRequestLogList(1, 10, "", "", 0, "", "", "")
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("SQL did not respect cancellation", time.Since(start), err)
	}
	db.Callback().Query().Remove(callback)
	_, _, err = service.NewLogService().GetRequestLogList(1, 1000, "", "", 0, "", "", "")
	if err == nil {
		t.Fatal("unbounded page accepted")
	}
	var n int64
	if err := db.Model(&model.RequestLog{}).Where("request_id=?", id).Count(&n).Error; err != nil || n != 1 {
		t.Fatal("retained log lost", n, err)
	}
}

func TestP1RetainedLogQueriesAndInstrumentationCost(t *testing.T) {
	db := quarantineDB(t)
	prefix := "p1-volume-" + uuid.NewString() + "-"
	if err := db.Exec(`INSERT INTO request_logs (request_id,method,uri,action,client_ip,created_at,risk_score,duration)
          SELECT ? || n::text,'GET','/p1-volume',CASE WHEN n%10=0 THEN 'block' ELSE 'pass' END,
          '198.51.100.42',now()-(n%720)*interval '1 hour',n%10,2
          FROM generate_series(1,100000) n`, prefix).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("ANALYZE request_logs").Error; err != nil {
		t.Fatal(err)
	}
	// With the same retained dataset and warm-up, compare route processing
	// before/after adding the P1 metrics and query context (no JWT overhead).
	gin.SetMode(gin.TestMode)
	h := handler.NewLogHandler()
	before := gin.New()
	before.GET("/logs", h.GetRequestLogList)
	after := gin.New()
	after.Use(middleware.LogQueryMetrics())
	after.GET("/logs", h.GetRequestLogList)
	measure := func(r *gin.Engine) (float64, float64) {
		durations := []float64{}
		for i := 0; i < 35; i++ {
			start := time.Now()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/logs?page=1&page_size=100&client_ip=198.51.100.42", nil))
			elapsed := float64(time.Since(start).Microseconds()) / 1000
			var body struct {
				Code int
				Data struct {
					Total int64
					List  []model.RequestLog
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Code != 0 || body.Data.Total < 100000 || len(body.Data.List) != 100 {
				t.Fatal("query response", err, w.Body.String())
			}
			if i >= 5 {
				durations = append(durations, elapsed)
			}
		}
		sort.Float64s(durations)
		return durations[len(durations)/2], durations[(len(durations)*95+99)/100-1]
	}
	pre50, pre95 := measure(before)
	telemetry.Logs.Sample()
	post50, post95 := measure(after)
	if post95 > 500 {
		t.Fatalf("100k retained log query P95 %.3f ms exceeds 500 ms local acceptance", post95)
	}
	if post50 > pre50*1.25+2 {
		t.Fatalf("instrumentation regression median %.3f -> %.3f ms", pre50, post50)
	}
	sample := telemetry.Logs.Sample()
	if sample.Count != 35 || sample.Errors != 0 {
		t.Fatal("metrics lost queries", sample)
	}
	start := time.Now()
	storage := monitor.ReadStorage(context.Background(), db, t.TempDir())
	elapsed := time.Since(start)
	if storage.DatabaseError || elapsed > 500*time.Millisecond {
		t.Fatal("catalog scan cost", elapsed, storage)
	}
	var rows int64
	for _, table := range storage.Tables {
		if table.Name == "request_logs" {
			rows = table.EstimatedRows
		}
	}
	if rows < 100000 {
		t.Fatal("missing row estimate", rows)
	}
	t.Logf("retained 100k logs; before median=%.3f p95=%.3f ms; after median=%.3f p95=%.3f ms; storage sampling=%s; estimated rows=%d", pre50, pre95, post50, post95, elapsed, rows)
}
