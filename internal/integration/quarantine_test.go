package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/router"
	"github.com/fly12323/RWAF/internal/ser/monitor"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/jwt"
	"github.com/fly12323/RWAF/pkg/proxy"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"gorm.io/gorm"
)

func quarantineDB(t *testing.T) *gorm.DB {
	t.Helper()
	if os.Getenv("WAF_INTEGRATION") != "1" {
		t.Skip("requires isolated integration stack")
	}
	previous := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = previous })
	for k, v := range map[string]string{"DB_HOST": "127.0.0.1", "DB_PORT": "15432", "DB_USER": "waf_test", "DB_PASSWORD": "waf-test-only", "DB_NAME": "waf_test", "REDIS_HOST": "127.0.0.1", "REDIS_PORT": "16379", "REDIS_PASSWORD": "", "KAFKA_BROKERS": "127.0.0.1:29094"} {
		t.Setenv(k, v)
	}
	if err := config.LoadConfig("../../configs/config.yaml"); err != nil {
		t.Fatal(err)
	}
	config.GetConfig().Server.Mode = "release"
	if err := dao.InitDB(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dao.CloseDB() })
	return dao.GetDB()
}

func quarantineFixture(t *testing.T, db *gorm.DB, cfg config.KafkaConfig, payload []byte, offset int64) model.QuarantinedEvent {
	t.Helper()
	msg := kafka.Message{Topic: cfg.Topic, Partition: 0, Offset: offset, Key: []byte{0, 255}, Value: payload, Headers: []kafka.Header{{Key: "binary", Value: []byte{0, 255}}}, Time: time.Now()}
	if err := events.QuarantineMessage(context.Background(), db, cfg, msg, errors.New("fixture invalid event")); err != nil {
		t.Fatal(err)
	}
	var q model.QuarantinedEvent
	if err := db.Where("consumer_group = ? AND \"offset\" = ?", cfg.GroupID, offset).First(&q).Error; err != nil {
		t.Fatal(err)
	}
	return q
}

func TestPostgresQuarantineReplayAtomicityAndConcurrency(t *testing.T) {
	db := quarantineDB(t)
	cfg := config.GetConfig().Kafka
	cfg.GroupID = "q-replay-" + uuid.NewString()
	cfg.Topic = "waf-test-events"
	payload := []byte{'{', 0, 255}
	q := quarantineFixture(t, db, cfg, payload, 11)
	quarantineFixture(t, db, cfg, payload, 11)
	var rows, alerts int64
	if err := db.Model(&model.QuarantinedEvent{}).Where("consumer_group = ?", cfg.GroupID).Count(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.Alert{}).Where("key = ?", fmt.Sprintf("quarantine:%d", q.ID)).Count(&alerts).Error; err != nil {
		t.Fatal(err)
	}
	if rows != 1 || alerts != 1 || !bytes.Equal(q.Payload, payload) {
		t.Fatal("redelivery duplicated/lost quarantine", rows, alerts, q)
	}
	ctx := context.Background()
	audit := model.OperationLog{Username: "p0-test-admin", UserID: 1}
	if _, err := events.ReplayQuarantinedEvent(ctx, db, q.ID, nil, "invalid original", 4096, audit); !errors.Is(err, events.ErrInvalidReplay) {
		t.Fatal("invalid original replay", err)
	}
	e := events.RequestEvent(&model.RequestLog{RequestID: "q-replay-" + uuid.NewString(), Method: "GET", URI: "/recovered"}, nil)
	corrected, _ := json.Marshal(e)
	bad := e
	copyRequest := *e.Request
	copyRequest.Method = strings.Repeat("x", 11)
	bad.Request = &copyRequest
	badBytes, _ := json.Marshal(bad)
	if _, err := events.ReplayQuarantinedEvent(ctx, db, q.ID, badBytes, "invalid SQL constraint", 4096, audit); !errors.Is(err, events.ErrInvalidReplay) {
		t.Fatal("SQL constraint replay", err)
	}
	// An audit failure must roll back the log, dedup receipt, status and alert.
	badAudit := audit
	badAudit.Username = strings.Repeat("x", 51)
	if _, err := events.ReplayQuarantinedEvent(ctx, db, q.ID, corrected, "audit rollback", 4096, badAudit); err == nil {
		t.Fatal("audit failure accepted")
	}
	var receiptCount int64
	if err := db.Model(&model.ProcessedEvent{}).Where("event_id = ?", e.ID).Count(&receiptCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.First(&q, q.ID).Error; err != nil {
		t.Fatal(err)
	}
	if receiptCount != 0 || q.Status != "pending" {
		t.Fatal("partial replay committed", receiptCount, q.Status)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := events.ReplayQuarantinedEvent(ctx, db, q.ID, corrected, "corrected event", 4096, audit)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	succeeded, conflicted := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, events.ErrAlreadyReplayed) {
			conflicted++
		} else {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatal("concurrent replay", succeeded, conflicted)
	}
	if err := db.First(&q, q.ID).Error; err != nil {
		t.Fatal(err)
	}
	if q.Status != "replayed" || q.ReplayEventID != e.ID || !bytes.Equal(q.Payload, payload) || !bytes.Equal(q.ReplayPayload, corrected) || q.ReplayReason != "corrected event" {
		t.Fatal("replay evidence", q)
	}
	if err := db.Model(&model.RequestLog{}).Where("request_id = ?", e.Request.RequestID).Count(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.OperationLog{}).Where("resource = ? AND resource_id = ?", "log_quarantine", q.ID).Count(&alerts).Error; err != nil {
		t.Fatal(err)
	}
	if rows != 1 || alerts != 1 {
		t.Fatal("replay duplicated log/audit", rows, alerts)
	}
	var alert model.Alert
	if err := db.Where("key = ?", fmt.Sprintf("quarantine:%d", q.ID)).First(&alert).Error; err != nil {
		t.Fatal(err)
	}
	if alert.Status != "resolved" {
		t.Fatal("replay alert not resolved")
	}
	// A different transport record carrying the same event cannot duplicate logs.
	q2 := quarantineFixture(t, db, cfg, corrected, 12)
	if _, err := events.ReplayQuarantinedEvent(ctx, db, q2.ID, nil, "duplicate event replay", 4096, audit); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.RequestLog{}).Where("request_id = ?", e.Request.RequestID).Count(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatal("dedup receipt lost on replay")
	}
	t.Log("binary original retained; quarantine/alert dedup; invalid replay refused; audit failure rolled back; concurrent replay serialized; event replay dedup verified")
}

func TestKafkaQuarantineContinuesAndRecoversStorageFailure(t *testing.T) {
	db := quarantineDB(t)
	cfg := config.GetConfig().Kafka
	cfg.Topic = "p0-" + uuid.NewString()
	cfg.GroupID = "p0-" + uuid.NewString()
	cfg.BatchSize = 10
	cfg.FlushIntervalMs = 25
	cfg.MaxEventBytes = 4096
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	conn, err := kafka.DialContext(ctx, "tcp", cfg.Brokers[0])
	if err != nil {
		t.Fatal(err)
	}
	controller, err := conn.Controller()
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := kafka.DialContext(ctx, "tcp", net.JoinHostPort(controller.Host, fmt.Sprint(controller.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := admin.CreateTopics(kafka.TopicConfig{Topic: cfg.Topic, NumPartitions: 3, ReplicationFactor: 1}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.DeleteTopics(cfg.Topic) })
	// Fail only quarantine persistence. Valid-prefix writes must still commit.
	if err := db.Exec(`CREATE OR REPLACE FUNCTION p0_quarantine_outage() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated quarantine storage outage' USING ERRCODE = '08006'; END $$`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TRIGGER p0_quarantine_outage BEFORE INSERT ON quarantined_events FOR EACH ROW EXECUTE FUNCTION p0_quarantine_outage()`).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec("DROP TRIGGER IF EXISTS p0_quarantine_outage ON quarantined_events")
		db.Exec("DROP FUNCTION IF EXISTS p0_quarantine_outage()")
	})
	id1, id2 := "p0-first-"+uuid.NewString(), "p0-last-"+uuid.NewString()
	first := events.RequestEvent(&model.RequestLog{RequestID: id1, Method: "GET", URI: "/first"}, nil)
	last := events.RequestEvent(&model.RequestLog{RequestID: id2, Method: "GET", URI: "/last"}, nil)
	firstBytes, _ := json.Marshal(first)
	lastBytes, _ := json.Marshal(last)
	badSQL := events.RequestEvent(&model.RequestLog{RequestID: "p0-sql-" + uuid.NewString(), Method: strings.Repeat("x", 11)}, nil)
	badSQLBytes, _ := json.Marshal(badSQL)
	payloads := [][]byte{firstBytes, []byte{'{', 0, 255}, []byte(`{"version":99,"id":"bad"}`), bytes.Repeat([]byte("x"), 8192), badSQLBytes, firstBytes, lastBytes}
	writer := &kafka.Writer{Addr: kafka.TCP(cfg.Brokers...), Topic: cfg.Topic, Balancer: &kafka.Hash{}, RequiredAcks: kafka.RequireAll, BatchTimeout: time.Millisecond}
	defer writer.Close()
	msgs := make([]kafka.Message, 0, len(payloads))
	for _, p := range payloads {
		msgs = append(msgs, kafka.Message{Key: []byte("same-partition"), Value: p})
	}
	if err := writer.WriteMessages(ctx, msgs...); err != nil {
		t.Fatal(err)
	}
	consumerCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- events.ConsumeGroup(consumerCtx, db, cfg) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("consumer failed to stop")
		}
	})
	wait := func(predicate func() bool) {
		t.Helper()
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case err := <-done:
				t.Fatalf("consumer unexpectedly stopped: %v", err)
			default:
			}
			if predicate() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("timed out waiting for consumer")
	}
	countLogs := func(id string) int64 {
		var n int64
		if err := db.Model(&model.RequestLog{}).Where("request_id = ?", id).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		return n
	}
	wait(func() bool { return countLogs(id1) == 1 })
	time.Sleep(200 * time.Millisecond)
	var isolated int64
	db.Model(&model.QuarantinedEvent{}).Where("consumer_group = ?", cfg.GroupID).Count(&isolated)
	if isolated != 0 || countLogs(id2) != 0 {
		t.Fatal("consumer advanced during quarantine storage outage")
	}
	transport := &kafka.Transport{DialTimeout: 2 * time.Second}
	defer transport.CloseIdleConnections()
	lag, err := monitor.KafkaLag(ctx, cfg, transport)
	if err != nil || lag == 0 {
		t.Fatal("failed quarantine offset was committed", lag, err)
	}
	if err := db.Exec("DROP TRIGGER p0_quarantine_outage ON quarantined_events").Error; err != nil {
		t.Fatal(err)
	}
	wait(func() bool {
		db.Model(&model.QuarantinedEvent{}).Where("consumer_group = ?", cfg.GroupID).Count(&isolated)
		return isolated == 4 && countLogs(id2) == 1
	})
	wait(func() bool { lag, err := monitor.KafkaLag(ctx, cfg, transport); return err == nil && lag == 0 })
	if countLogs(id1) != 1 {
		t.Fatal("valid duplicate was inserted twice")
	}
	var qs []model.QuarantinedEvent
	if err := db.Where("consumer_group = ?", cfg.GroupID).Order("\"offset\"").Find(&qs).Error; err != nil {
		t.Fatal(err)
	}
	if len(qs) != 4 {
		t.Fatal("quarantine detail count mismatch", len(qs))
	}
	for i, q := range qs {
		if !bytes.Equal(q.Payload, payloads[i+1]) {
			t.Fatal("quarantine bytes changed", i, q.PayloadBytes)
		}
		var n int64
		db.Model(&model.Alert{}).Where("key = ?", fmt.Sprintf("quarantine:%d", q.ID)).Count(&n)
		if n != 1 {
			t.Fatal("quarantine alert missing")
		}
	}
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Restart using committed offsets: no duplicate isolation and no missing tail.
	consumerCtx, stop = context.WithCancel(ctx)
	defer stop()
	go func() { done <- events.ConsumeGroup(consumerCtx, db, cfg) }()
	time.Sleep(1200 * time.Millisecond)
	db.Model(&model.QuarantinedEvent{}).Where("consumer_group = ?", cfg.GroupID).Count(&isolated)
	if isolated != 4 || countLogs(id1) != 1 || countLogs(id2) != 1 {
		t.Fatal("restart duplicated/lost events")
	}
	t.Log("3 workers / 3 partitions; isolation outage preserved offset; recovery reached lag 0; 4 bad messages retained byte-for-byte; 2 unique logs retained; restart dedup verified")
}

func TestQuarantineAPIAuthorizationAndReplay(t *testing.T) {
	db := quarantineDB(t)
	if err := dao.InitRedis(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dao.CloseRedis() })
	cfg := config.GetConfig().Kafka
	cfg.GroupID = "q-api-" + uuid.NewString()
	cfg.Topic = "waf-test-events"
	q := quarantineFixture(t, db, cfg, []byte("{"), 1)
	tokens := service.NewTokenService()
	j := jwt.NewJWT(jwt.JWTConfig{Secret: strings.Repeat("t", 32), Issuer: "p0-test", ExpireTime: 1})
	gin.SetMode(gin.TestMode)
	r := gin.New()
	manager := proxy.NewProxyManager(nil)
	defer manager.StopAll()
	router.SetupAPIRouter(r, manager, j, tokens, service.NewUserService(j, tokens))
	request := func(method, path, token string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	apiCode := func(w *httptest.ResponseRecorder) int {
		t.Helper()
		var result struct {
			Code int `json:"code"`
		}
		if w.Code != 200 {
			t.Fatal("unexpected HTTP status", w.Code)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Code
	}
	if w := request("GET", "/api/v1/log-quarantine", "", nil); apiCode(w) != 401 {
		t.Fatal("unauthenticated access", w.Body.String())
	}
	roleTokens := map[string]string{}
	for i, role := range []string{"auditor", "operator", "admin"} {
		token, err := j.GenerateToken(uint(900+i), role, role)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := j.ParseToken(token)
		if err != nil {
			t.Fatal(err)
		}
		if err := tokens.SaveSession(claims.UserID, claims.ID, time.Hour); err != nil {
			t.Fatal(err)
		}
		roleTokens[role] = token
		w := request("GET", fmt.Sprintf("/api/v1/log-quarantine/%d", q.ID), token, nil)
		if apiCode(w) != 0 {
			t.Fatal("read role denied", role, w.Body.String())
		}
		if role != "admin" {
			w = request("POST", fmt.Sprintf("/api/v1/log-quarantine/%d/replay", q.ID), token, []byte(`{"reason":"test"}`))
			if apiCode(w) != 403 {
				t.Fatal("non-admin replay allowed", role, w.Body.String())
			}
		}
	}
	list := request("GET", "/api/v1/log-quarantine?status=pending", roleTokens["auditor"], nil)
	if apiCode(list) != 0 || strings.Contains(list.Body.String(), `"payload":`) {
		t.Fatal("list leaked raw payload", list.Body.String())
	}
	path := fmt.Sprintf("/api/v1/log-quarantine/%d/replay", q.ID)
	if w := request("POST", path, roleTokens["admin"], []byte(`{"reason":"invalid original"}`)); apiCode(w) != 400 {
		t.Fatal("invalid replay accepted", w.Body.String())
	}
	e := events.RequestEvent(&model.RequestLog{RequestID: "q-api-" + uuid.NewString(), Method: "GET"}, nil)
	body, _ := json.Marshal(map[string]any{"event": e, "reason": "restore API test event"})
	if w := request("POST", path, roleTokens["admin"], body); apiCode(w) != 0 {
		t.Fatal("valid replay rejected", w.Body.String())
	}
	if w := request("POST", path, roleTokens["admin"], body); apiCode(w) != 409 {
		t.Fatal("duplicate replay not rejected", w.Body.String())
	}
	t.Log("real JWT/session middleware: unauthenticated denied; three roles may read; only admin may replay; invalid=400, corrected=200, repeated=409")
}

func TestLogsRemainWhenAutomaticRetentionDisabled(t *testing.T) {
	db := quarantineDB(t)
	if config.GetConfig().Log.RetentionDays != 0 {
		t.Fatal("automatic deletion is enabled")
	}
	old := time.Now().AddDate(-1, 0, 0)
	r := model.RequestLog{RequestID: "retained-" + uuid.NewString(), CreatedAt: old}
	if err := db.Create(&r).Error; err != nil {
		t.Fatal(err)
	}
	match := model.RuleMatch{RequestLogID: r.ID, RuleID: "942100", CreatedAt: old}
	if err := db.Create(&match).Error; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := service.StartLogRetention(ctx)
	done := make(chan struct{})
	go func() { wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disabled retention worker did not exit")
	}
	if err := db.First(&r, r.ID).Error; err != nil {
		t.Fatal("old request deleted", err)
	}
	if err := db.First(&match, match.ID).Error; err != nil {
		t.Fatal("old rule evidence deleted", err)
	}
	t.Log("default automatic retention disabled; year-old request and rule evidence remain in PostgreSQL")
}
