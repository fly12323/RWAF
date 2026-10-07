package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"

	"github.com/segmentio/kafka-go"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var consumedCount, lastPersist atomic.Int64
var consumerState atomic.Pointer[string]
var persistNanos, commitNanos, batches, fetchErrors atomic.Int64
var activeConsumers, retryingConsumers atomic.Int64

func setConsumerState(s string) { consumerState.Store(&s) }
func ConsumerStats() map[string]any {
	state := "starting"
	if s := consumerState.Load(); s != nil {
		state = *s
	}
	if activeConsumers.Load() > 0 {
		state = "running"
	}
	if retryingConsumers.Load() > 0 {
		state = "retrying"
	}
	return map[string]any{"state": state, "workers": activeConsumers.Load(), "retrying_workers": retryingConsumers.Load(), "persisted": consumedCount.Load(), "last_persist_at": lastPersist.Load(), "batches": batches.Load(), "persist_ms": persistNanos.Load() / int64(time.Millisecond), "commit_ms": commitNanos.Load() / int64(time.Millisecond), "fetch_errors": fetchErrors.Load()}
}

// Independent group members distribute partitions. Never share one reader
// between concurrent batches: committing a later offset could skip an earlier
// failed transaction in the same partition.
func ConsumeGroup(ctx context.Context, db *gorm.DB, cfg config.KafkaConfig) error {
	g, ctx := errgroup.WithContext(ctx)
	workers := cfg.ConsumerWorkers
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		g.Go(func() error { return Consume(ctx, db, cfg) })
	}
	return g.Wait()
}

// PersistBatch deduplicates and writes each batch in one PostgreSQL transaction.
func PersistBatch(ctx context.Context, db *gorm.DB, batch []Event) error {
	for i := range batch {
		if err := batch[i].Validate(); err != nil {
			return err
		}
	}
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(batch) == 0 {
			return nil
		}
		// Claim the entire batch with one round trip, and retain only events
		// actually inserted. Claims and logs still share the same transaction.
		values := make([]string, 0, len(batch))
		args := make([]any, 0, len(batch)*2)
		seen := make(map[string]bool)
		for _, e := range batch {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			values = append(values, "(?, ?)")
			args = append(args, e.ID, time.Now())
		}
		var inserted []struct{ EventID string }
		if err := tx.Raw("INSERT INTO processed_events (event_id, created_at) VALUES "+strings.Join(values, ",")+" ON CONFLICT (event_id) DO NOTHING RETURNING event_id", args...).Scan(&inserted).Error; err != nil {
			return err
		}
		claimed := make(map[string]bool, len(inserted))
		for _, row := range inserted {
			claimed[row.EventID] = true
		}
		requests := make([]model.RequestLog, 0, len(batch))
		crawlers := make([]model.CrawlerLog, 0, len(batch))
		weak := make([]model.WeakPasswordEvent, 0)
		details := make(map[string][]model.RuleMatch)
		for _, e := range batch {
			if !claimed[e.ID] {
				continue
			}
			delete(claimed, e.ID)
			if e.Request != nil {
				r := *e.Request
				r.ID = 0
				requests = append(requests, r)
				details[r.RequestID] = e.Matches
			} else if e.Crawler != nil {
				r := *e.Crawler
				r.ID = 0
				crawlers = append(crawlers, r)
			} else {
				r := *e.Weak
				r.ID = 0
				weak = append(weak, r)
			}
		}
		if len(requests) > 0 {
			if err := tx.CreateInBatches(&requests, 100).Error; err != nil {
				return err
			}
			matches := make([]model.RuleMatch, 0)
			for _, r := range requests {
				for _, m := range details[r.RequestID] {
					m.ID = 0
					m.RequestLogID = r.ID
					m.CreatedAt = r.CreatedAt
					matches = append(matches, m)
				}
			}
			if len(matches) > 0 {
				if err := tx.CreateInBatches(&matches, 100).Error; err != nil {
					return err
				}
			}
		}
		if len(crawlers) > 0 {
			if err := tx.CreateInBatches(&crawlers, 100).Error; err != nil {
				return err
			}
		}
		if len(weak) > 0 {
			if err := tx.CreateInBatches(&weak, 100).Error; err != nil {
				return err
			}
			// Consistent endpoint lock order prevents cross-worker deadlocks.
			sort.Slice(weak, func(i, j int) bool {
				return fmt.Sprintf("weak:%d:%s", weak[i].SiteID, weak[i].Endpoint) < fmt.Sprintf("weak:%d:%s", weak[j].SiteID, weak[j].Endpoint)
			})
			for _, w := range weak {
				// One pending alert per endpoint/site; repeated matches increment it.
				key := fmt.Sprintf("weak:%d:%s", w.SiteID, w.Endpoint)
				if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", key).Error; err != nil {
					return err
				}
				var alert model.Alert
				err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("key = ? AND status = ?", key, "open").First(&alert).Error
				if errors.Is(err, gorm.ErrRecordNotFound) {
					alert = model.Alert{Key: key, Source: "weak_password", Severity: "warning", Message: fmt.Sprintf("站点 %d 接口 %s 检测到弱密码提交，登录结果未知", w.SiteID, w.Endpoint), Status: "open", Occurrences: 1, CreatedAt: w.CreatedAt, LastSeen: w.CreatedAt}
					if err := tx.Create(&alert).Error; err != nil {
						return err
					}
				} else if err != nil {
					return err
				} else if err := tx.Model(&alert).Updates(map[string]any{"occurrences": gorm.Expr("occurrences + 1"), "last_seen": gorm.Expr("GREATEST(last_seen, ?)", w.CreatedAt)}).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func Consume(ctx context.Context, db *gorm.DB, cfg config.KafkaConfig) (err error) {
	activeConsumers.Add(1)
	retrying := false
	setState := func(state string) {
		if (state == "retrying") != retrying {
			if state == "retrying" {
				retryingConsumers.Add(1)
			} else {
				retryingConsumers.Add(-1)
			}
			retrying = state == "retrying"
		}
		setConsumerState(state)
	}
	setState("running")
	defer func() { setState("stopped"); activeConsumers.Add(-1) }()
	defer func() {
		// Cancellation leaves offsets uncommitted so a restart replays the batch.
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			err = nil
		}
	}()
	r := kafka.NewReader(kafka.ReaderConfig{Brokers: cfg.Brokers, Topic: cfg.Topic, GroupID: cfg.GroupID,
		MinBytes: 1, MaxBytes: 1048576, MaxWait: 200 * time.Millisecond,
		QueueCapacity: cfg.BatchSize, CommitInterval: 0, StartOffset: kafka.FirstOffset})
	defer r.Close()
	batch := make([]Event, 0, cfg.BatchSize)
	messages := make([]kafka.Message, 0, cfg.BatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		for {
			started := time.Now()
			writeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := PersistBatch(writeCtx, db, batch)
			cancel()
			persistNanos.Add(int64(time.Since(started)))
			if err == nil {
				break
			}
			log.Printf("log batch failed; offsets remain uncommitted: %v", err)
			setState("retrying")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
		for {
			started := time.Now()
			commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := r.CommitMessages(commitCtx, messages...)
			cancel()
			commitNanos.Add(int64(time.Since(started)))
			if err == nil {
				break
			}
			setState("retrying")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
		log.Printf("persisted batch: events=%d", len(batch))
		consumedCount.Add(int64(len(batch)))
		batches.Add(1)
		lastPersist.Store(time.Now().Unix())
		setState("running")
		batch = batch[:0]
		messages = messages[:0]
		return nil
	}
	deadline := time.Now().Add(time.Duration(cfg.FlushIntervalMs) * time.Millisecond)
	for {
		fetchCtx, cancel := context.WithDeadline(ctx, deadline)
		msg, err := r.FetchMessage(fetchCtx)
		cancel()
		if ctx.Err() != nil {
			return nil
		} // uncommitted messages are replayed on restart
		if errors.Is(err, context.DeadlineExceeded) {
			if err := flush(); err != nil {
				return err
			}
			deadline = time.Now().Add(time.Duration(cfg.FlushIntervalMs) * time.Millisecond)
			continue
		}
		if err != nil {
			fetchErrors.Add(1)
			setState("retrying")
			log.Printf("Kafka fetch failed; retrying without committing: %v", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			deadline = time.Now().Add(time.Duration(cfg.FlushIntervalMs) * time.Millisecond)
			continue
		}
		var e Event
		if len(msg.Value) > cfg.MaxEventBytes {
			return fmt.Errorf("oversized event at partition=%d offset=%d", msg.Partition, msg.Offset)
		}
		if err := json.Unmarshal(msg.Value, &e); err != nil {
			return fmt.Errorf("invalid event partition=%d offset=%d: %w", msg.Partition, msg.Offset, err)
		}
		if err := e.Validate(); err != nil {
			return fmt.Errorf("invalid event partition=%d offset=%d: %w", msg.Partition, msg.Offset, err)
		}
		setState("running")
		batch = append(batch, e)
		messages = append(messages, msg)
		if len(batch) >= cfg.BatchSize {
			if err := flush(); err != nil {
				return err
			}
			deadline = time.Now().Add(time.Duration(cfg.FlushIntervalMs) * time.Millisecond)
		}
	}
}
