package events

import (
	"context"
	"errors"
	"fmt"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"
	"log"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var consumedCount, lastPersist, quarantinedCount atomic.Int64
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
	return map[string]any{"state": state, "workers": activeConsumers.Load(), "retrying_workers": retryingConsumers.Load(), "persisted": consumedCount.Load(), "quarantined": quarantinedCount.Load(), "last_persist_at": lastPersist.Load(), "batches": batches.Load(), "persist_ms": persistNanos.Load() / int64(time.Millisecond), "commit_ms": commitNanos.Load() / int64(time.Millisecond), "fetch_errors": fetchErrors.Load()}
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
	return consumeMessages(ctx, cfg, r,
		func(ctx context.Context, batch []Event) error { return PersistBatch(ctx, db, batch) },
		func(ctx context.Context, msg kafka.Message, reason error) error {
			return QuarantineMessage(ctx, db, cfg, msg, reason)
		}, setState)
}

type messageReader interface {
	FetchMessage(context.Context) (kafka.Message, error)
	CommitMessages(context.Context, ...kafka.Message) error
}

func consumeMessages(ctx context.Context, cfg config.KafkaConfig, r messageReader,
	persist func(context.Context, []Event) error,
	quarantine func(context.Context, kafka.Message, error) error, setState func(string)) error {
	retry := func(timeout time.Duration, operation func(context.Context) error) error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			attempt, cancel := context.WithTimeout(ctx, timeout)
			err := operation(attempt)
			cancel()
			if err == nil {
				return nil
			}
			log.Printf("log consumer operation failed; offsets remain uncommitted: %v", err)
			setState("retrying")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	commit := func(messages []kafka.Message) error {
		return retry(5*time.Second, func(ctx context.Context) error {
			started := time.Now()
			err := r.CommitMessages(ctx, messages...)
			commitNanos.Add(int64(time.Since(started)))
			return err
		})
	}
	batch := make([]Event, 0, cfg.BatchSize)
	messages := make([]kafka.Message, 0, cfg.BatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		isolatedBatch := 0
		if err := retry(15*time.Second, func(writeCtx context.Context) error {
			isolatedBatch = 0
			started := time.Now()
			err := persist(writeCtx, batch)
			persistNanos.Add(int64(time.Since(started)))
			if permanentEventError(err) {
				// A rolled-back batch does not identify its bad row. Retry events
				// individually, isolating only durable data/constraint failures.
				for i, event := range batch {
					if err := retry(15*time.Second, func(ctx context.Context) error {
						err := persist(ctx, []Event{event})
						if permanentEventError(err) {
							if err := quarantine(ctx, messages[i], err); err != nil {
								return err
							}
							isolatedBatch++
							return nil
						}
						return err
					}); err != nil {
						return err
					}
				}
				return nil
			}
			return err
		}); err != nil {
			return err
		}
		if err := commit(messages); err != nil {
			return err
		}
		log.Printf("persisted batch: events=%d", len(batch))
		consumedCount.Add(int64(len(batch) - isolatedBatch))
		quarantinedCount.Add(int64(isolatedBatch))
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
		e, decodeErr := DecodeEvent(msg.Value, cfg.MaxEventBytes)
		if decodeErr != nil {
			// Commit the valid prefix first; committing this later offset must
			// never skip previously fetched but unpersisted events.
			if err := flush(); err != nil {
				return err
			}
			if err := retry(15*time.Second, func(ctx context.Context) error { return quarantine(ctx, msg, decodeErr) }); err != nil {
				return err
			}
			if err := commit([]kafka.Message{msg}); err != nil {
				return err
			}
			quarantinedCount.Add(1)
			log.Printf("quarantined log event partition=%d offset=%d", msg.Partition, msg.Offset)
			setState("running")
			deadline = time.Now().Add(time.Duration(cfg.FlushIntervalMs) * time.Millisecond)
			continue
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
