package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
	"github.com/fly12323/RWAF/internal/config"

	"github.com/segmentio/kafka-go"
)

type messageWriter interface {
	WriteMessages(context.Context, ...kafka.Message) error
	Close() error
}

// Publisher owns one bounded queue and worker. Submit never waits for Kafka.
type Publisher struct {
	disk      *diskPublisher
	writer    messageWriter
	queue     chan kafka.Message
	mu        sync.RWMutex
	closed    bool
	cancel    context.CancelFunc
	done      chan struct{}
	batchSize int
	interval  time.Duration
	maxBytes  int
	accepted  atomic.Int64
	dropped   atomic.Int64
	published atomic.Int64
	errors    atomic.Int64
}

var active atomic.Pointer[Publisher]
var lastWarning atomic.Int64

func Stats() map[string]int64 {
	if p := active.Load(); p != nil {
		return p.Stats()
	}
	return map[string]int64{}
}

func SetPublisher(p *Publisher) { active.Store(p) }

func Publish(e Event) error {
	p := active.Load()
	if p == nil {
		return errors.New("event publisher is not initialized")
	}
	err := p.Submit(e)
	if err != nil {
		now := time.Now().Unix()
		last := lastWarning.Load()
		if now-last >= 5 && lastWarning.CompareAndSwap(last, now) {
			log.Printf("event not queued: %v; pipeline=%v", err, p.Stats())
		}
	}
	return err
}

func NewPublisher(cfg config.KafkaConfig) *Publisher {
	p, err := OpenPublisher(cfg)
	if err != nil {
		panic(err)
	}
	return p
}

// OpenPublisher fails startup on inaccessible/corrupt spool instead of silently
// falling back to lossy memory. Empty SpoolDir preserves the test-only queue.
func OpenPublisher(cfg config.KafkaConfig) (*Publisher, error) {
	w := &kafka.Writer{Addr: kafka.TCP(cfg.Brokers...), Topic: cfg.Topic,
		Balancer: &kafka.Hash{}, RequiredAcks: kafka.RequireAll,
		// The publisher already collects batches. A second full flush interval
		// here stalls every partial partition batch in synchronous WriteMessages.
		BatchSize: cfg.BatchSize, BatchTimeout: time.Millisecond,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxAttempts: 3}
	if cfg.SpoolDir != "" {
		disk, err := openDiskPublisher(cfg, w)
		if err != nil {
			w.Close()
			return nil, err
		}
		return &Publisher{disk: disk, maxBytes: cfg.MaxEventBytes}, nil
	}
	return newPublisher(cfg, w), nil
}

func newPublisher(cfg config.KafkaConfig, writer messageWriter) *Publisher {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Publisher{writer: writer, queue: make(chan kafka.Message, cfg.QueueSize),
		cancel: cancel, done: make(chan struct{}), batchSize: cfg.BatchSize,
		interval: time.Duration(cfg.FlushIntervalMs) * time.Millisecond, maxBytes: cfg.MaxEventBytes}
	go p.run(ctx)
	return p
}

func (p *Publisher) Submit(e Event) error {
	if err := e.Validate(); err != nil {
		p.recordDrop()
		return err
	}
	data, err := json.Marshal(e)
	if err != nil || len(data) > p.maxBytes {
		p.recordDrop()
		return fmt.Errorf("event exceeds serialization limit (%d bytes): %v", len(data), err)
	}
	if p.disk != nil {
		return p.disk.submit(e.ID, data)
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		p.dropped.Add(1)
		return errors.New("publisher closed")
	}
	select {
	case p.queue <- kafka.Message{Key: []byte(e.ID), Value: data}:
		p.accepted.Add(1)
		return nil
	default:
		p.dropped.Add(1)
		return errors.New("event queue full")
	}
}

func (p *Publisher) run(ctx context.Context) {
	defer close(p.done)
	defer p.writer.Close()
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	batch := make([]kafka.Message, 0, p.batchSize)
	flush := func() bool {
		if len(batch) == 0 {
			return true
		}
		for {
			err := p.writer.WriteMessages(ctx, batch...)
			if err == nil {
				p.published.Add(int64(len(batch)))
				batch = batch[:0]
				return true
			}
			p.errors.Add(1)
			log.Printf("Kafka publish failed; retrying %d events: %v", len(batch), err)
			select {
			case <-ctx.Done():
				return false
			case <-time.After(time.Second):
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-p.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, msg)
			if len(batch) >= p.batchSize && !flush() {
				return
			}
		case <-ticker.C:
			if !flush() {
				return
			}
		}
	}
}

func (p *Publisher) Close(ctx context.Context) error {
	if p.disk != nil {
		return p.disk.close(ctx)
	}
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.queue)
	}
	p.mu.Unlock()
	select {
	case <-p.done:
		p.cancel()
		return nil
	case <-ctx.Done():
		p.cancel()
		return ctx.Err()
	}
}

func (p *Publisher) Stats() map[string]int64 {
	if p.disk != nil {
		return p.disk.stats()
	}
	return map[string]int64{"accepted": p.accepted.Load(), "published": p.published.Load(),
		"dropped": p.dropped.Load(), "errors": p.errors.Load(), "queued": int64(len(p.queue)),
		"capacity": int64(cap(p.queue))}
}

func (p *Publisher) recordDrop() {
	if p.disk != nil {
		p.disk.dropped.Add(1)
	} else {
		p.dropped.Add(1)
	}
}

func decodeEvent(value []byte, e *Event) error {
	if err := json.Unmarshal(value, e); err != nil {
		return err
	}
	return e.Validate()
}

func EnsureTopic(ctx context.Context, cfg config.KafkaConfig) error {
	conn, err := kafka.DialContext(ctx, "tcp", cfg.Brokers[0])
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	parts, err := conn.ReadPartitions(cfg.Topic)
	if err != nil {
		return err
	}
	if len(parts) == 0 {
		return fmt.Errorf("Kafka topic %s is not ready; create it before starting", cfg.Topic)
	}
	return nil
}
