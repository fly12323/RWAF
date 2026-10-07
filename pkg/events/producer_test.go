package events

import (
	"context"
	"encoding/json"
	"github.com/segmentio/kafka-go"
	"strings"
	"sync"
	"testing"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"
)

type blockingWriter struct {
	started  chan struct{}
	release  chan struct{}
	once     sync.Once
	messages []kafka.Message
}

func (w *blockingWriter) WriteMessages(ctx context.Context, msgs ...kafka.Message) error {
	w.once.Do(func() { close(w.started) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.release:
	}
	w.messages = append(w.messages, msgs...)
	return nil
}
func (w *blockingWriter) Close() error { return nil }

func TestBoundedQueueSnapshotAndDrain(t *testing.T) {
	w := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	p := newPublisher(config.KafkaConfig{QueueSize: 1, BatchSize: 1, FlushIntervalMs: 10, MaxEventBytes: 4096}, w)
	r := &model.RequestLog{RequestID: "first", URI: "original"}
	if err := p.Submit(RequestEvent(r, nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	r.URI = "mutated"
	if err := p.Submit(RequestEvent(&model.RequestLog{RequestID: "second"}, nil)); err != nil {
		t.Fatal(err)
	}
	if err := p.Submit(RequestEvent(&model.RequestLog{RequestID: "third"}, nil)); err == nil {
		t.Fatal("full queue accepted an event")
	}
	close(w.release)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(ctx); err != nil {
		t.Fatal("close is not idempotent", err)
	}
	if len(w.messages) != 2 {
		t.Fatalf("drained %d messages", len(w.messages))
	}
	var e Event
	if err := json.Unmarshal(w.messages[0].Value, &e); err != nil {
		t.Fatal(err)
	}
	if e.Request.URI != "original" {
		t.Fatal("queued log was mutated")
	}
	if err := p.Submit(RequestEvent(&model.RequestLog{RequestID: "late"}, nil)); err == nil {
		t.Fatal("closed queue accepted event")
	}
	if p.Stats()["published"] != 2 || p.Stats()["dropped"] != 2 {
		t.Fatal(p.Stats())
	}
}

func TestOversizedEventRejected(t *testing.T) {
	w := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	close(w.release)
	p := newPublisher(config.KafkaConfig{QueueSize: 1, BatchSize: 1, FlushIntervalMs: 10, MaxEventBytes: 100}, w)
	if err := p.Submit(RequestEvent(&model.RequestLog{RequestID: "large", Body: strings.Repeat("x", 200)}, nil)); err == nil {
		t.Fatal("oversized event accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
