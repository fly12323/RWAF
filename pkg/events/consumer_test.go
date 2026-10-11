package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/segmentio/kafka-go"
)

type scriptedReader struct {
	messages []kafka.Message
	next     int
	commit   func(...kafka.Message) error
}

func (r *scriptedReader) FetchMessage(ctx context.Context) (kafka.Message, error) {
	if r.next < len(r.messages) {
		m := r.messages[r.next]
		r.next++
		return m, nil
	}
	<-ctx.Done()
	return kafka.Message{}, ctx.Err()
}
func (r *scriptedReader) CommitMessages(_ context.Context, msgs ...kafka.Message) error {
	return r.commit(msgs...)
}
func testMessage(t *testing.T, offset int64) kafka.Message {
	t.Helper()
	b, err := json.Marshal(RequestEvent(&model.RequestLog{RequestID: fmt.Sprint(offset)}, nil))
	if err != nil {
		t.Fatal(err)
	}
	return kafka.Message{Topic: "test", Partition: 0, Offset: offset, Value: b}
}

func TestQuarantineCommitsOnlyAfterValidPrefixAndDurableIsolation(t *testing.T) {
	for name, payload := range map[string][]byte{"json": []byte("{"), "version": []byte(`{"version":99,"id":"bad"}`), "oversized": []byte(strings.Repeat("x", 1025))} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bad := kafka.Message{Topic: "test", Partition: 0, Offset: 1, Value: payload}
			steps := []string{}
			r := &scriptedReader{messages: []kafka.Message{testMessage(t, 0), bad, testMessage(t, 2)}}
			r.commit = func(msgs ...kafka.Message) error {
				for _, m := range msgs {
					steps = append(steps, fmt.Sprintf("commit:%d", m.Offset))
					if m.Offset == 2 {
						cancel()
					}
				}
				return nil
			}
			err := consumeMessages(ctx, config.KafkaConfig{BatchSize: 1, FlushIntervalMs: 10, MaxEventBytes: 1024}, r,
				func(_ context.Context, batch []Event) error {
					for _, e := range batch {
						steps = append(steps, "persist:"+e.Request.RequestID)
					}
					return nil
				},
				func(_ context.Context, m kafka.Message, reason error) error {
					if !reflect.DeepEqual(m.Value, payload) || reason == nil {
						t.Fatal("lost evidence")
					}
					steps = append(steps, "quarantine:1")
					return nil
				}, func(string) {})
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			want := []string{"persist:0", "commit:0", "quarantine:1", "commit:1", "persist:2", "commit:2"}
			if !reflect.DeepEqual(steps, want) {
				t.Fatalf("steps=%v want=%v", steps, want)
			}
		})
	}
}

func TestQuarantineFlushesUncommittedBatchAndRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	steps := []string{}
	r := &scriptedReader{messages: []kafka.Message{testMessage(t, 0), {Topic: "test", Offset: 1, Value: []byte("{")}, testMessage(t, 2)}}
	r.commit = func(msgs ...kafka.Message) error {
		for _, m := range msgs {
			steps = append(steps, fmt.Sprintf("commit:%d", m.Offset))
			if m.Offset == 2 {
				cancel()
			}
		}
		return nil
	}
	attempts := 0
	err := consumeMessages(ctx, config.KafkaConfig{BatchSize: 10, FlushIntervalMs: 10, MaxEventBytes: 1024}, r,
		func(_ context.Context, batch []Event) error {
			for _, e := range batch {
				steps = append(steps, "persist:"+e.Request.RequestID)
			}
			return nil
		},
		func(context.Context, kafka.Message, error) error {
			attempts++
			steps = append(steps, "isolate")
			if attempts == 1 {
				return errors.New("database unavailable")
			}
			return nil
		}, func(string) {})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	want := []string{"persist:0", "commit:0", "isolate", "isolate", "commit:1", "persist:2", "commit:2"}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("unsafe ordering: %v", steps)
	}
}

func TestFailedQuarantineNeverCommitsOffset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	commits := 0
	r := &scriptedReader{messages: []kafka.Message{{Topic: "test", Offset: 7, Value: []byte("{")}}}
	r.commit = func(...kafka.Message) error { commits++; return nil }
	err := consumeMessages(ctx, config.KafkaConfig{BatchSize: 10, FlushIntervalMs: 10, MaxEventBytes: 1024}, r,
		func(context.Context, []Event) error { t.Fatal("invalid event persisted"); return nil },
		func(context.Context, kafka.Message, error) error { cancel(); return errors.New("database unavailable") }, func(string) {})
	if !errors.Is(err, context.Canceled) || commits != 0 {
		t.Fatalf("err=%v commits=%d", err, commits)
	}
}

func TestQuarantineCommitRetryDoesNotFetchAhead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	commits, isolated := 0, 0
	r := &scriptedReader{messages: []kafka.Message{{Topic: "test", Offset: 7, Value: []byte("{")}, testMessage(t, 8)}}
	r.commit = func(msgs ...kafka.Message) error {
		commits++
		if commits == 1 {
			return errors.New("broker unavailable")
		}
		if msgs[0].Offset == 7 && r.next != 1 {
			t.Fatal("fetched ahead before quarantine commit")
		}
		if msgs[0].Offset == 8 {
			cancel()
		}
		return nil
	}
	err := consumeMessages(ctx, config.KafkaConfig{BatchSize: 1, FlushIntervalMs: 10, MaxEventBytes: 1024}, r, func(context.Context, []Event) error { return nil }, func(context.Context, kafka.Message, error) error { isolated++; return nil }, func(string) {})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if isolated != 1 || commits != 3 {
		t.Fatalf("isolated=%d commits=%d", isolated, commits)
	}
}

type testSQLFailure string

func (e testSQLFailure) Error() string    { return string(e) }
func (e testSQLFailure) SQLState() string { return string(e) }

func TestBadDatabaseRowIsolatedWithoutLosingBatchNeighbours(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	steps := []string{}
	r := &scriptedReader{messages: []kafka.Message{testMessage(t, 0), testMessage(t, 1), testMessage(t, 2)}}
	r.commit = func(msgs ...kafka.Message) error {
		for _, m := range msgs {
			steps = append(steps, fmt.Sprintf("commit:%d", m.Offset))
		}
		cancel()
		return nil
	}
	err := consumeMessages(ctx, config.KafkaConfig{BatchSize: 3, FlushIntervalMs: 10, MaxEventBytes: 1024}, r,
		func(_ context.Context, batch []Event) error {
			if len(batch) > 1 {
				steps = append(steps, "batch-rollback")
				return testSQLFailure("22001")
			}
			id := batch[0].Request.RequestID
			if id == "1" {
				return testSQLFailure("22001")
			}
			steps = append(steps, "persist:"+id)
			return nil
		},
		func(_ context.Context, m kafka.Message, _ error) error {
			steps = append(steps, fmt.Sprintf("quarantine:%d", m.Offset))
			return nil
		}, func(string) {})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	want := []string{"batch-rollback", "persist:0", "quarantine:1", "persist:2", "commit:0", "commit:1", "commit:2"}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("lost/skipped batch neighbours: %v", steps)
	}
}

func TestTransientDatabaseErrorNeverQuarantinesValidRows(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &scriptedReader{messages: []kafka.Message{testMessage(t, 0)}}
	r.commit = func(...kafka.Message) error { t.Fatal("failed write committed"); return nil }
	err := consumeMessages(ctx, config.KafkaConfig{BatchSize: 1, FlushIntervalMs: 10, MaxEventBytes: 1024}, r,
		func(context.Context, []Event) error { cancel(); return testSQLFailure("08006") },
		func(context.Context, kafka.Message, error) error {
			t.Fatal("transient outage quarantined a valid event")
			return nil
		}, func(string) {})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, state := range []string{"08006", "40001", "40P01", "42P01", "57014"} {
		if permanentEventError(testSQLFailure(state)) {
			t.Fatal("retryable infrastructure error classified as event failure", state)
		}
	}
}
