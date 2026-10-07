package events

import (
	"context"
	"fmt"
	"github.com/segmentio/kafka-go"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"
)

type durableWriter struct {
	mu       sync.Mutex
	messages []kafka.Message
	blocked  bool
}

func (w *durableWriter) WriteMessages(ctx context.Context, msgs ...kafka.Message) error {
	if w.blocked {
		<-ctx.Done()
		return ctx.Err()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.messages = append(w.messages, msgs...)
	return nil
}
func (w *durableWriter) Close() error { return nil }
func spoolConfig(dir string) config.KafkaConfig {
	return config.KafkaConfig{SpoolDir: dir, SpoolMaxBytes: 32 << 20, SpoolSyncMs: 2, PublisherWorkers: 3, BatchSize: 100, MaxEventBytes: 4096}
}
func diskTestPublisher(t *testing.T, cfg config.KafkaConfig, w messageWriter) *Publisher {
	t.Helper()
	disk, err := openDiskPublisher(cfg, w)
	if err != nil {
		t.Fatal(err)
	}
	return &Publisher{disk: disk, maxBytes: cfg.MaxEventBytes}
}
func TestSpoolConcurrentPublishAndExclusiveOwnership(t *testing.T) {
	cfg := spoolConfig(t.TempDir())
	w := &durableWriter{}
	p := diskTestPublisher(t, cfg, w)
	if _, err := openDiskPublisher(cfg, &durableWriter{}); err == nil {
		t.Fatal("two publishers acquired one spool")
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := p.Submit(RequestEvent(&model.RequestLog{RequestID: fmt.Sprintf("%d-%d", worker, i)}, nil)); err != nil {
					t.Error(err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(ctx); err != nil {
		t.Fatal("idempotent close", err)
	}
	if p.Stats()["published"] != 3200 || p.Stats()["queued"] != 0 || p.Stats()["spool_bytes"] != 0 || p.Stats()["dropped"] != 0 {
		t.Fatal(p.Stats())
	}
	seen := map[string]bool{}
	for _, msg := range w.messages {
		if seen[string(msg.Key)] {
			t.Fatal("duplicate publish")
		}
		seen[string(msg.Key)] = true
	}
}

func TestSpoolSurvivesProcessExit(t *testing.T) {
	if dir := os.Getenv("WAF_SPOOL_CRASH_HELPER"); dir != "" {
		p := diskTestPublisher(t, spoolConfig(dir), &durableWriter{blocked: true})
		for i := 0; i < 50; i++ {
			if err := p.Submit(RequestEvent(&model.RequestLog{RequestID: fmt.Sprintf("crash-%d", i)}, nil)); err != nil {
				t.Fatal(err)
			}
		}
		os.Exit(0) // Deliberately no Close: kernel closes locks, WAL remains.
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSpoolSurvivesProcessExit$")
	cmd.Env = append(os.Environ(), "WAF_SPOOL_CRASH_HELPER="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}
	p := diskTestPublisher(t, spoolConfig(dir), &durableWriter{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if p.Stats()["recovered"] != 50 || p.Stats()["published"] != 50 {
		t.Fatal(p.Stats())
	}
}

func TestSpoolCapacityAndRecoveryAfterShutdownTimeout(t *testing.T) {
	cfg := spoolConfig(t.TempDir())
	cfg.SpoolMaxBytes = 800
	p := diskTestPublisher(t, cfg, &durableWriter{blocked: true})
	accepted := 0
	for i := 0; i < 30; i++ {
		if err := p.Submit(RequestEvent(&model.RequestLog{RequestID: fmt.Sprintf("capacity-%d", i)}, nil)); err == nil {
			accepted++
		}
	}
	if accepted == 0 || p.Stats()["dropped"] == 0 || p.Stats()["spool_bytes"] > 800 {
		t.Fatal(p.Stats())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.Close(ctx); err == nil {
		t.Fatal("expected timeout during Kafka outage")
	}
	p = diskTestPublisher(t, cfg, &durableWriter{})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if err := p.Close(ctx2); err != nil {
		t.Fatal(err)
	}
	if p.Stats()["published"] != int64(accepted) {
		t.Fatal(p.Stats())
	}
}

func TestSpoolTailRecoveryAndCorruptionRefusal(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprint(corrupt), func(t *testing.T) {
			cfg := spoolConfig(t.TempDir())
			p := diskTestPublisher(t, cfg, &durableWriter{blocked: true})
			if err := p.Submit(RequestEvent(&model.RequestLog{RequestID: "tail"}, nil)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			_ = p.Close(ctx)
			files, _ := filepath.Glob(filepath.Join(cfg.SpoolDir, "shard-*", "*.wal"))
			if len(files) != 1 {
				t.Fatal(files)
			}
			bytes, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			if corrupt {
				bytes[len(bytes)-1] ^= 1
				if err := os.WriteFile(files[0], bytes, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := openDiskPublisher(cfg, &durableWriter{}); err == nil {
					t.Fatal("corrupt data was silently accepted")
				}
				return
			}
			open := files[0][:len(files[0])-4] + ".open"
			if err := os.Rename(files[0], open); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(open, append(bytes, 0, 0, 0), 0600); err != nil {
				t.Fatal(err)
			}
			p = diskTestPublisher(t, cfg, &durableWriter{})
			ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
			defer cancel2()
			if err := p.Close(ctx2); err != nil {
				t.Fatal(err)
			}
			if p.Stats()["published"] != 1 {
				t.Fatal(p.Stats())
			}
		})
	}
}

func BenchmarkDurableSubmit(b *testing.B) {
	cfg := spoolConfig(b.TempDir())
	disk, err := openDiskPublisher(cfg, &durableWriter{})
	if err != nil {
		b.Fatal(err)
	}
	p := &Publisher{disk: disk, maxBytes: cfg.MaxEventBytes}
	value := RequestEvent(&model.RequestLog{RequestID: "benchmark"}, nil)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := p.Submit(value); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.StopTimer()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = p.Close(ctx)
}
