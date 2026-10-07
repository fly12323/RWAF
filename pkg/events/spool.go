package events

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"github.com/fly12323/RWAF/internal/config"

	"github.com/segmentio/kafka-go"
)

// Each shard group-commits a segment before acknowledging Submit. A segment is
// removed only after Kafka acknowledges every message. A crash may replay a
// segment, which the database event IDs deduplicate. The spool stores exactly
// the captured event payload; its volume must follow the log access policy.
type diskPublisher struct {
	mu           sync.RWMutex
	closed       bool
	shards       []*spoolShard
	writer       messageWriter
	lock         *os.File
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	used         atomic.Int64
	queued       atomic.Int64
	accepted     atomic.Int64
	published    atomic.Int64
	dropped      atomic.Int64
	errors       atomic.Int64
	maxBytes     int64
	maxEvent     int
	batchSize    int
	syncInterval time.Duration
	sealInterval time.Duration
	recovered    int64
}

type spoolCommit struct {
	done chan struct{}
	err  error
}
type pendingSegment struct {
	file    *os.File
	path    string
	count   int
	created time.Time
	group   *spoolCommit
	dirty   bool
	err     error
}

type spoolShard struct {
	owner    *diskPublisher
	dir      string
	mu       sync.Mutex
	pending  *pendingSegment
	wake     chan struct{}
	sealDone chan struct{}
}

func openDiskPublisher(cfg config.KafkaConfig, writer messageWriter) (*diskPublisher, error) {
	if cfg.PublisherWorkers < 1 || cfg.BatchSize < 1 || cfg.SpoolMaxBytes <= 0 || cfg.SpoolSyncMs < 1 {
		return nil, errors.New("invalid disk publisher configuration")
	}
	if err := os.MkdirAll(cfg.SpoolDir, 0700); err != nil {
		return nil, err
	}
	lock, err := lockSpool(filepath.Join(cfg.SpoolDir, ".lock"))
	if err != nil {
		return nil, fmt.Errorf("spool already in use or inaccessible: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &diskPublisher{writer: writer, lock: lock, ctx: ctx, cancel: cancel, done: make(chan struct{}), maxBytes: cfg.SpoolMaxBytes, maxEvent: cfg.MaxEventBytes, batchSize: cfg.BatchSize, syncInterval: time.Duration(cfg.SpoolSyncMs) * time.Millisecond, sealInterval: time.Duration(cfg.FlushIntervalMs) * time.Millisecond}
	if p.sealInterval <= 0 {
		p.sealInterval = 200 * time.Millisecond
	}
	// Discover old shards too, so changing worker count never strands old data.
	for i := 0; i < cfg.PublisherWorkers; i++ {
		if err = os.MkdirAll(filepath.Join(cfg.SpoolDir, fmt.Sprintf("shard-%02d", i)), 0700); err != nil {
			cancel()
			lock.Close()
			return nil, err
		}
	}
	entries, err := os.ReadDir(cfg.SpoolDir)
	if err != nil {
		cancel()
		lock.Close()
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "shard-") {
			continue
		}
		s := &spoolShard{owner: p, dir: filepath.Join(cfg.SpoolDir, entry.Name()), wake: make(chan struct{}, 1), sealDone: make(chan struct{})}
		if err = s.recover(); err != nil {
			cancel()
			lock.Close()
			return nil, fmt.Errorf("recover %s: %w", entry.Name(), err)
		}
		p.shards = append(p.shards, s)
	}
	p.recovered = p.queued.Load()
	var wg sync.WaitGroup
	for _, s := range p.shards {
		wg.Add(2)
		go func(s *spoolShard) { defer wg.Done(); s.sealer() }(s)
		go func(s *spoolShard) { defer wg.Done(); s.publish() }(s)
	}
	go func() { wg.Wait(); writer.Close(); lock.Close(); close(p.done) }()
	return p, nil
}

func (s *spoolShard) recover() error {
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, file := range files {
		ext := filepath.Ext(file.Name())
		if ext != ".open" && ext != ".wal" {
			continue
		}
		path := filepath.Join(s.dir, file.Name())
		messages, size, err := readSegment(path, s.owner.maxEvent, ext == ".open")
		if err != nil {
			return err
		} // Never silently discard corrupt acknowledged data.
		if ext == ".open" {
			f, err := os.OpenFile(path, os.O_RDWR, 0600)
			if err != nil {
				return err
			}
			err = f.Truncate(size)
			if err == nil {
				err = f.Sync()
			}
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if len(messages) == 0 {
				if err = os.Remove(path); err != nil {
					return err
				}
				continue
			}
			if err = os.Rename(path, strings.TrimSuffix(path, ".open")+".wal"); err != nil {
				return err
			}
			if err = syncSpoolDir(s.dir); err != nil {
				return err
			}
		}
		s.owner.used.Add(size)
		s.owner.queued.Add(int64(len(messages)))
	}
	return nil
}

func readSegment(path string, maxEvent int, allowTail bool) ([]kafka.Message, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var messages []kafka.Message
	var size int64
	for {
		var header [8]byte
		n, err := io.ReadFull(f, header[:])
		if err == io.EOF && n == 0 {
			return messages, size, nil
		}
		if allowTail && (err == io.EOF || err == io.ErrUnexpectedEOF) {
			return messages, size, nil
		}
		if err != nil {
			return nil, size, err
		}
		length := int(binary.BigEndian.Uint32(header[:4]))
		if length < 1 || length > maxEvent {
			return nil, size, errors.New("invalid spool record length")
		}
		value := make([]byte, length)
		if _, err := io.ReadFull(f, value); err != nil {
			if allowTail && (err == io.EOF || err == io.ErrUnexpectedEOF) {
				return messages, size, nil
			}
			return nil, size, err
		}
		if crc32.ChecksumIEEE(value) != binary.BigEndian.Uint32(header[4:]) {
			return nil, size, errors.New("spool checksum mismatch")
		}
		var e Event
		if err := decodeEvent(value, &e); err != nil {
			return nil, size, err
		}
		messages = append(messages, kafka.Message{Key: []byte(e.ID), Value: value})
		size += int64(8 + length)
	}
}

func (p *diskPublisher) submit(key string, value []byte) error {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		p.dropped.Add(1)
		return errors.New("publisher closed")
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	s := p.shards[int(h.Sum32())%len(p.shards)]
	s.mu.Lock()
	needed := int64(8 + len(value))
	for {
		used := p.used.Load()
		if needed > p.maxBytes-used {
			s.mu.Unlock()
			p.mu.RUnlock()
			p.dropped.Add(1)
			return errors.New("durable event spool full")
		}
		if p.used.CompareAndSwap(used, used+needed) {
			break
		}
	}
	if s.pending == nil {
		f, err := os.CreateTemp(s.dir, fmt.Sprintf("%020d-*.open", time.Now().UnixNano()))
		if err != nil {
			p.used.Add(-needed)
			s.mu.Unlock()
			p.mu.RUnlock()
			p.dropped.Add(1)
			return err
		}
		if err := syncSpoolDir(s.dir); err != nil {
			f.Close()
			os.Remove(f.Name())
			p.used.Add(-needed)
			s.mu.Unlock()
			p.mu.RUnlock()
			p.dropped.Add(1)
			return err
		}
		s.pending = &pendingSegment{file: f, path: f.Name(), created: time.Now(), group: &spoolCommit{done: make(chan struct{})}}
	}
	segment := s.pending
	group := segment.group
	var header [8]byte
	binary.BigEndian.PutUint32(header[:4], uint32(len(value)))
	binary.BigEndian.PutUint32(header[4:], crc32.ChecksumIEEE(value))
	// A partial append is rolled back before any subsequent records are written.
	pos, err := segment.file.Seek(0, io.SeekCurrent)
	if err == nil {
		_, err = segment.file.Write(append(header[:], value...))
	}
	if err != nil {
		rollback := segment.file.Truncate(pos)
		_, seekErr := segment.file.Seek(pos, io.SeekStart)
		p.used.Add(-needed)
		if rollback != nil || seekErr != nil {
			segment.err = errors.Join(err, rollback, seekErr)
			s.sealLocked()
		}
		s.mu.Unlock()
		p.mu.RUnlock()
		p.dropped.Add(1)
		return err
	}
	segment.count++
	segment.dirty = true
	p.queued.Add(1)
	if segment.count >= p.batchSize {
		s.sealLocked()
	}
	s.mu.Unlock()
	p.mu.RUnlock()
	<-group.done // Group fsync only; never waits for Kafka or the database.
	if group.err != nil {
		p.errors.Add(1)
		p.dropped.Add(1)
		return group.err
	}
	p.accepted.Add(1)
	return nil
}

// Commit appended records in the same file. Directory fsync is needed only
// when creating/sealing/deleting a segment, not for every group commit.
func (s *spoolShard) commitLocked() {
	segment := s.pending
	if segment == nil || !segment.dirty {
		return
	}
	group := segment.group
	if segment.err == nil {
		segment.err = segment.file.Sync()
	}
	group.err = segment.err
	segment.dirty = false
	close(group.done)
	segment.group = &spoolCommit{done: make(chan struct{})}
}

func (s *spoolShard) sealLocked() {
	segment := s.pending
	if segment == nil {
		return
	}
	s.commitLocked()
	s.pending = nil
	err := errors.Join(segment.err, segment.file.Close())
	if err == nil {
		err = os.Rename(segment.path, strings.TrimSuffix(segment.path, ".open")+".wal")
	}
	if err == nil {
		err = syncSpoolDir(s.dir)
	}
	if err != nil {
		s.owner.errors.Add(1)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *spoolShard) sealer() {
	defer close(s.sealDone)
	ticker := time.NewTicker(s.owner.syncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			s.commitLocked()
			if s.pending != nil && time.Since(s.pending.created) >= s.owner.sealInterval {
				s.sealLocked()
			}
			s.mu.Unlock()
		case <-s.owner.ctx.Done():
			s.mu.Lock()
			s.sealLocked()
			s.mu.Unlock()
			return
		}
	}
}

func (s *spoolShard) publish() {
	p := s.owner
	var backlog []string
	for {
		if p.ctx.Err() != nil {
			return
		}
		if len(backlog) == 0 {
			files, err := filepath.Glob(filepath.Join(s.dir, "*.wal"))
			if err != nil {
				p.errors.Add(1)
				if !s.retry() {
					return
				}
				continue
			}
			sort.Strings(files)
			backlog = files
		}
		if len(backlog) == 0 {
			select {
			case <-p.ctx.Done():
				return
			case <-s.wake:
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		// Combine group-fsync segments into Kafka batches. Cache the directory
		// snapshot until drained instead of rescanning it for every acknowledged file.
		messages := make([]kafka.Message, 0, p.batchSize)
		sizes := []int64{}
		for _, path := range backlog {
			next, size, err := readSegment(path, p.maxEvent, false)
			if err != nil {
				p.errors.Add(1)
				break
			}
			if len(messages) > 0 && len(messages)+len(next) > p.batchSize {
				break
			}
			messages = append(messages, next...)
			sizes = append(sizes, size)
			if len(messages) >= p.batchSize {
				break
			}
		}
		if len(sizes) == 0 {
			if !s.retry() {
				return
			}
			continue
		}
		if err := p.writer.WriteMessages(p.ctx, messages...); err != nil {
			p.errors.Add(1)
			if !s.retry() {
				return
			}
			continue
		}
		removed := 0
		for i, size := range sizes {
			path := backlog[i]
			if err := os.Remove(path); err != nil {
				p.errors.Add(1)
				break
			}
			p.used.Add(-size)
			// Read count from records to account correctly if a deletion partially fails.
			count := 0
			bytes := int64(0)
			for count < len(messages) && bytes < size {
				bytes += int64(8 + len(messages[count].Value))
				count++
			}
			p.queued.Add(-int64(count))
			p.published.Add(int64(count))
			messages = messages[count:]
			removed++
		}
		if err := syncSpoolDir(s.dir); err != nil {
			p.errors.Add(1)
		}
		backlog = backlog[removed:]
		if removed < len(sizes) && !s.retry() {
			return
		}
	}
}

func (s *spoolShard) retry() bool {
	select {
	case <-s.owner.ctx.Done():
		return false
	case <-time.After(time.Second):
		return true
	}
}

func (p *diskPublisher) close(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	for _, s := range p.shards {
		s.mu.Lock()
		s.sealLocked()
		s.mu.Unlock()
	}
	p.mu.Unlock()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for p.queued.Load() > 0 {
		select {
		case <-ctx.Done():
			p.cancel()
			<-p.done // Workers respect cancellation; leave acknowledged segments for restart.
			return ctx.Err()
		case <-p.done:
			return ctx.Err()
		case <-ticker.C:
		}
	}
	p.cancel()
	<-p.done
	return nil
}

func (p *diskPublisher) stats() map[string]int64 {
	return map[string]int64{"accepted": p.accepted.Load(), "published": p.published.Load(), "dropped": p.dropped.Load(), "errors": p.errors.Load(), "queued": p.queued.Load(), "capacity": 0, "spool_bytes": p.used.Load(), "spool_capacity_bytes": p.maxBytes, "recovered": p.recovered, "publisher_workers": int64(len(p.shards)), "durable": 1}
}
