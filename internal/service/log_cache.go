package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"golang.org/x/sync/singleflight"
	"sync"
	"time"
)

var logCache = struct {
	sync.Mutex
	entries map[string]cachedLogValue
	flight  singleflight.Group
}{entries: map[string]cachedLogValue{}}

type cachedLogValue struct {
	data    []byte
	expires time.Time
}

func logCacheTTL() time.Duration {
	if c := config.GetConfig(); c != nil {
		return time.Duration(c.Log.StatisticsCacheSeconds) * time.Second
	}
	return 0
}

func logRangeKey(t *time.Time) string {
	if t == nil {
		return "*"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// Cache immutable JSON so callers cannot change shared results. Cap cardinality
// and coalesce concurrent misses from dashboard users. Failed queries are never cached.
func cachedLogQuery[T any](key string, query func() (T, error)) (T, error) {
	return cachedLogQueryContext(context.Background(), key, query)
}

func cachedLogQueryContext[T any](ctx context.Context, key string, query func() (T, error)) (T, error) {
	if err := ctx.Err(); err != nil {
		var zero T
		return zero, err
	}
	ttl := logCacheTTL()
	if ttl <= 0 {
		return query()
	}
	key = fmt.Sprintf("%p:%s", dao.GetDB(), key)
	lookup := func() []byte {
		logCache.Lock()
		defer logCache.Unlock()
		v, ok := logCache.entries[key]
		if ok && time.Now().Before(v.expires) {
			return v.data
		}
		return nil
	}
	data := lookup()
	if data == nil {
		pending := logCache.flight.DoChan(key, func() (any, error) {
			if data := lookup(); data != nil {
				return data, nil
			}
			result, err := query()
			if err != nil {
				return nil, err
			}
			data, err := json.Marshal(result)
			if err != nil {
				return nil, err
			}
			logCache.Lock()
			if len(logCache.entries) >= 128 {
				for k, v := range logCache.entries {
					if time.Now().After(v.expires) {
						delete(logCache.entries, k)
					}
				}
				if len(logCache.entries) >= 128 {
					for k := range logCache.entries {
						delete(logCache.entries, k)
						break
					}
				}
			}
			logCache.entries[key] = cachedLogValue{data, time.Now().Add(ttl)}
			logCache.Unlock()
			return data, nil
		})
		var completed singleflight.Result
		select {
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		case completed = <-pending:
		}
		if completed.Err != nil {
			// A shared flight runs with its initiator's query context. If that
			// caller left the page, an independent live waiter can retry with its
			// own context. Never retry an unrelated database error here.
			if ctx.Err() == nil && (errors.Is(completed.Err, context.Canceled) || errors.Is(completed.Err, context.DeadlineExceeded)) {
				return query()
			}
			var zero T
			return zero, completed.Err
		}
		data = completed.Val.([]byte)
	}
	var result T
	err := json.Unmarshal(data, &result)
	return result, err
}

func invalidateLogCache() {
	logCache.Lock()
	logCache.entries = map[string]cachedLogValue{}
	logCache.Unlock()
}
