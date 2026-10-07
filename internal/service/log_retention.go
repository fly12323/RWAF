package service

import (
	"context"
	"gorm.io/gorm"
	"log"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
)

// Delete details and their parent rows atomically, in bounded batches. Event
// receipts deliberately remain: time alone cannot prove Kafka/spool replay has
// expired, and deleting receipts would resurrect previously retired logs.
func deleteRequestLogs(db *gorm.DB, cutoff time.Time, batch int) (int64, error) {
	var deleted int64
	err := db.Transaction(func(tx *gorm.DB) error {
		var ids []uint
		if err := tx.Raw("SELECT id FROM request_logs WHERE created_at < ? ORDER BY id LIMIT ? FOR UPDATE SKIP LOCKED", cutoff, batch).Scan(&ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		if err := tx.Exec("DELETE FROM rule_matches WHERE request_log_id IN ?", ids).Error; err != nil {
			return err
		}
		result := tx.Exec("DELETE FROM request_logs WHERE id IN ?", ids)
		deleted = result.RowsAffected
		return result.Error
	})
	if err == nil && deleted > 0 {
		invalidateLogCache()
	}
	return deleted, err
}

// RunLogRetention is also callable by the isolated acceptance harness.
func RunLogRetention(ctx context.Context, db *gorm.DB, cutoff time.Time, batch int) (int64, error) {
	var total int64
	for i := 0; i < 20; i++ {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := deleteRequestLogs(db.WithContext(ctx), cutoff, batch)
		total += n
		if err != nil {
			return total, err
		}
		if n < int64(batch) {
			break
		}
	}
	// Keep audit operations and unresolved alerts; clean only event data here.
	for _, table := range []string{"crawler_logs", "weak_password_events"} {
		for i := 0; i < 20; i++ {
			result := db.WithContext(ctx).Exec("DELETE FROM "+table+" WHERE id IN (SELECT id FROM "+table+" WHERE created_at < ? ORDER BY id LIMIT ?)", cutoff, batch)
			total += result.RowsAffected
			if result.Error != nil {
				return total, result.Error
			}
			if result.RowsAffected < int64(batch) {
				break
			}
		}
	}
	return total, nil
}

func StartLogRetention(ctx context.Context) func() {
	done := make(chan struct{})
	c := config.GetConfig().Log
	go func() {
		defer close(done)
		if c.RetentionDays == 0 {
			return
		}
		ticker := time.NewTicker(time.Duration(c.CleanupIntervalMinutes) * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				n, err := RunLogRetention(cleanupCtx, dao.GetDB(), time.Now().AddDate(0, 0, -c.RetentionDays), c.CleanupBatchSize)
				cancel()
				if err != nil {
					log.Printf("log retention failed: %v", err)
				} else if n > 0 {
					log.Printf("log retention deleted %d expired rows; replay receipts preserved", n)
				}
			}
		}
	}()
	return func() { <-done }
}
