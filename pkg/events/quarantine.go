package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/segmentio/kafka-go"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrInvalidReplay = errors.New("invalid quarantine replay")
var ErrAlreadyReplayed = errors.New("quarantined event already replayed")

// Data/constraint failures belong to an event; connection, schema, deadlock and
// serialization failures remain retryable and must never advance offsets.
func permanentEventError(err error) bool {
	var state interface{ SQLState() string }
	return errors.As(err, &state) && (strings.HasPrefix(state.SQLState(), "22") || strings.HasPrefix(state.SQLState(), "23"))
}

func payloadHash(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

// DecodeEvent deliberately shares validation with administrator replay.
func DecodeEvent(payload []byte, maxBytes int) (Event, error) {
	var e Event
	if len(payload) > maxBytes {
		return e, fmt.Errorf("event exceeds size limit: %d > %d", len(payload), maxBytes)
	}
	if err := json.Unmarshal(payload, &e); err != nil {
		return e, fmt.Errorf("invalid event JSON: %w", err)
	}
	if err := e.Validate(); err != nil {
		return e, err
	}
	return e, nil
}

// The quarantine row and its alert commit together. Never truncate original bytes.
// A Kafka redelivery is idempotent on the consumer group's transport position.
func QuarantineMessage(ctx context.Context, db *gorm.DB, cfg config.KafkaConfig, msg kafka.Message, reason error) error {
	headers, err := json.Marshal(msg.Headers)
	if err != nil {
		return err
	}
	q := model.QuarantinedEvent{ConsumerGroup: cfg.GroupID, Topic: msg.Topic, Partition: msg.Partition, Offset: msg.Offset,
		MessageTime: msg.Time, MessageKey: msg.Key, Payload: msg.Value, Headers: string(headers), PayloadSHA256: payloadHash(msg.Value), PayloadBytes: len(msg.Value),
		Reason: reason.Error(), Status: "pending", CreatedAt: time.Now()}
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "consumer_group"}, {Name: "topic"}, {Name: "partition"}, {Name: "offset"}}, DoNothing: true}).Create(&q)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return nil
		}
		alert := model.Alert{Key: fmt.Sprintf("quarantine:%d", q.ID), Source: "log_quarantine", Severity: "warning",
			Message: fmt.Sprintf("日志异常消息已隔离（ID %d，分区 %d，offset %d），请查看隔离记录并修复重放", q.ID, q.Partition, q.Offset),
			Status:  "open", Occurrences: 1, CreatedAt: q.CreatedAt, LastSeen: q.CreatedAt}
		return tx.Create(&alert).Error
	})
}

// Replay persists the corrected event, immutable replay evidence, audit and alert
// resolution in one transaction. Row locking serializes concurrent operators.
func ReplayQuarantinedEvent(ctx context.Context, db *gorm.DB, id uint, replacement []byte, reason string, maxBytes int, audit model.OperationLog) (*model.QuarantinedEvent, error) {
	var q model.QuarantinedEvent
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&q, id).Error; err != nil {
			return err
		}
		if q.Status != "pending" {
			return ErrAlreadyReplayed
		}
		payload := q.Payload
		if len(replacement) > 0 {
			payload = replacement
		}
		e, err := DecodeEvent(payload, maxBytes)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidReplay, err)
		}
		if err := PersistBatch(ctx, tx, []Event{e}); err != nil {
			if permanentEventError(err) {
				return fmt.Errorf("%w: event violates database constraints", ErrInvalidReplay)
			}
			return err
		}
		now := time.Now()
		updates := map[string]any{"status": "replayed", "replayed_at": now, "replayed_by": audit.Username, "replay_event_id": e.ID,
			"replay_payload": payload, "replay_sha256": payloadHash(payload), "replay_reason": reason}
		if err := tx.Model(&q).Updates(updates).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Alert{}).Where("key = ? AND source = ? AND status = ?", fmt.Sprintf("quarantine:%d", id), "log_quarantine", "open").Updates(map[string]any{"status": "resolved", "resolved_at": now}).Error; err != nil {
			return err
		}
		details, err := json.Marshal(map[string]any{"event_id": e.ID, "original_sha256": q.PayloadSHA256, "replay_sha256": payloadHash(payload), "corrected": len(replacement) > 0, "reason": reason})
		if err != nil {
			return err
		}
		audit.Action, audit.Resource, audit.ResourceID, audit.Details, audit.Result, audit.CreatedAt = model.ActionReplayQuarantinedEvent, model.ResourceLogQuarantine, id, string(details), model.ResultSuccess, now
		if err := tx.Create(&audit).Error; err != nil {
			return err
		}
		return tx.First(&q, id).Error
	})
	if err != nil {
		return nil, err
	}
	return &q, nil
}
