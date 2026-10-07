package model

import "time"

// ProcessedEvent is committed with the logs to make Kafka redelivery harmless.
type ProcessedEvent struct {
	EventID   string    `gorm:"primaryKey;size:128"`
	CreatedAt time.Time `gorm:"autoCreateTime;index"`
}
