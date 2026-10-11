package model

import "time"

// Original transport evidence is immutable and retained even after replay.
type QuarantinedEvent struct {
	ID            uint       `json:"id" gorm:"primaryKey"`
	ConsumerGroup string     `json:"consumer_group" gorm:"size:255;not null;uniqueIndex:idx_quarantine_position,priority:1"`
	Topic         string     `json:"topic" gorm:"size:255;not null;uniqueIndex:idx_quarantine_position,priority:2"`
	Partition     int        `json:"partition" gorm:"not null;uniqueIndex:idx_quarantine_position,priority:3"`
	Offset        int64      `json:"offset" gorm:"not null;uniqueIndex:idx_quarantine_position,priority:4"`
	MessageTime   time.Time  `json:"message_time"`
	MessageKey    []byte     `json:"message_key,omitempty" gorm:"type:bytea"`
	Payload       []byte     `json:"payload,omitempty" gorm:"type:bytea"`
	Headers       string     `json:"headers,omitempty" gorm:"type:text"`
	PayloadSHA256 string     `json:"payload_sha256" gorm:"size:64;not null"`
	PayloadBytes  int        `json:"payload_bytes"`
	Reason        string     `json:"reason" gorm:"type:text;not null"`
	Status        string     `json:"status" gorm:"size:20;not null;index"`
	CreatedAt     time.Time  `json:"created_at" gorm:"index"`
	ReplayedAt    *time.Time `json:"replayed_at,omitempty"`
	ReplayedBy    string     `json:"replayed_by,omitempty" gorm:"size:50"`
	ReplayEventID string     `json:"replay_event_id,omitempty" gorm:"size:128"`
	ReplayPayload []byte     `json:"replay_payload,omitempty" gorm:"type:bytea"`
	ReplaySHA256  string     `json:"replay_sha256,omitempty" gorm:"size:64"`
	ReplayReason  string     `json:"replay_reason,omitempty" gorm:"type:text"`
}
