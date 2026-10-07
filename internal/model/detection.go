package model

import "time"

// AuthEndpoint describes a protocol, not a separate site protection policy.
type AuthEndpoint struct {
	Name           string   `json:"name"`
	Host           string   `json:"host"`
	Path           string   `json:"path"`
	Method         string   `json:"method"`
	Kind           string   `json:"kind"`
	Format         string   `json:"format"`
	PasswordFields []string `json:"password_fields"`
}

type WeakPasswordConfig struct {
	ID              uint           `json:"id" gorm:"primaryKey;autoIncrement:false;check:weak_config_singleton,id = 1"`
	Enabled         bool           `json:"enabled"`
	Dictionary      []string       `json:"dictionary" gorm:"serializer:json;type:jsonb"`
	Representations []string       `json:"representations" gorm:"serializer:json;type:jsonb"`
	Endpoints       []AuthEndpoint `json:"endpoints" gorm:"serializer:json;type:jsonb"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type WeakPasswordEvent struct {
	ID                uint      `json:"id" gorm:"primaryKey"`
	RequestID         string    `json:"request_id" gorm:"uniqueIndex;size:64"`
	SiteID            uint      `json:"site_id" gorm:"index"`
	ClientIP          string    `json:"client_ip" gorm:"size:64"`
	Endpoint          string    `json:"endpoint" gorm:"size:100"`
	Kind              string    `json:"kind" gorm:"size:20"`
	Path              string    `json:"path" gorm:"size:512"`
	Representation    string    `json:"representation" gorm:"size:32"`
	DictionaryVersion string    `json:"dictionary_version" gorm:"size:64"`
	Outcome           string    `json:"outcome" gorm:"size:20"`
	CreatedAt         time.Time `json:"created_at" gorm:"index"`
}

type MonitorConfig struct {
	ID                     uint      `json:"id" gorm:"primaryKey;autoIncrement:false;check:monitor_config_singleton,id = 1"`
	Enabled                bool      `json:"enabled"`
	IntervalSeconds        int       `json:"interval_seconds"`
	KafkaLagThreshold      int64     `json:"kafka_lag_threshold"`
	QueuePercent           int       `json:"queue_percent"`
	ConsumerTimeoutSeconds int       `json:"consumer_timeout_seconds"`
	HeapLimitMB            int       `json:"heap_limit_mb"`
	ProxyErrorPercent      int       `json:"proxy_error_percent"`
	ProxyMinRequests       int       `json:"proxy_min_requests"`
	ProxyP99MS             int       `json:"proxy_p99_ms"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type Alert struct {
	ID             uint       `json:"id" gorm:"primaryKey"`
	Key            string     `json:"key" gorm:"index;size:200"`
	Source         string     `json:"source" gorm:"size:40"`
	Severity       string     `json:"severity" gorm:"size:20"`
	Message        string     `json:"message" gorm:"size:500"`
	Status         string     `json:"status" gorm:"index;size:20"`
	Occurrences    int        `json:"occurrences"`
	CreatedAt      time.Time  `json:"created_at" gorm:"index"`
	LastSeen       time.Time  `json:"last_seen"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
	AcknowledgedBy string     `json:"acknowledged_by" gorm:"size:50"`
}
