package model

import "time"

// CrawlerLog 爬虫检测日志
type CrawlerLog struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	RequestID      string    `json:"request_id" gorm:"size:64"`
	SiteID         *uint     `json:"site_id"`
	ClientIP       string    `json:"client_ip" gorm:"size:50"`
	UserAgent      string    `json:"user_agent" gorm:"type:text"`
	Method         string    `json:"method" gorm:"size:10"`
	URI            string    `json:"uri" gorm:"type:text"`
	CrawlerType    string    `json:"crawler_type" gorm:"size:50"`
	CrawlerName    string    `json:"crawler_name" gorm:"size:100"`
	Confidence     float64   `json:"confidence"`
	DetectionRules string    `json:"detection_rules" gorm:"type:jsonb"`
	Action         string    `json:"action" gorm:"size:20;default:'log'"`
	CreatedAt      time.Time `json:"created_at"`
}

// TableName 指定表名
func (CrawlerLog) TableName() string {
	return "crawler_logs"
}
