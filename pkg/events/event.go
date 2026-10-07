package events

import (
	"fmt"
	"time"
	"github.com/fly12323/RWAF/internal/model"
)

const Version = 1

type Event struct {
	Version int                      `json:"version"`
	ID      string                   `json:"id"`
	Request *model.RequestLog        `json:"request,omitempty"`
	Matches []model.RuleMatch        `json:"matches,omitempty"`
	Crawler *model.CrawlerLog        `json:"crawler,omitempty"`
	Weak    *model.WeakPasswordEvent `json:"weak,omitempty"`
}

func (e *Event) Validate() error {
	if e.Version != Version || e.ID == "" || len(e.ID) > 128 {
		return fmt.Errorf("invalid event version/id")
	}
	count := 0
	if e.Request != nil {
		count++
	}
	if e.Crawler != nil {
		count++
	}
	if e.Weak != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("event must contain exactly one log")
	}
	if e.Weak != nil && (e.Weak.RequestID == "" || e.Weak.CreatedAt.IsZero() || e.ID != "weak:"+e.Weak.RequestID || len(e.Matches) != 0 || e.Weak.Outcome != "unknown") {
		return fmt.Errorf("invalid weak password event")
	}
	if e.Request != nil && (e.Request.RequestID == "" || e.Request.CreatedAt.IsZero()) {
		return fmt.Errorf("invalid request event")
	}
	if e.Request != nil && e.ID != "request:"+e.Request.RequestID {
		return fmt.Errorf("request event id mismatch")
	}
	if e.Crawler != nil && e.ID != "crawler:"+e.Crawler.RequestID {
		return fmt.Errorf("crawler event id mismatch")
	}
	if e.Crawler != nil && (e.Crawler.RequestID == "" || e.Crawler.CreatedAt.IsZero() || len(e.Matches) != 0) {
		return fmt.Errorf("invalid crawler event")
	}
	return nil
}

func WeakEvent(r *model.WeakPasswordEvent) Event {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	return Event{Version: Version, ID: "weak:" + r.RequestID, Weak: r}
}

func RequestEvent(r *model.RequestLog, matches []model.RuleMatch) Event {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	return Event{Version: Version, ID: "request:" + r.RequestID, Request: r, Matches: matches}
}

func CrawlerEvent(r *model.CrawlerLog) Event {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	return Event{Version: Version, ID: "crawler:" + r.RequestID, Crawler: r}
}
