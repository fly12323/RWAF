package weakpassword

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/password"

	"gorm.io/gorm/clause"
)

const MaxBody = 64 * 1024

type snapshot struct {
	config  model.WeakPasswordConfig
	sets    map[string]map[string]struct{}
	version string
}
type Ticket struct {
	snapshot *snapshot
	endpoint model.AuthEndpoint
}
type job struct {
	ticket              *Ticket
	body                []byte
	contentType, id, ip string
	site                uint
	created             time.Time
}
type Engine struct {
	state                                                         atomic.Pointer[snapshot]
	queue                                                         chan job
	wg                                                            sync.WaitGroup
	accepted, dropped, processed, matched, skipped, publishErrors atomic.Int64
	lastError                                                     atomic.Pointer[string]
	configMu                                                      sync.Mutex
}

var active atomic.Pointer[Engine]

func DefaultConfig() model.WeakPasswordConfig {
	endpoints := []model.AuthEndpoint{}
	for _, kind := range []string{"login", "register", "password"} {
		path := "/" + kind
		endpoints = append(endpoints, model.AuthEndpoint{Name: kind, Path: path, Method: "POST", Kind: kind, Format: "auto", PasswordFields: []string{"password", "new_password"}})
	}
	return model.WeakPasswordConfig{ID: 1, Enabled: true, Dictionary: append([]string{}, password.Defaults...), Representations: append([]string{}, password.Formats...), Endpoints: endpoints}
}
func compile(c model.WeakPasswordConfig) (*snapshot, error) {
	if len(c.Dictionary) == 0 || len(c.Dictionary) > 10000 || len(c.Endpoints) > 100 || len(c.Representations) == 0 || len(c.Representations) > len(password.Formats) {
		return nil, fmt.Errorf("字典需包含 1–10000 项，接口最多 100 条，编码不能为空")
	}
	s := &snapshot{config: c, sets: map[string]map[string]struct{}{}}
	for _, format := range c.Representations {
		valid := false
		for _, v := range password.Formats {
			if v == format {
				valid = true
			}
		}
		if !valid {
			return nil, fmt.Errorf("不支持的表示形式: %s", format)
		}
		set := map[string]struct{}{}
		for _, word := range c.Dictionary {
			if word == "" || len(word) > 256 {
				return nil, fmt.Errorf("字典项长度需为 1–256 字节")
			}
			set[password.Encode(word, format)] = struct{}{}
		}
		s.sets[format] = set
	}
	names := map[string]bool{}
	for _, r := range c.Endpoints {
		if r.Name == "" || len(r.Name) > 100 || names[r.Name] || len(r.Host) > 255 || strings.ContainsAny(r.Host, "/ *") || !strings.HasPrefix(r.Path, "/") || len(r.Path) > 512 || strings.Count(r.Path, "*") > 1 || (strings.Contains(r.Path, "*") && !strings.HasSuffix(r.Path, "*")) || (r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH") {
			return nil, fmt.Errorf("接口名称须唯一，Host 不带端口，路径仅支持末尾 *，方法为 POST/PUT/PATCH")
		}
		names[r.Name] = true
		if (r.Kind != "login" && r.Kind != "register" && r.Kind != "password") || (r.Format != "auto" && r.Format != "json" && r.Format != "form") || len(r.PasswordFields) == 0 || len(r.PasswordFields) > 8 {
			return nil, fmt.Errorf("无效的接口类型、请求格式或密码字段")
		}
		for _, f := range r.PasswordFields {
			if f == "" || len(f) > 100 || strings.ContainsAny(f, "\r\n") {
				return nil, fmt.Errorf("密码字段为空或过长")
			}
		}
	}
	encoded, _ := json.Marshal(struct {
		Dictionary []string
		Formats    []string
	}{c.Dictionary, c.Representations})
	hash := sha256.Sum256(encoded)
	s.version = hex.EncodeToString(hash[:8])
	return s, nil
}
func New(c model.WeakPasswordConfig) (*Engine, error) {
	s, err := compile(c)
	if err != nil {
		return nil, err
	}
	e := &Engine{queue: make(chan job, 256)}
	e.state.Store(s)
	return e, nil
}
func GetConfig() (*model.WeakPasswordConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var c model.WeakPasswordConfig
	err := dao.GetDB().WithContext(ctx).First(&c, 1).Error
	return &c, err
}
func SaveConfig(c *model.WeakPasswordConfig) error {
	// Detach all slices from the caller before publishing the immutable snapshot.
	encoded, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var copy model.WeakPasswordConfig
	if err = json.Unmarshal(encoded, &copy); err != nil {
		return err
	}
	copy.ID = 1
	s, err := compile(copy)
	if err != nil {
		return err
	}
	e := active.Load()
	if e != nil {
		e.configMu.Lock()
		defer e.configMu.Unlock()
	}
	result := dao.GetDB().Model(&model.WeakPasswordConfig{}).Where("id = 1").Select("*").Omit("id").Updates(&copy)
	err = result.Error
	if err == nil && result.RowsAffected != 1 {
		err = fmt.Errorf("弱口令配置尚未初始化")
	}
	if err == nil && e != nil {
		e.state.Store(s)
		e.lastError.Store(nil)
	}
	return err
}
func Start(ctx context.Context) (*Engine, error) {
	c := DefaultConfig()
	if err := dao.GetDB().Clauses(clause.OnConflict{DoNothing: true}).Create(&c).Error; err != nil {
		return nil, err
	}
	stored, err := GetConfig()
	if err != nil {
		return nil, err
	}
	e, err := New(*stored)
	if err != nil {
		return nil, err
	}
	active.Store(e)
	for i := 0; i < 2; i++ {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-e.queue:
					e.process(j)
				}
			}
		}()
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.configMu.Lock()
				c, err := GetConfig()
				if err == nil && !c.UpdatedAt.Equal(e.state.Load().config.UpdatedAt) {
					var s *snapshot
					s, err = compile(*c)
					if err == nil {
						e.state.Store(s)
					}
				}
				if err != nil {
					message := "弱口令配置刷新失败"
					e.lastError.Store(&message)
				} else {
					e.lastError.Store(nil)
				}
				e.configMu.Unlock()
			}
		}
	}()
	return e, nil
}
func (e *Engine) Wait() {
	e.wg.Wait()
	active.CompareAndSwap(e, nil)
	for {
		select {
		case j := <-e.queue:
			clear(j.body)
			e.dropped.Add(1)
		default:
			return
		}
	}
}
func (e *Engine) Match(r *http.Request) *Ticket {
	s := e.state.Load()
	if s == nil {
		return nil
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	for _, rule := range s.config.Endpoints {
		if rule.Method != r.Method || (rule.Host != "" && !strings.EqualFold(rule.Host, host)) {
			continue
		}
		path := r.URL.Path
		match := path == rule.Path
		if strings.HasSuffix(rule.Path, "*") {
			match = strings.HasPrefix(path, strings.TrimSuffix(rule.Path, "*"))
		}
		if match {
			return &Ticket{snapshot: s, endpoint: rule}
		}
	}
	return nil
}
func Match(r *http.Request) *Ticket {
	if e := active.Load(); e != nil {
		return e.Match(r)
	}
	return nil
}
func Submit(t *Ticket, body []byte, contentType, id, ip string, site uint, created time.Time) {
	e := active.Load()
	if e == nil || t == nil || !t.snapshot.config.Enabled {
		return
	}
	if len(body) > MaxBody {
		e.skipped.Add(1)
		return
	}
	// Best effort: never wait for the detector. Only bounded, matched bodies are copied.
	if len(e.queue) == cap(e.queue) {
		e.dropped.Add(1)
		return
	}
	j := job{ticket: t, body: append([]byte{}, body...), contentType: contentType, id: id, ip: ip, site: site, created: created}
	select {
	case e.queue <- j:
		e.accepted.Add(1)
	default:
		clear(j.body)
		e.dropped.Add(1)
	}
}
func values(t *Ticket, body []byte, contentType string) ([]string, error) {
	format := t.endpoint.Format
	media, _, _ := mime.ParseMediaType(contentType)
	if format == "auto" {
		switch {
		case media == "application/json" || strings.HasSuffix(media, "+json"):
			format = "json"
		case media == "application/x-www-form-urlencoded":
			format = "form"
		default:
			return nil, fmt.Errorf("unsupported content type")
		}
	}
	out := []string{}
	switch format {
	case "json":
		var root map[string]any
		if err := json.Unmarshal(body, &root); err != nil {
			return nil, err
		}
		for _, field := range t.endpoint.PasswordFields {
			var value any = root
			for _, part := range strings.Split(field, ".") {
				m, ok := value.(map[string]any)
				if !ok {
					value = nil
					break
				}
				value = m[part]
			}
			if s, ok := value.(string); ok {
				out = append(out, s)
			}
		}
	case "form":
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		for _, field := range t.endpoint.PasswordFields {
			out = append(out, form[field]...)
		}
	default:
		return nil, fmt.Errorf("unsupported format")
	}
	return out, nil
}
func (e *Engine) detect(j job) (*model.WeakPasswordEvent, error) {
	vs, err := values(j.ticket, j.body, j.contentType)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, fmt.Errorf("password field missing")
	}
	for _, v := range vs {
		for _, format := range j.ticket.snapshot.config.Representations {
			candidate := v
			if format == "md5" || format == "sha1" || format == "sha256" {
				candidate = strings.ToLower(v)
			}
			if _, ok := j.ticket.snapshot.sets[format][candidate]; ok {
				return &model.WeakPasswordEvent{RequestID: j.id, SiteID: j.site, ClientIP: j.ip, Endpoint: j.ticket.endpoint.Name, Kind: j.ticket.endpoint.Kind, Path: j.ticket.endpoint.Path, Representation: format, DictionaryVersion: j.ticket.snapshot.version, Outcome: "unknown", CreatedAt: j.created}, nil
			}
		}
	}
	return nil, nil
}
func (e *Engine) process(j job) {
	defer clear(j.body)
	e.processed.Add(1)
	event, err := e.detect(j)
	if err != nil {
		e.skipped.Add(1)
		return
	}
	if event == nil {
		return
	}
	e.matched.Add(1)
	if events.Publish(events.WeakEvent(event)) != nil {
		e.publishErrors.Add(1)
	}
}
func Stats() map[string]any {
	if e := active.Load(); e != nil {
		s := e.state.Load()
		message := ""
		if p := e.lastError.Load(); p != nil {
			message = *p
		}
		return map[string]any{"enabled": s.config.Enabled, "dictionary_entries": len(s.config.Dictionary), "dictionary_version": s.version, "endpoints": len(s.config.Endpoints), "accepted": e.accepted.Load(), "dropped": e.dropped.Load(), "processed": e.processed.Load(), "matched": e.matched.Load(), "skipped": e.skipped.Load(), "publish_errors": e.publishErrors.Load(), "queued": len(e.queue), "capacity": cap(e.queue), "config_error": message}
	}
	return map[string]any{"enabled": false}
}
