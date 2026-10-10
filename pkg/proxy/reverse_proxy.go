package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/autoblock"
	"github.com/fly12323/RWAF/internal/ser/crawler"
	"github.com/fly12323/RWAF/internal/ser/ipcache"
	"github.com/fly12323/RWAF/internal/ser/protection"
	"github.com/fly12323/RWAF/internal/ser/ratelimit"
	"github.com/fly12323/RWAF/internal/ser/weakpassword"
	"github.com/fly12323/RWAF/pkg/coraza"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/telemetry"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

const captureLimit = 8192

type ReverseProxy struct {
	siteID         uint
	balancer       Balancer
	wafEngine      *coraza.WAFEngine
	ccProtection   ccLimiter
	crawlerService *crawler.CrawlerService
	transport      *http.Transport
	ccWaiters      chan struct{}
	loadPolicy     func() (*model.ProtectionConfig, error)
	isWhitelisted  func(string) (bool, error)
	isBlocked      func(string) (bool, *model.IPBlacklist, error)
	publish        func(events.Event) error
	autoBlock      func(context.Context, uint, string, string, *model.AutoBlockConfig) error
}

func NewReverseProxy(siteID uint, targets []Target, strategy string, engine *coraza.WAFEngine) *ReverseProxy {
	balancer := NewBalancer(strategy)
	for _, target := range targets {
		target := target
		balancer.AddTarget(&target)
	}
	cfg := config.GetConfig()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // upstream traffic must not inherit the Docker download proxy
	transport.DialContext = (&net.Dialer{Timeout: time.Duration(cfg.Proxy.ConnectTimeout) * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.ResponseHeaderTimeout = time.Duration(cfg.Proxy.ReadTimeout) * time.Second
	transport.MaxIdleConns = cfg.Proxy.MaxIdleConns
	transport.MaxIdleConnsPerHost = cfg.Proxy.MaxIdleConnsPerHost
	transport.IdleConnTimeout = time.Duration(cfg.Proxy.IdleTimeout) * time.Second
	transport.DisableCompression = true
	return &ReverseProxy{siteID: siteID, balancer: balancer, wafEngine: engine,
		ccProtection:   ratelimit.NewCCProtectionService(),
		crawlerService: crawler.NewCrawlerService(), transport: transport, ccWaiters: make(chan struct{}, 64),
		loadPolicy: protection.GetConfig, isWhitelisted: ipcache.IsWhitelisted, isBlocked: ipcache.IsBlocked,
		publish: events.Publish, autoBlock: autoblock.RecordRuleBlock}
}

func (p *ReverseProxy) Close() { p.transport.CloseIdleConnections() }

func (p *ReverseProxy) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		defer func() { telemetry.Observe(c.Writer.Status(), time.Since(started)) }()
		requestID := uuid.NewString()
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		ip := c.ClientIP()
		var tx *coraza.Transaction
		var body []byte
		defer func() {
			if !c.GetBool("request_recorded") {
				p.record(c, requestID, ip, started, tx, body, c.Writer.Status(), nil, nil, "error", "")
			}
			if tx != nil {
				tx.Close()
			}
		}()
		fail := func(status int, source, reason string) {
			c.Set("decision_source", source)
			c.Set("decision_reason", reason)
			c.AbortWithStatusJSON(status, gin.H{"message": reason})
		}
		authTicket := weakpassword.Match(c.Request)
		state := &decisionState{mode: "unavailable"}
		c.Set("decision_state", state)
		policy, err := p.loadPolicy()
		if err != nil {
			fail(503, "policy_error", "防护配置暂不可用")
			return
		}
		state.mode, state.version = policy.WafMode, policy.UpdatedAt.UTC().Format(time.RFC3339Nano)
		if !policy.Enabled {
			state.mode = "off"
		}
		c.Set("decision_state", state)
		trusted := !policy.Enabled
		if !trusted && policy.IPWhitelistEnabled {
			trusted, err = p.isWhitelisted(ip)
			if err != nil {
				fail(503, "ip_list_error", "IP 名单暂不可用")
				return
			}
		}
		block := func(status int, kind, message, reason string) {
			c.Set("decision_source", kind)
			c.Set("decision_reason", strings.TrimSpace(message+" "+reason))
			p.record(c, requestID, ip, started, nil, nil, status, nil, nil, "block", "")
			p.renderBlockPage(c, status, kind, ip, message, reason, nil)
			c.Abort()
		}
		if !trusted && policy.IPBlacklistEnabled {
			blocked, entry, err := p.isBlocked(ip)
			if err != nil {
				fail(503, "ip_list_error", "IP 名单暂不可用")
				return
			}
			if blocked && state.enforce("ipban", "block", entry.Reason) {
				block(403, "ipban", "您的IP已被封禁", entry.Reason)
				return
			}
		}
		if !trusted && policy.CCProtectionEnabled {
			cc := policy.CCConfig()
			ctx, cancel := context.WithTimeout(c.Request.Context(), time.Second)
			result, err := p.ccProtection.Evaluate(ctx, p.siteID, ip, c.Request.URL.Path, cc)
			cancel()
			if err != nil {
				fail(503, "cc_error", "限流服务暂不可用")
				return
			}
			if !result.Allowed {
				state.enforce("cc", result.Action, "超出限额："+result.Rule)
			}
			if !result.Allowed && state.mode == "block" {
				if result.Action == "delay" {
					result, err = p.waitForCC(c.Request.Context(), ip, c.Request.URL.Path, cc, result)
					if err != nil {
						if c.Request.Context().Err() != nil {
							fail(499, "client_error", "客户端已取消请求")
						} else {
							fail(503, "cc_error", "限流等待失败")
						}
						return
					}
				}
				if !result.Allowed {
					c.Header("Retry-After", fmt.Sprint(max(1, int(result.RetryAfter.Seconds()+0.999))))
					block(429, "cc", "请求过于频繁，请稍后再试", result.Rule)
					return
				}
			}
		}
		if !trusted && policy.CrawlerDetectionEnabled {
			result := p.crawlerService.DetectCrawler(c.GetHeader("User-Agent"), ip, c.Request.URL.String(), c.Request.Method)
			action := "log"
			switch result.Type {
			case "scanner":
				action = policy.CrawlerScannerAction
			case "bot":
				action = policy.CrawlerBotAction
			case "crawler":
				action = policy.CrawlerCrawlerAction
			}
			enforce := false
			if result.Type != "human" {
				enforce = state.enforce("crawler", action, result.Name)
			}
			if action == "block" && state.mode == "monitor" {
				action = "log"
			}
			if p.publish != nil {
				_ = p.publish(events.CrawlerEvent(p.crawlerService.BuildLog(requestID, &p.siteID, ip, c.GetHeader("User-Agent"), c.Request.Method, c.Request.URL.Path, result, action)))
			}
			if enforce {
				block(403, "crawler", "请求被爬虫检测拦截", result.Name)
				return
			}
		}
		if !trusted && policy.RuleEngineEnabled {
			tx, err = p.wafEngine.NewTransactionWithPolicy(policy.WafMode, policy.DisabledRuleIDs, policy.EnabledRuleCategories, policy.ScoreThreshold, policy.ParanoiaLevel)
			if err != nil {
				log.Printf("site WAF policy invalid: %v", err)
				fail(503, "waf_error", "规则策略暂不可用")
				return
			}
			c.Set("rule_evaluated", true)
			tx.ProcessConnection(ip, 0, "", 0)
			tx.ProcessURI(c.Request.URL.RequestURI(), c.Request.Method, c.Request.Proto)
			tx.AddRequestHeader("Host", c.Request.Host)
			for name, values := range c.Request.Header {
				for _, value := range values {
					tx.AddRequestHeader(name, value)
				}
			}
			if p.enforceWAF(c, state, policy, tx, tx.ProcessRequestHeaders() != nil, requestID, ip, started, nil) {
				return
			}
		}
		body, err = readRequestBody(c.Writer, c.Request, config.GetConfig().WAF.RequestBodyLimit)
		if err != nil {
			status := http.StatusBadRequest
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			fail(status, "body_limit", "请求体读取失败或超过大小限制")
			return
		}
		weakpassword.Submit(authTicket, body, c.GetHeader("Content-Type"), requestID, ip, p.siteID, started)
		if tx != nil {
			interruption, err := tx.InspectRequestBody(body)
			if err != nil {
				fail(400, "waf_error", "规则引擎无法处理请求体")
				return
			}
			if p.enforceWAF(c, state, policy, tx, interruption != nil, requestID, ip, started, body) {
				return
			}
			if len(tx.GetMatchedRuleDetails()) > 0 && !state.hasSource("waf") {
				state.enforce("waf", "log", "规则命中，未执行阻断")
			}
		}
		p.forward(c, requestID, ip, started, tx, body)
	}
}

func readRequestBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	original := r.Body
	defer original.Close()
	data, err := io.ReadAll(http.MaxBytesReader(w, original, limit))
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}

// captureBody retains a prefix while ReverseProxy streams the original body.
type captureBody struct {
	io.ReadCloser
	prefix []byte
	limit  int
}

func (b *captureBody) Read(dst []byte) (int, error) {
	n, err := b.ReadCloser.Read(dst)
	if room := b.limit - len(b.prefix); room > 0 {
		take := n
		if take > room {
			take = room
		}
		b.prefix = append(b.prefix, dst[:take]...)
	}
	return n, err
}

func (p *ReverseProxy) forward(c *gin.Context, id, ip string, started time.Time, tx *coraza.Transaction, body []byte) {
	target := p.balancer.Next()
	if target == nil {
		p.record(c, id, ip, started, tx, body, 502, nil, nil, "error", "")
		c.AbortWithStatus(502)
		return
	}
	targetURL := &url.URL{Scheme: "http", Host: net.JoinHostPort(target.Host, fmt.Sprint(target.Port))}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Director = nil
	proxy.Rewrite = func(r *httputil.ProxyRequest) {
		r.SetURL(targetURL)
		r.Out.Host = r.In.Host
		r.Out.Header.Set("X-Forwarded-For", ip)
		scheme := "http"
		if r.In.TLS != nil {
			scheme = "https"
		}
		r.Out.Header.Set("X-Forwarded-Proto", scheme)
		r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
		r.Out.Header.Set("X-Request-ID", id)
	}
	proxy.Transport = p.transport
	var captured *captureBody
	var headers http.Header
	status := 502
	action := "pass"
	proxy.ModifyResponse = func(resp *http.Response) error {
		status = resp.StatusCode
		headers = resp.Header.Clone()
		captured = &captureBody{ReadCloser: resp.Body, limit: captureLimit}
		resp.Body = captured
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("upstream %s failed: %v", targetURL.Host, err)
		status = 502
		action = "error"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(502)
		_, _ = w.Write([]byte(`{"code":502,"message":"后端服务器不可用"}`))
	}
	proxy.ServeHTTP(c.Writer, c.Request)
	var responseBody []byte
	if captured != nil {
		responseBody = captured.prefix
	}
	p.record(c, id, ip, started, tx, body, status, headers, responseBody, action, targetURL.Host)
}

func (p *ReverseProxy) calculateAttackType(tx *coraza.Transaction) string {
	if tx == nil {
		return ""
	}
	counts := map[string]int{}
	for _, m := range tx.GetMatchedRuleDetails() {
		if isAttackDetectionRule(m.RuleID) {
			kind := getAttackType(m.RuleID)
			if kind != "Protocol Issue" {
				counts[kind]++
			}
		}
	}
	result := ""
	max := 0
	for kind, n := range counts {
		if n > max || (n == max && kind < result) {
			max = n
			result = kind
		}
	}
	return result
}

func (p *ReverseProxy) checkAutoBlock(parent context.Context, ip, requestID string, cfg *model.AutoBlockConfig) {
	if err := p.autoBlock(parent, p.siteID, ip, requestID, cfg); err != nil {
		log.Printf("auto-block failed: %v", err)
	}
}

var blockTemplateOnce sync.Once
var blockTemplate *template.Template

func (p *ReverseProxy) renderBlockPage(c *gin.Context, status int, kind, ip, message, reason string, extra map[string]string) {
	blockTemplateOnce.Do(func() { blockTemplate, _ = template.ParseFiles("templates/block.html") })
	if blockTemplate == nil {
		c.JSON(status, gin.H{"code": status, "message": message})
		return
	}
	values := url.Values{"type": {kind}, "code": {fmt.Sprint(status)}, "ip": {ip}, "message": {message}, "reason": {reason}}
	for k, v := range extra {
		values.Set(k, v)
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	if err := blockTemplate.Execute(c.Writer, struct{ QueryString string }{values.Encode()}); err != nil {
		log.Printf("block page failed: %v", err)
	}
}

// isAttackDetectionRule 判断是否是真正的攻击检测规则
func isAttackDetectionRule(ruleID string) bool {
	prefix := ""
	if len(ruleID) >= 3 {
		prefix = ruleID[:3]
	}

	isAttackCategory := false
	switch prefix {
	case "920", "921", "930", "931", "932", "933", "934", "941", "942", "943", "944":
		isAttackCategory = true
	}

	if !isAttackCategory {
		return false
	}

	if len(ruleID) >= 6 {
		suffix := ruleID[3:]
		suffixNum := 0
		fmt.Sscanf(suffix, "%d", &suffixNum)
		return suffixNum >= 100
	}

	return false
}

// getAttackType 根据规则ID判断攻击类型
func getAttackType(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "942"):
		return "SQL Injection"
	case strings.HasPrefix(ruleID, "941"):
		return "XSS"
	case strings.HasPrefix(ruleID, "930"):
		return "LFI"
	case strings.HasPrefix(ruleID, "931"):
		return "RFI"
	case strings.HasPrefix(ruleID, "932"):
		return "RCE"
	case strings.HasPrefix(ruleID, "933"):
		return "PHP Injection"
	case strings.HasPrefix(ruleID, "934"):
		return "Node.js Injection"
	case strings.HasPrefix(ruleID, "921"):
		return "Protocol Attack"
	case strings.HasPrefix(ruleID, "920"):
		return "Protocol Issue"
	case strings.HasPrefix(ruleID, "943"):
		return "Session Fixation"
	case strings.HasPrefix(ruleID, "944"):
		return "Java Attack"
	default:
		return "Unknown"
	}
}
