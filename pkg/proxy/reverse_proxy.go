package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
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
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/blacklist"
	"github.com/fly12323/RWAF/internal/ser/crawler"
	"github.com/fly12323/RWAF/internal/ser/ipcache"
	"github.com/fly12323/RWAF/internal/ser/protection"
	"github.com/fly12323/RWAF/internal/ser/ratelimit"
	"github.com/fly12323/RWAF/internal/ser/weakpassword"
	"github.com/fly12323/RWAF/pkg/coraza"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/telemetry"
)

const captureLimit = 8192

type ReverseProxy struct {
	siteID         uint
	balancer       Balancer
	wafEngine      *coraza.WAFEngine
	ccProtection   *ratelimit.CCProtectionService
	crawlerService *crawler.CrawlerService
	transport      *http.Transport
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
		crawlerService: crawler.NewCrawlerService(), transport: transport}
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
		authTicket := weakpassword.Match(c.Request)
		if authTicket != nil {
		}
		policy, err := protection.GetConfig()
		if err != nil {
			c.AbortWithStatusJSON(503, gin.H{"message": "防护配置暂不可用"})
			return
		}
		trusted := !policy.Enabled
		if !trusted && policy.IPWhitelistEnabled {
			trusted, err = ipcache.IsWhitelisted(ip)
			if err != nil {
				c.AbortWithStatus(503)
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
			blocked, entry, err := ipcache.IsBlocked(ip)
			if err != nil {
				c.AbortWithStatus(503)
				return
			}
			if blocked {
				block(403, "ipban", "您的IP已被封禁", entry.Reason)
				return
			}
		}
		if !trusted && policy.CCProtectionEnabled {
			cc := policy.CCConfig()
			ctx, cancel := context.WithTimeout(c.Request.Context(), time.Second)
			allowed, _, err := p.ccProtection.CheckLimitContext(ctx, p.siteID, ip, c.Request.URL.Path, cc)
			cancel()
			if err != nil {
				c.AbortWithStatusJSON(503, gin.H{"message": "限流服务暂不可用"})
				return
			}
			if !allowed {
				if cc.Action == "delay" {
					timer := time.NewTimer(time.Duration(cc.DelayMs) * time.Millisecond)
					select {
					case <-timer.C:
					case <-c.Request.Context().Done():
						timer.Stop()
						return
					}
				} else {
					block(429, "cc", "请求过于频繁，请稍后再试", "")
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
			p.crawlerService.LogCrawlerDetection(requestID, &p.siteID, ip, c.GetHeader("User-Agent"), c.Request.Method, c.Request.URL.Path, result, action)
			if action == "block" && result.Type != "human" {
				block(403, "crawler", "请求被爬虫检测拦截", result.Name)
				return
			}
		}
		body, err := readRequestBody(c.Writer, c.Request, config.GetConfig().WAF.RequestBodyLimit)
		if err != nil {
			status := http.StatusBadRequest
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			c.Set("decision_source", "body_limit")
			c.Set("decision_reason", "请求体读取失败或超过大小限制")
			p.record(c, requestID, ip, started, nil, nil, status, nil, nil, "error", "")
			c.AbortWithStatusJSON(status, gin.H{"message": "请求体读取失败或超过大小限制"})
			return
		}
		var tx *coraza.Transaction
		weakpassword.Submit(authTicket, body, c.GetHeader("Content-Type"), requestID, ip, p.siteID, started)
		if !trusted && policy.RuleEngineEnabled {
			tx, err = p.wafEngine.NewTransactionWithPolicy(policy.WafMode, policy.DisabledRuleIDs, policy.EnabledRuleCategories)
			if err != nil {
				log.Printf("site WAF policy invalid: %v", err)
				c.AbortWithStatus(503)
				return
			}
			defer tx.Close()
			c.Set("rule_evaluated", true)
			tx.ProcessConnection(ip, 0, "", 0)
			tx.ProcessURI(c.Request.URL.RequestURI(), c.Request.Method, c.Request.Proto)
			tx.AddRequestHeader("Host", c.Request.Host)
			for name, values := range c.Request.Header {
				for _, value := range values {
					tx.AddRequestHeader(name, value)
				}
			}
			interruption := tx.ProcessRequestHeaders()
			if interruption == nil {
				if err := tx.AddRequestBody(body); err != nil {
					c.AbortWithStatus(400)
					return
				}
				interruption = tx.ProcessRequestBody()
			}
			if policy.WafMode == "block" && p.wafEngine.BlockingEnabled() && (interruption != nil || tx.GetRiskScore() >= policy.ScoreThreshold) {
				c.Set("decision_source", "waf")
				c.Set("decision_reason", "规则引擎直接拒绝或风险评分达到阈值")
				p.record(c, requestID, ip, started, tx, body, 403, nil, nil, "block", "")
				p.checkAutoBlock(c.Request.Context(), ip, requestID, policy.AutoBlockConfig())
				p.renderBlockPage(c, 403, "waf", ip, "请求被 WAF 拦截", p.calculateAttackType(tx), map[string]string{"score": fmt.Sprint(tx.GetRiskScore())})
				c.Abort()
				return
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

func prefix(data []byte) []byte {
	if len(data) > captureLimit {
		return data[:captureLimit]
	}
	return data
}
func (p *ReverseProxy) record(c *gin.Context, id, ip string, started time.Time, tx *coraza.Transaction, body []byte, status int, headers http.Header, responseBody []byte, action, upstream string) {
	requestHeaders, _ := json.Marshal(c.Request.Header)
	responseHeaders, _ := json.Marshal(headers)
	uri := c.Request.URL.RequestURI()
	score := 0
	matches := make([]model.RuleMatch, 0)
	if tx != nil {
		score = tx.GetRiskScore()
		for _, m := range tx.GetMatchedRuleDetails() {
			matches = append(matches, model.RuleMatch{RuleID: m.RuleID, RuleFile: m.RuleFile, RuleMsg: m.RuleMsg, Severity: m.Severity, Score: m.Score, MatchedData: m.MatchedData})
		}
	}
	entry := &model.RequestLog{RequestID: id, SiteID: p.siteID, ClientIP: ip, Method: c.Request.Method, URI: uri,
		Headers: string(requestHeaders), Body: base64.StdEncoding.EncodeToString(prefix(body)), ResponseCode: status, ResponseHeaders: string(responseHeaders),
		ResponseBody: base64.StdEncoding.EncodeToString(prefix(responseBody)), RiskScore: score, Action: action, AttackType: p.calculateAttackType(tx), UpstreamAddr: upstream, Duration: int(time.Since(started).Milliseconds()), CreatedAt: started}
	entry.DecisionSource = c.GetString("decision_source")
	entry.DecisionReason = c.GetString("decision_reason")
	entry.RuleEvaluated = c.GetBool("rule_evaluated")
	if entry.DecisionSource == "" {
		entry.DecisionSource = "upstream"
		entry.DecisionReason = "请求已转发至业务上游"
		if action == "error" {
			entry.DecisionReason = "业务上游转发失败"
		}
	}
	_ = events.Publish(events.RequestEvent(entry, matches))
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

var attackCounter = redis.NewScript(`
local now=redis.call('TIME')
local stamp=now[1]*1000+math.floor(now[2]/1000)
redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',stamp-tonumber(ARGV[1])*1000)
redis.call('ZADD',KEYS[1],stamp,ARGV[2])
local count=redis.call('ZCARD',KEYS[1])
redis.call('EXPIRE',KEYS[1],ARGV[1])
if count>=tonumber(ARGV[3]) then redis.call('ZREM',KEYS[1],ARGV[2]) end
return count
`)

func (p *ReverseProxy) checkAutoBlock(parent context.Context, ip, requestID string, cfg *model.AutoBlockConfig) {
	if !cfg.Enabled || cfg.Duration <= 0 || cfg.Threshold <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	key := fmt.Sprintf("waf:attacks:%d:%s", p.siteID, ip)
	count, err := attackCounter.Run(ctx, dao.RDB, []string{key}, cfg.Duration, requestID, cfg.Threshold).Int64()
	if err != nil {
		log.Printf("auto-block counter failed: %v", err)
		return
	}
	if count >= int64(cfg.Threshold) {
		err := blacklist.NewIPBlacklistService().AutoBlock(ip, fmt.Sprintf("站点 %d 触发防护阈值", p.siteID), cfg.BlockHours)
		if err != nil {
			log.Printf("auto-block persistence failed: %v", err)
		}
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
