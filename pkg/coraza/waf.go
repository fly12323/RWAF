package coraza

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sync/singleflight"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/fsnotify/fsnotify"
)

// WAFEngine WAF 引擎封装
type WAFEngine struct {
	waf      coraza.WAF
	config   *WAFConfig
	mu       sync.RWMutex
	watcher  *fsnotify.Watcher
	stopChan chan struct{}
	stopOnce sync.Once
	buildMu  sync.Mutex
	policies map[string]policyWAF
	flights  singleflight.Group
}

var globalWAFEngine *WAFEngine

// SetGlobalWAFEngine 设置全局 WAF 引擎实例
func SetGlobalWAFEngine(engine *WAFEngine) {
	globalWAFEngine = engine
}

// GetGlobalWAFEngine 获取全局 WAF 引擎实例
func GetGlobalWAFEngine() *WAFEngine {
	return globalWAFEngine
}

// WAFConfig WAF 配置
type WAFConfig struct {
	RulesDir         string // 规则目录
	CrsDir           string // CRS 规则目录
	CustomRulesDir   string // 自定义规则目录
	EngineMode       string // 引擎模式: On, DetectionOnly, Off
	RequestBodyLimit int64  // 请求体限制
}

// NewWAFEngine 创建 WAF 引擎实例
func NewWAFEngine(cfg *WAFConfig) (*WAFEngine, error) {
	waf, err := buildEngine(cfg, "block", nil, nil)
	if err != nil {
		return nil, err
	}
	engine := &WAFEngine{
		waf:      waf,
		config:   cfg,
		policies: make(map[string]policyWAF),
	}

	// 设置全局实例
	SetGlobalWAFEngine(engine)

	// 启动热加载监控
	if err := engine.StartFileWatcher(); err != nil {
		fmt.Printf("警告: 启动热加载监控失败: %v\n", err)
	}

	return engine, nil
}

// loadRules 加载所有规则文件
func loadRules(cfg *WAFConfig) ([]string, error) {
	var directives []string

	// 1. 加载 CRS 配置文件
	crsSetupFile := filepath.Join(cfg.CrsDir, "crs-setup.conf")
	if _, err := os.Stat(crsSetupFile); err == nil {
		directives = append(directives, fmt.Sprintf("Include %s", crsSetupFile))
	}

	// 2. 加载 CRS 规则文件
	crsRulesDir := filepath.Join(cfg.CrsDir, "rules")
	ruleFiles, err := filepath.Glob(filepath.Join(crsRulesDir, "*.conf"))
	if err != nil {
		return nil, fmt.Errorf("读取 CRS 规则目录失败: %w", err)
	}

	// 按文件名排序，确保规则按正确顺序加载
	for _, ruleFile := range ruleFiles {
		directives = append(directives, fmt.Sprintf("Include %s", ruleFile))
	}

	// 3. 加载自定义规则
	customRuleFiles, err := filepath.Glob(filepath.Join(cfg.CustomRulesDir, "*.conf"))
	if err != nil {
		fmt.Printf("警告: 读取自定义规则目录失败: %v\n", err)
	} else {
		for _, ruleFile := range customRuleFiles {
			directives = append(directives, fmt.Sprintf("Include %s", ruleFile))
		}
	}

	return directives, nil
}

// NewTransaction 创建新的事务
func (e *WAFEngine) NewTransaction() *Transaction {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return &Transaction{
		tx: e.waf.NewTransaction(),
	}
}

// Transaction WAF 事务封装
type Transaction struct {
	tx types.Transaction
}

// ProcessConnection 处理连接信息
func (t *Transaction) ProcessConnection(clientIP string, clientPort int, serverIP string, serverPort int) {
	t.tx.ProcessConnection(clientIP, clientPort, serverIP, serverPort)
}

// ProcessURI 处理请求 URI
func (t *Transaction) ProcessURI(uri, method, httpVersion string) {
	t.tx.ProcessURI(uri, method, httpVersion)
}

// AddRequestHeader 添加请求头
func (t *Transaction) AddRequestHeader(key, value string) {
	t.tx.AddRequestHeader(key, value)
}

// ProcessRequestHeaders 处理请求头阶段
func (t *Transaction) ProcessRequestHeaders() *types.Interruption {
	return t.tx.ProcessRequestHeaders()
}

// AddRequestBody 添加请求体数据
func (t *Transaction) AddRequestBody(data []byte) error {
	_, _, err := t.tx.WriteRequestBody(data)
	return err
}

// ProcessRequestBody 处理请求体阶段
func (t *Transaction) ProcessRequestBody() *types.Interruption {
	intru, _ := t.tx.ProcessRequestBody()
	return intru
}

// InspectRequestBody preserves both body-write interruptions and parser errors.
func (t *Transaction) InspectRequestBody(data []byte) (*types.Interruption, error) {
	interruption, _, err := t.tx.WriteRequestBody(data)
	if interruption != nil || err != nil {
		return interruption, err
	}
	return t.tx.ProcessRequestBody()
}

// GetRiskScore 计算风险评分
func (t *Transaction) GetRiskScore() int {
	// Keep the pinned Coraza plugin variable interface confined to this adapter.
	v, ok := t.tx.(interface {
		Variables() plugintypes.TransactionVariables
	})
	if !ok {
		return 0
	}
	tx := v.Variables().TX()
	read := func(key string) int {
		values := tx.Get(key)
		if len(values) == 0 {
			return 0
		}
		n, _ := strconv.Atoi(values[0])
		return n
	}
	// Per-PL scores cover direct interruptions before CRS aggregation runs.
	level := read("blocking_paranoia_level")
	if level < 1 {
		level = 1
	}
	if level > 4 {
		level = 4
	}
	score := 0
	for i := 1; i <= level; i++ {
		score += read(fmt.Sprintf("inbound_anomaly_score_pl%d", i))
	}
	for _, key := range []string{"blocking_inbound_anomaly_score", "inbound_anomaly_score", "anomaly_score"} {
		if n := read(key); n > score {
			score = n
		}
	}
	return score
}

// GetMatchedRuleDetails 获取匹配规则的详细信息
func (t *Transaction) GetMatchedRuleDetails() []MatchedRuleDetail {
	var details []MatchedRuleDetail
	for _, rule := range t.tx.MatchedRules() {
		// The policy initializer is infrastructure, not a detection.
		if rule.Rule().ID() == 1000000001 {
			continue
		}
		detail := MatchedRuleDetail{
			RuleID:   fmt.Sprintf("%d", rule.Rule().ID()),
			RuleFile: rule.Rule().File(),
			RuleMsg:  rule.Message(),
			Severity: severityToString(rule.Rule().Severity()),
			// Rule severity does not determine its actual TX score contribution.
			Score: 0,
		}

		// 获取匹配的数据
		if len(rule.MatchedDatas()) > 0 {
			var matchedData []string
			for _, data := range rule.MatchedDatas() {
				matchedData = append(matchedData, string(data.Data()))
			}
			detail.MatchedData = strings.Join(matchedData, ", ")
		}

		details = append(details, detail)
	}
	return details
}

// Close 关闭事务
func (t *Transaction) Close() {
	t.tx.ProcessLogging()
	t.tx.Close()
}

// MatchedRuleDetail 匹配规则详情
type MatchedRuleDetail struct {
	RuleID      string `json:"rule_id"`
	RuleFile    string `json:"rule_file"`
	RuleMsg     string `json:"rule_msg"`
	Severity    string `json:"severity"`
	Score       int    `json:"score"`
	MatchedData string `json:"matched_data"`
}

// severityToString 将严重级别转换为字符串
func severityToString(severity types.RuleSeverity) string {
	switch severity {
	case types.RuleSeverityCritical:
		return "CRITICAL"
	case types.RuleSeverityError:
		return "ERROR"
	case types.RuleSeverityWarning:
		return "WARNING"
	case types.RuleSeverityNotice:
		return "NOTICE"
	case types.RuleSeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// StartFileWatcher 启动规则文件监控，实现热加载
func (e *WAFEngine) StartFileWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("创建文件监控器失败: %w", err)
	}
	e.watcher = watcher

	// 监控自定义规则目录
	if err := watcher.Add(e.config.CustomRulesDir); err != nil {
		watcher.Close()
		e.watcher = nil
		return fmt.Errorf("监控规则目录失败: %w", err)
	}

	// 同时监控 CRS 规则目录
	if err := watcher.Add(filepath.Join(e.config.CrsDir, "rules")); err != nil {
		fmt.Printf("警告: 监控 CRS 目录失败: %v\n", err)
	}

	e.stopChan = make(chan struct{})

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// 只关注 .conf 文件的修改事件
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
					if strings.HasSuffix(event.Name, ".conf") {
						fmt.Printf("[热加载] 检测到规则文件变化: %s\n", event.Name)
						if err := e.reloadRules(); err != nil {
							fmt.Printf("[热加载] 重载失败: %v\n", err)
						} else {
							fmt.Printf("[热加载] 重载成功!\n")
						}
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Printf("[热加载] 监控错误: %v\n", err)
			case <-e.stopChan:
				return
			}
		}
	}()

	fmt.Println("[热加载] 规则文件监控已启动")
	return nil
}

// StopFileWatcher 停止文件监控
func (e *WAFEngine) StopFileWatcher() {
	if e.watcher != nil {
		e.stopOnce.Do(func() {
			if e.stopChan != nil {
				close(e.stopChan)
			}
			_ = e.watcher.Close()
		})
	}
}

// reloadRules 重新加载规则
func (e *WAFEngine) reloadRules() error {
	e.buildMu.Lock()
	defer e.buildMu.Unlock()
	waf, err := buildEngine(e.config, "block", nil, nil)
	if err != nil {
		return err
	}
	e.mu.RLock()
	specs := make(map[string]policyWAF, len(e.policies))
	for k, v := range e.policies {
		specs[k] = v
	}
	e.mu.RUnlock()
	for k, v := range specs {
		v.engine, err = buildEngine(e.config, v.mode, v.disabled, v.categories, v.threshold, v.paranoiaLevel)
		if err != nil {
			return err
		}
		specs[k] = v
	}
	e.mu.Lock()
	e.waf = waf
	e.policies = specs
	e.mu.Unlock()
	return nil
}

// ReloadNow 手动触发立即重载（用于 API 调用）
func (e *WAFEngine) ReloadNow() error {
	return e.reloadRules()
}

type policyWAF struct {
	engine        coraza.WAF
	mode          string
	disabled      []string
	categories    []string
	threshold     int
	paranoiaLevel int
}

func (e *WAFEngine) BlockingEnabled() bool { return e.config.EngineMode == "On" }
func (e *WAFEngine) NewTransactionWithPolicy(mode string, disabled, categories []string, threshold ...int) (*Transaction, error) {
	waf, err := e.PolicyEngine(mode, disabled, categories, threshold...)
	if err != nil {
		return nil, err
	}
	return &Transaction{tx: waf.NewTransaction()}, nil
}
func (e *WAFEngine) PolicyEngine(mode string, disabled, categories []string, thresholds ...int) (coraza.WAF, error) {
	threshold := 15
	if len(thresholds) > 0 {
		threshold = thresholds[0]
	}
	if threshold <= 0 {
		return nil, fmt.Errorf("规则异常分阈值必须大于零")
	}
	level, err := policyParanoiaLevel(thresholds)
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal([]interface{}{mode, disabled, categories, threshold, level})
	key := string(data)
	e.mu.RLock()
	policy, ok := e.policies[key]
	e.mu.RUnlock()
	if ok {
		return policy.engine, nil
	}
	result, err, _ := e.flights.Do(key, func() (interface{}, error) {
		e.buildMu.Lock()
		defer e.buildMu.Unlock()
		e.mu.RLock()
		policy, ok := e.policies[key]
		e.mu.RUnlock()
		if ok {
			return policy.engine, nil
		}
		engine, err := buildEngine(e.config, mode, disabled, categories, threshold, level)
		if err != nil {
			return nil, err
		}
		e.mu.Lock()
		if len(e.policies) >= 256 {
			e.policies = make(map[string]policyWAF)
		}
		e.policies[key] = policyWAF{engine: engine, mode: mode, disabled: append([]string(nil), disabled...), categories: append([]string(nil), categories...), threshold: threshold, paranoiaLevel: level}
		e.mu.Unlock()
		return engine, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(coraza.WAF), nil
}

func policyParanoiaLevel(options []int) (int, error) {
	level := 1
	if len(options) > 1 && options[1] != 0 {
		level = options[1]
	}
	if level < 1 || level > 4 {
		return 0, fmt.Errorf("规则检测级别必须在 PL1 到 PL4 之间")
	}
	return level, nil
}

func buildEngine(cfg *WAFConfig, mode string, disabled, categories []string, thresholds ...int) (coraza.WAF, error) {
	level, err := policyParanoiaLevel(thresholds)
	if err != nil {
		return nil, err
	}
	wafConfig := coraza.NewWAFConfig().WithDirectives(fmt.Sprintf("SecRequestBodyLimit %d\nSecRequestBodyAccess On\nSecResponseBodyAccess Off", cfg.RequestBodyLimit))
	directives, err := loadRules(cfg)
	if err != nil {
		return nil, err
	}
	known := map[string]string{"sqli": "942000-942999", "xss": "941000-941999", "lfi": "930000-930999", "rfi": "931000-931999", "rce": "932000-932999", "php": "933000-933999", "nodejs": "934000-934999", "scanner": "913000-913999", "session": "943000-943999", "java": "944000-944999"}
	allowed := map[string]bool{}
	for _, category := range categories {
		if _, ok := known[category]; !ok && category != "custom" && category != "protocol" {
			return nil, fmt.Errorf("未知规则分类: %s", category)
		}
		allowed[category] = true
	}
	threshold := 15
	if len(thresholds) > 0 {
		threshold = thresholds[0]
	}
	if threshold <= 0 {
		return nil, fmt.Errorf("规则异常分阈值必须大于零")
	}
	thresholdAdded := false
	for _, directive := range directives {
		includePath := strings.TrimPrefix(directive, "Include ")
		// Apply after crs-setup, before detection rules; do not edit CRS files.
		if !thresholdAdded && filepath.Base(includePath) != "crs-setup.conf" {
			wafConfig = wafConfig.WithDirectives(fmt.Sprintf(`SecAction "id:1000000001,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d"`, threshold, level, level))
			thresholdAdded = true
		}
		customDir, pathErr := filepath.Abs(cfg.CustomRulesDir)
		includeAbs, includeErr := filepath.Abs(includePath)
		rel, relErr := filepath.Rel(customDir, includeAbs)
		isCustom := pathErr == nil && includeErr == nil && relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
		if len(categories) > 0 && !allowed["custom"] && isCustom {
			continue
		}
		wafConfig = wafConfig.WithDirectives(directive)
	}
	if len(categories) > 0 {
		for category, ids := range known {
			if !allowed[category] {
				wafConfig = wafConfig.WithDirectives("SecRuleRemoveById " + ids)
			}
		}
	}
	for _, id := range disabled {
		n, err := strconv.Atoi(id)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("无效规则 ID: %s", id)
		}
		if n == 1000000001 {
			return nil, fmt.Errorf("不能禁用系统策略初始化规则")
		}
		wafConfig = wafConfig.WithDirectives("SecRuleRemoveById " + id)
	}
	engineMode := cfg.EngineMode
	if mode == "monitor" && engineMode != "Off" {
		engineMode = "DetectionOnly"
	}
	wafConfig = wafConfig.WithDirectives("SecRuleEngine " + engineMode)
	return coraza.NewWAF(wafConfig)
}
