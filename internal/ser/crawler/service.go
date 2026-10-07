package crawler

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/pkg/events"
)

// CrawlerService 爬虫检测服务
type CrawlerService struct{}

var suspiciousURI = regexp.MustCompile(`\.\.\/|\.\.\\|\/etc\/passwd|union.*select|select.*from|insert.*into|update.*set|delete.*from|drop.*table|<script|javascript:|onerror=|onload=|onclick=|<iframe|<object|<embed`)

// NewCrawlerService 创建爬虫检测服务
func NewCrawlerService() *CrawlerService {
	return &CrawlerService{}
}

// CrawlerResult 爬虫检测结果
type CrawlerResult struct {
	Type           string   `json:"type"`
	Name           string   `json:"name"`
	Confidence     float64  `json:"confidence"`
	DetectionRules []string `json:"detection_rules"`
}

// DetectCrawler 检测爬虫
func (s *CrawlerService) DetectCrawler(userAgent, clientIP, uri, method string) *CrawlerResult {
	result := &CrawlerResult{
		Type:           "human",
		Name:           "Human",
		Confidence:     0.0,
		DetectionRules: []string{},
	}

	// 检测 User-Agent
	userAgent = strings.ToLower(userAgent)

	// 检测已知的爬虫
	botSignatures := map[string]string{
		"bot":       "Generic Bot",
		"crawler":   "Generic Crawler",
		"spider":    "Generic Spider",
		"scanner":   "Generic Scanner",
		"wget":      "Wget",
		"curl":      "cURL",
		"python":    "Python Requests",
		"java":      "Java HttpClient",
		"ruby":      "Ruby Net::HTTP",
		"perl":      "Perl LWP",
		"php":       "PHP cURL",
		"node":      "Node.js",
		"go":        "Go HTTP Client",
		"scrapy":    "Scrapy",
		"phantomjs": "PhantomJS",
		"slimerjs":  "SlimerJS",
		"selenium":  "Selenium",
		"webdriver": "WebDriver",
		"headless":  "Headless Browser",
		"nmap":      "Nmap",
		"nikto":     "Nikto",
		"sqlmap":    "SQLmap",
		"burpsuite": "Burp Suite",
		"zap":       "OWASP ZAP",
		"wpscan":    "WPScan",
		"acunetix":  "Acunetix",
		"nessus":    "Nessus",
		"openvas":   "OpenVAS",
		"masscan":   "Masscan",
		"amass":     "Amass",
		"dirb":      "DirBuster",
		"dirsearch": "Dirsearch",
		"gobuster":  "Gobuster",
		"ffuf":      "FFUF",
	}

	// 搜索引擎爬虫
	searchEngineSignatures := map[string]string{
		"googlebot":           "Google Bot",
		"bingbot":             "Bing Bot",
		"yahoo":               "Yahoo Bot",
		"baidu":               "Baidu Spider",
		"sogou":               "Sogou Spider",
		"yandex":              "Yandex Bot",
		"duckduckgo":          "DuckDuckGo Bot",
		"bingpreview":         "Bing Preview",
		"facebookexternalhit": "Facebook Crawler",
		"twitterbot":          "Twitter Bot",
		"linkedinbot":         "LinkedIn Bot",
		"pinterestbot":        "Pinterest Bot",
		"slurp":               "Yahoo Slurp",
	}

	// 检测扫描器特征
	scannerSignatures := []string{
		"sqlmap",
		"nikto",
		"nmap",
		"nessus",
		"openvas",
		"acunetix",
		"wpscan",
		"burpsuite",
		"zap",
		"dirb",
		"dirsearch",
		"gobuster",
		"ffuf",
		"masscan",
		"amass",
		"webshell",
		"backdoor",
		"exploit",
		"injection",
		"xss",
		"sqli",
		"rce",
		"lfi",
		"rfi",
		"xxe",
		"ssrf",
	}

	// 检测爬虫行为模式（保留用于未来扩展）

	// 首先检测扫描器
	for _, sig := range scannerSignatures {
		if strings.Contains(userAgent, sig) {
			result.Type = "scanner"
			result.Name = botSignatures[sig]
			result.Confidence = 0.95
			result.DetectionRules = append(result.DetectionRules, "Scanner signature detected")
			return result
		}
	}

	// 检测搜索引擎爬虫
	for sig, name := range searchEngineSignatures {
		if strings.Contains(userAgent, sig) {
			result.Type = "crawler"
			result.Name = name
			result.Confidence = 0.9
			result.DetectionRules = append(result.DetectionRules, "Search engine crawler detected")
			return result
		}
	}

	// 检测其他爬虫和机器人
	for sig, name := range botSignatures {
		if strings.Contains(userAgent, sig) {
			result.Type = "bot"
			result.Name = name
			result.Confidence = 0.85
			result.DetectionRules = append(result.DetectionRules, "Bot signature detected")
			return result
		}
	}

	// 检测爬虫行为模式
	if s.detectCrawlerBehavior(userAgent, uri, method) {
		result.Type = "bot"
		result.Name = "Suspicious Bot"
		result.Confidence = 0.7
		result.DetectionRules = append(result.DetectionRules, "Suspicious crawler behavior detected")
		return result
	}

	// 检测异常请求模式
	if s.detectAbnormalPatterns(uri, method) {
		result.Type = "scanner"
		result.Name = "Suspicious Scanner"
		result.Confidence = 0.65
		result.DetectionRules = append(result.DetectionRules, "Abnormal request patterns detected")
		return result
	}

	return result
}

// detectCrawlerBehavior 检测爬虫行为模式
func (s *CrawlerService) detectCrawlerBehavior(userAgent, uri, method string) bool {
	// 检测请求频率相关的模式
	// 这里可以根据实际需求添加更多的检测逻辑

	// 检测常见的爬虫路径模式
	crawlerPaths := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/sitemap",
		"/feed",
		"/rss",
		"/atom",
	}

	for _, path := range crawlerPaths {
		if strings.Contains(uri, path) {
			return true
		}
	}

	// 检测API扫描模式
	apiPatterns := []string{
		"/swagger",
		"/docs",
		"/openapi",
		"/graphql",
		"/rest",
	}

	for _, pattern := range apiPatterns {
		if strings.Contains(uri, pattern) && method == "GET" {
			return true
		}
	}

	return false
}

// detectAbnormalPatterns 检测异常请求模式
func (s *CrawlerService) detectAbnormalPatterns(uri, method string) bool {
	// 检测SQL注入特征
	sqliPatterns := []string{
		"union select",
		"select.*from",
		"insert into",
		"update.*set",
		"delete from",
		"drop table",
		"or 1=1",
		"and 1=1",
		"sleep\\(",
		"benchmark\\(",
	}

	// 检测XSS特征
	xssPatterns := []string{
		"<script",
		"javascript:",
		"onerror=",
		"onload=",
		"onclick=",
		"<iframe",
		"<object",
		"<embed",
	}

	// 检测路径遍历特征
	lfiPatterns := []string{
		"../",
		"..\\",
		"/etc/passwd",
		"/windows/win.ini",
		"/boot.ini",
	}

	// 检测命令注入特征
	rcePatterns := []string{
		"|",
		";",
		"&&",
		"||",
		"`",
		"$(",
		"wget",
		"curl",
		"bash",
		"sh",
		"cmd",
	}

	// 检测敏感文件访问
	sensitiveFiles := []string{
		"/.env",
		"/.git/config",
		"/config.php",
		"/wp-config.php",
		"/.htaccess",
		"/web.config",
	}

	// 合并所有模式
	patterns := append(sqliPatterns, xssPatterns...)
	patterns = append(patterns, lfiPatterns...)
	patterns = append(patterns, rcePatterns...)
	patterns = append(patterns, sensitiveFiles...)

	uriLower := strings.ToLower(uri)

	for _, pattern := range patterns {
		if strings.Contains(uriLower, pattern) {
			return true
		}
	}

	// 使用正则表达式检测更复杂的模式
	if suspiciousURI.MatchString(uriLower) {
		return true
	}

	return false
}

// LogCrawlerDetection 记录爬虫检测结果
func (s *CrawlerService) LogCrawlerDetection(requestID string, siteID *uint, clientIP, userAgent, method, uri string, result *CrawlerResult, action string) {
	if result == nil {
		return
	}

	detectionRulesJSON, _ := json.Marshal(result.DetectionRules)

	log := &model.CrawlerLog{
		RequestID:      requestID,
		SiteID:         siteID,
		ClientIP:       clientIP,
		UserAgent:      userAgent,
		Method:         method,
		URI:            uri,
		CrawlerType:    result.Type,
		CrawlerName:    result.Name,
		Confidence:     result.Confidence,
		DetectionRules: string(detectionRulesJSON),
		Action:         action,
	}

	_ = events.Publish(events.CrawlerEvent(log))
}
