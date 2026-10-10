package model

import (
	"regexp"
	"strconv"
	"strings"
)

// RuleProfile describes catalogue evidence, not measured detection accuracy.
type RuleProfile struct {
	Role              string `json:"role"`
	Scope             string `json:"scope"`
	ParanoiaLevel     int    `json:"paranoia_level"`
	Strength          string `json:"strength"`
	FalsePositiveRisk string `json:"false_positive_risk"`
	RiskReason        string `json:"risk_reason"`
	Scenario          string `json:"scenario"`
	Basis             string `json:"basis"`
}

var profilePL = regexp.MustCompile(`tag:\s*['"]paranoia-level/([1-4])['"]`)
var profilePhase = regexp.MustCompile(`(?:^|,)\s*phase:\s*([1-5])`)

func DescribeRule(r Rule) *RuleProfile {
	p := &RuleProfile{Role: "detection", Scope: "request", Strength: "待评估", FalsePositiveRisk: "unknown", RiskReason: "未找到 CRS PL 标签，需结合业务流量验证。", Basis: "规则元数据推断，非实测误报率", Scenario: "通用 HTTP 请求；上线前回放正常业务流量。"}
	flat := strings.ReplaceAll(r.RuleContent, "\\\n", "")
	if m := profilePhase.FindStringSubmatch(flat); len(m) > 0 && m[1] >= "3" {
		p.Scope = "response"
	}
	if p.Scope == "response" {
		p.Scenario = "响应检测规则；当前代理未执行响应规则阶段，不提供响应防护。"
	}
	if r.IsCustom {
		p.Role = "custom"
		p.RiskReason = "自定义规则需人工评估；目录严重级别、备注分数和 PL 标签不代表实测准确性。"
		return p
	}
	if strings.HasPrefix(strings.TrimSpace(flat), "SecAction ") || strings.Contains(flat, "skipAfter:") {
		p.Role = "control"
		p.Scope = "control"
		p.Strength = "引擎辅助"
		p.FalsePositiveRisk = "not_applicable"
		p.RiskReason = "配置或执行流程控制规则，不作为攻击检测效果排名。"
		p.Scenario = "支撑规则初始化或按 PL 跳过规则；不宜单独禁用。"
		return p
	}
	switch r.Category {
	case "Initialization", "Blocking Evaluation", "Correlation", "Exclusion":
		p.Role = "control"
		p.Scope = "control"
		p.Strength = "引擎辅助"
		p.FalsePositiveRisk = "not_applicable"
		p.RiskReason = "初始化、排除或评分决策规则，不作为独立攻击检测效果排名。"
		p.Scenario = "支撑规则运行与评分；禁用可能破坏防护链路。"
		return p
	case "SQL Injection":
		p.Scenario = "数据库查询参数；搜索语句、报表与 SQL 编辑器应重点验证。"
	case "XSS":
		p.Scenario = "脚本注入；富文本、HTML 编辑器与代码提交应重点验证。"
	case "RCE":
		p.Scenario = "命令执行；运维命令、脚本与代码输入应重点验证。"
	case "LFI", "RFI":
		p.Scenario = "文件路径与远程引用；文件管理、URL 导入应重点验证。"
	case "PHP Injection", "Node.js Injection", "Java Attack":
		p.Scenario = "对应语言攻击特征；代码片段、序列化数据应重点验证。"
	case "Generic Attack":
		p.Scenario = "通用应用注入攻击（含 Node.js 等）；模板、代码与特殊格式输入应重点验证。"
	case "Protocol":
		p.Scenario = "HTTP 协议异常；非标准客户端与特殊 API 格式应重点验证。"
	case "Scanner":
		p.Scenario = "扫描器特征；授权安全测试与自动化客户端应重点验证。"
	}
	if p.Scope == "response" {
		p.Scenario = "响应检测规则；当前代理未执行响应规则阶段，不提供响应防护。"
	}
	if m := profilePL.FindStringSubmatch(flat); len(m) > 0 {
		p.ParanoiaLevel, _ = strconv.Atoi(m[1])
		p.Strength = []string{"", "基础检测", "扩展检测", "严格检测", "极严格检测"}[p.ParanoiaLevel]
		p.FalsePositiveRisk = []string{"", "low", "moderate", "high", "very_high"}[p.ParanoiaLevel]
		p.RiskReason = "依据 CRS PL" + m[1] + " 的调优需求估计相对误报风险；低风险仍可能误封，严重级别不代表准确率。"
	}
	return p
}

type RulePreset struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	ParanoiaLevel  int    `json:"paranoia_level"`
	ScoreThreshold int    `json:"score_threshold"`
	Description    string `json:"description"`
}

func RulePresets() []RulePreset {
	return []RulePreset{
		{"low-fp", "低误报优先", 1, 5, "使用 PL1 基础检测，误报调优需求相对较低；仍需验证正常业务。"},
		{"balanced", "均衡防护", 2, 5, "增加 PL2 检测覆盖；富文本、搜索、代码输入更需要误报调优。"},
		{"strict", "严格防护", 3, 5, "增加 PL3 严格检测，误报风险较高；建议先用观察模式和业务回放验证。"},
	}
}
