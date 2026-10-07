package service

import "github.com/fly12323/RWAF/internal/model"

// DescribeDecision annotates legacy records without rewriting their stored evidence.
func DescribeDecision(log *model.RequestLog) {
	if log.DecisionSource != "" {
		return
	}
	log.SourceInferred = true
	switch {
	case log.Action == "block" && log.ResponseCode == 429:
		log.DecisionSource = "cc"
		log.DecisionReason = "CC 请求频率限制；该历史日志按 HTTP 429 推断来源，未经过规则评分"
	case log.Action == "block" && (log.RiskScore > 0 || log.AttackType != ""):
		log.DecisionSource = "waf"
		log.RuleEvaluated = true
		log.DecisionReason = "历史日志根据评分与攻击分类推断为规则引擎拦截"
	case log.Action == "block":
		log.DecisionSource = "unknown"
		log.DecisionReason = "历史日志未记录具体拦截来源；评分 0 不代表请求安全"
	default:
		log.DecisionSource = "upstream"
		log.DecisionReason = "历史日志记录的业务转发结果"
	}
}
