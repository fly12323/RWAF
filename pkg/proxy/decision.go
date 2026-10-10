package proxy

import (
	"fmt"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/pkg/coraza"
	"github.com/gin-gonic/gin"
	"time"
)

// decisionState is request-local. Detectors propose actions; this boundary
// decides whether to enforce them and keeps evidence separate from forwarding.
type decisionState struct {
	mode       string
	version    string
	detections []model.Detection
}

func (p *ReverseProxy) enforceWAF(c *gin.Context, state *decisionState, policy *model.ProtectionConfig, tx *coraza.Transaction, interrupted bool, id, ip string, started time.Time, body []byte) bool {
	if !interrupted && tx.GetRiskScore() < policy.ScoreThreshold {
		return false
	}
	reason := "CRS 入站异常分达到阈值"
	if interrupted {
		reason = "规则引擎直接拒绝请求（包括显式 deny 规则）"
	}
	if !state.enforce("waf", "block", reason) || !p.wafEngine.BlockingEnabled() {
		return false
	}
	c.Set("decision_source", "waf")
	c.Set("decision_reason", reason)
	p.record(c, id, ip, started, tx, body, 403, nil, nil, "block", "")
	p.checkAutoBlock(c.Request.Context(), ip, id, policy.AutoBlockConfig())
	p.renderBlockPage(c, 403, "waf", ip, "请求被 WAF 拦截", p.calculateAttackType(tx), map[string]string{"score": fmt.Sprint(tx.GetRiskScore())})
	c.Abort()
	return true
}

func (s *decisionState) enforce(source, action, reason string) bool {
	for i, d := range s.detections {
		if d.Source == source {
			s.detections[i] = model.Detection{Source: source, Action: action, Reason: reason}
			return s.mode == "block" && action == "block"
		}
	}
	s.detections = append(s.detections, model.Detection{Source: source, Action: action, Reason: reason})
	return s.mode == "block" && action == "block"
}

func (s *decisionState) hasSource(source string) bool {
	for _, d := range s.detections {
		if d.Source == source {
			return true
		}
	}
	return false
}

func (s *decisionState) reason() string {
	if len(s.detections) == 0 {
		return "请求已转发至业务上游"
	}
	if s.mode == "monitor" {
		return "观察模式：记录检测结果，未执行阻断、延迟或自动封禁"
	}
	return "检测完成，请求已转发至业务上游；具体依据见检测记录"
}
