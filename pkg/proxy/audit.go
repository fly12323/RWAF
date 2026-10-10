package proxy

import (
	"encoding/base64"
	"encoding/json"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/pkg/coraza"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

// Audit construction is separate from transport and detector decisions.
func prefix(data []byte) []byte {
	if len(data) > captureLimit {
		return data[:captureLimit]
	}
	return data
}
func (p *ReverseProxy) record(c *gin.Context, id, ip string, started time.Time, tx *coraza.Transaction, body []byte, status int, headers http.Header, responseBody []byte, action, upstream string) {
	c.Set("request_recorded", true)
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
	if value, ok := c.Get("decision_state"); ok {
		state := value.(*decisionState)
		entry.ProtectionMode, entry.PolicyVersion, entry.Detections = state.mode, state.version, state.detections
		if tx != nil {
			entry.ScoreBasis = "crs_anomaly"
		}
		if entry.DecisionSource == "upstream" && action != "error" {
			entry.DecisionReason = state.reason()
		}
	}
	if p.publish != nil {
		_ = p.publish(events.RequestEvent(entry, matches))
	}
}
