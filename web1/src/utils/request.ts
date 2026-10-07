import type { RequestLog } from '@/types/api'

export const decisionLabels: Record<string, string> = { cc: 'CC 限流', ipban: 'IP 黑名单', crawler: '爬虫防护', waf: '规则引擎', body_limit: '请求体限制', upstream: '业务转发', unknown: '历史来源未知' }
export function decisionLabel(log: RequestLog) { return decisionLabels[log.decision_source || ''] || (log.action === 'block' ? '来源未记录' : '业务转发') }
export function scoreLabel(log: RequestLog) { return log.rule_evaluated || log.risk_score > 0 ? String(log.risk_score) : log.source_inferred && log.decision_source !== 'cc' ? '未记录' : '未评分' }
export function decodeBody(body?: string): string {
  if (!body) return ''
  try { return new TextDecoder().decode(Uint8Array.from(atob(body), char => char.charCodeAt(0))) } catch { return body }
}
export function headerLines(input: unknown): string {
  try {
    const headers = typeof input === 'string' ? JSON.parse(input) : input
    if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return ''
    return Object.entries(headers).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : String(value)}`).join('\n')
  } catch { return '' }
}
