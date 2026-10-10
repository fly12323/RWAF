import type { RequestLog } from '@/types/api'

export const decisionLabels: Record<string, string> = { cc: 'CC 限流', ipban: 'IP 黑名单', crawler: '爬虫防护', waf: '规则引擎', body_limit: '请求体限制', upstream: '业务转发', unknown: '历史来源未知', policy_error: '策略读取失败', ip_list_error: '名单读取失败', cc_error: '限流服务错误', waf_error: '规则处理错误', client_error: '请求取消' }
export function protectionModeLabel(mode?: string) { return mode === 'monitor' ? '观察模式' : mode === 'block' ? '拦截模式' : mode === 'off' ? '防护关闭' : '未记录' }
export function scoreBasisLabel(log: RequestLog) { return log.score_basis === 'crs_anomaly' ? 'CRS 入站异常分' : log.protection_mode && !log.rule_evaluated ? '未经过规则评分' : '历史评分（旧口径）' }
export function detectionActionLabel(action: string) { return ({ block: '建议阻断', delay: '建议等待', log: '仅记录' } as Record<string,string>)[action] || action }
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
