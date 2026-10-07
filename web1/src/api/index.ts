import { http } from './http'
import type {
  WeakPasswordConfig, WeakPasswordEvent, MonitorConfig, RuntimeSnapshot, SecurityAlert,
  PageData,
  RequestLog,
  Rule,
  Site,
  UserInfo,
  IPItem,
  ProtectionConfig,
  OperationLog,
  OperationLogStatistics,
  ActionOption,
  WAFStatus,
  LogStatistics,
  AttackType,
  LogTrend,
  AttackIP,
  AttackGeo,
  CrawlerStats,
  CrawlerTrend
} from '../types/api'

const q = (params: Record<string, string | number | undefined | null>) => {
  const sp = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v))
  })
  return sp.toString() ? `?${sp.toString()}` : ''
}

const get = <T>(url: string) => http.get<unknown, T>(url)
const post = <T>(url: string, data?: unknown) => http.post<unknown, T>(url, data)
const put = <T>(url: string, data?: unknown) => http.put<unknown, T>(url, data)
const del = <T>(url: string) => http.delete<unknown, T>(url)

export const api = {
  weakPasswordConfig: () => get<WeakPasswordConfig>('/api/v1/weak-password/config'),
  previewWeakPassword: (value: string) => post<Record<string, string>>('/api/v1/weak-password/preview', { value }),
  updateWeakPasswordConfig: (v: WeakPasswordConfig) => put<WeakPasswordConfig>('/api/v1/weak-password/config', v),
  weakPasswordEvents: (page = 1, kind = '') => get<PageData<WeakPasswordEvent> & { stats: Record<string, number | string | boolean> }>(`/api/v1/weak-password/events?page=${page}&kind=${encodeURIComponent(kind)}`),
  weakPasswordEventDetail: (id: number) => get<{ event: WeakPasswordEvent; request: { log: RequestLog; matches: NonNullable<RequestLog['matches']> } | null; site_name?: string; request_notice?: string }>(`/api/v1/weak-password/events/${id}`),
  monitorStatus: () => get<RuntimeSnapshot>('/api/v1/monitor/status'),
  monitorConfig: () => get<MonitorConfig>('/api/v1/monitor/config'),
  updateMonitorConfig: (v: MonitorConfig) => put<MonitorConfig>('/api/v1/monitor/config', v),
  alerts: (page = 1, status = '', source = '') => get<PageData<SecurityAlert>>(`/api/v1/monitor/alerts${q({ page, status, source })}`),
  acknowledgeAlert: (id: number) => post<null>(`/api/v1/monitor/alerts/${id}/acknowledge`),
  resolveWeakAlert: (id: number) => post<null>(`/api/v1/monitor/alerts/${id}/resolve`),
  // Health
  health: () => get<Record<string, unknown>>('/health'),

  // Auth
  login: (username: string, password: string) =>
    post<{ token: string; user: UserInfo; expire_at: number }>('/api/v1/auth/login', { username, password }),
  me: () => get<UserInfo>('/api/v1/auth/info'),
  logout: () => post<null>('/api/v1/auth/logout'),
  changePassword: (oldPassword: string, newPassword: string) =>
    post<null>('/api/v1/auth/password', { oldPassword, newPassword }),

  // WAF
  wafStatus: () => get<WAFStatus>('/api/v1/waf/status'),
  wafReload: () => post<null>('/api/v1/waf/reload'),

  // Statistics
  stats: (params?: { start_time?: string; end_time?: string }) =>
    get<LogStatistics>(`/api/v1/logs/statistics${q(params || {})}`),
  attackTypes: () => get<AttackType[]>('/api/v1/logs/attack-types'),
  logsTrend: (params: { hours?: number; start_time?: string; end_time?: string } = {}) =>
    get<LogTrend[]>(`/api/v1/logs/trend${q(params)}`),
  attackIps: (params: { start_time?: string; end_time?: string } = {}) =>
    get<AttackIP[]>(`/api/v1/logs/attack-ips${q(params)}`),
  attackGeo: (params: { start_time?: string; end_time?: string; limit?: number } = {}) =>
    get<AttackGeo[]>(`/api/v1/logs/attack-geo${q(params)}`),

  // Sites
  sites: (params: { page?: number; page_size?: number; keyword?: string } = {}) =>
    get<PageData<Site>>(`/api/v1/sites${q(params)}`),
  createSite: (payload: Record<string, unknown>) => post<Record<string, unknown>>('/api/v1/sites', payload),
  updateSite: (id: number, payload: Record<string, unknown>) => put<Record<string, unknown>>(`/api/v1/sites/${id}`, payload),
  toggleSite: (id: number, enabled: boolean) => put<null>(`/api/v1/sites/${id}/status`, { enabled }),
  deleteSite: (id: number) => del<null>(`/api/v1/sites/${id}`),
  protectionConfig: () => get<ProtectionConfig>('/api/v1/waf/protection'),
  updateProtectionConfig: (config: ProtectionConfig) => put<ProtectionConfig>('/api/v1/waf/protection', config),

  // Rules
  rules: (params: { page?: number; page_size?: number; keyword?: string; category?: string } = {}) =>
    get<PageData<Rule>>(`/api/v1/rules${q(params)}`),
  createRule: (payload: Record<string, unknown>) => post<Record<string, unknown>>('/api/v1/rules', payload),
  updateRule: (id: number, payload: Record<string, unknown>) => put<Record<string, unknown>>(`/api/v1/rules/${id}`, payload),
  toggleRule: (id: number, enabled: boolean) => put<null>(`/api/v1/rules/${id}/status`, { enabled }),
  deleteRule: (id: number) => del<null>(`/api/v1/rules/${id}`),
  getRuleCategories: () => get<Array<{ category: string; count: number }>>('/api/v1/rules/categories'),
  getRuleStatistics: () => get<{ total: number; enabled: number; disabled: number; by_category: Array<{ category: string; count: number }> }>('/api/v1/rules/statistics'),
  reloadRules: () => post<null>('/api/v1/rules/reload'),

  // Logs
  logs: (params: Record<string, string | number | undefined>) =>
    get<PageData<RequestLog>>(`/api/v1/logs${q(params)}`),
  logDetail: (id: number) => get<Record<string, unknown>>(`/api/v1/logs/${id}`),
  deleteOldLogs: (days: number) => del<null>(`/api/v1/logs/old?days=${days}`),

  // IP Blacklist
  ipBlacklist: (params: Record<string, string | number | undefined> = { page: 1, page_size: 50 }) =>
    get<PageData<IPItem>>(`/api/v1/ip-blacklist${q(params)}`),
  createIPBlacklist: (payload: Record<string, unknown>) => post<Record<string, unknown>>('/api/v1/ip-blacklist', payload),
  toggleIPBlacklist: (id: number, status: number) => put<null>(`/api/v1/ip-blacklist/${id}/status`, { status }),
  deleteIPBlacklist: (id: number) => del<null>(`/api/v1/ip-blacklist/${id}`),
  ipBlacklistStats: () => get<{ total: number; enabled_count: number; disabled_count: number }>('/api/v1/ip-blacklist/stats'),
  autoBlockConfig: () => get<Record<string, unknown>>('/api/v1/ip-blacklist/auto-config'),
  updateAutoBlockConfig: (payload: Record<string, unknown>) => put<Record<string, unknown>>('/api/v1/ip-blacklist/auto-config', payload),
  cleanExpiredBlacklist: () => del<null>('/api/v1/ip-blacklist/expired'),

  // IP Whitelist
  ipWhitelist: (params: Record<string, string | number | undefined> = { page: 1, page_size: 50 }) =>
    get<PageData<IPItem>>(`/api/v1/ip-whitelist${q(params)}`),
  createIPWhitelist: (payload: Record<string, unknown>) => post<Record<string, unknown>>('/api/v1/ip-whitelist', payload),
  toggleIPWhitelist: (id: number, status: number) => put<null>(`/api/v1/ip-whitelist/${id}/status`, { status }),
  deleteIPWhitelist: (id: number) => del<null>(`/api/v1/ip-whitelist/${id}`),
  ipWhitelistStats: () => get<{ total: number; enabled_count: number; disabled_count: number }>('/api/v1/ip-whitelist/stats'),

  // CC Protection
  ccConfig: () => get<Record<string, unknown>>('/api/v1/cc-protection'),
  updateCCConfig: (payload: Record<string, unknown>) => put<Record<string, unknown>>('/api/v1/cc-protection', payload),

  // Crawler
  crawlerStats: () => get<CrawlerStats>('/api/v1/crawler/stats'),
  crawlerRecent: (limit = 50) => get<Array<Record<string, unknown>>>(`/api/v1/crawler/recent${q({ limit })}`),
  crawlerTrend: (params: { hours?: number } = {}) =>
    get<CrawlerTrend[]>(`/api/v1/crawler/trend${q(params)}`),
  crawlerLogs: (params: { page?: number; page_size?: number; type?: string; min_confidence?: number } = {}) =>
    get<PageData<Record<string, unknown>>>(`/api/v1/crawler/logs${q(params)}`),
  crawlerLogDetail: (id: number) => get<Record<string, unknown>>(`/api/v1/crawler/logs/${id}`),
  crawlerTopIPs: (params: { limit?: number } = {}) =>
    get<Array<{ client_ip: string; count: number; bot_count: number; scanner_count: number }>>(`/api/v1/crawler/top-ips${q(params)}`),

  // Users
  users: (params: Record<string, string | number | undefined> = { page: 1, page_size: 100 }) =>
    get<PageData<UserInfo>>(`/api/v1/users${q(params)}`),
  createUser: (payload: Record<string, unknown>) => post<Record<string, unknown>>('/api/v1/users', payload),
  toggleUser: (id: number, status: number) => put<null>(`/api/v1/users/${id}/status`, { status }),
  resetUser: (id: number, password: string) => post<null>(`/api/v1/users/${id}/reset-password`, { password }),
  deleteUser: (id: number) => del<null>(`/api/v1/users/${id}`),

  // Operation Logs
  operationLogs: (params: Record<string, string | number | undefined> = {}) =>
    get<PageData<OperationLog>>(`/api/v1/operation-logs${q(params)}`),
  operationLogsStatistics: (params: { start_time?: string; end_time?: string } = {}) =>
    get<OperationLogStatistics>(`/api/v1/operation-logs/statistics${q(params)}`),
  operationLogsActions: () => get<ActionOption[]>('/api/v1/operation-logs/actions'),
  deleteOldOperationLogs: (days: number) => del<null>(`/api/v1/operation-logs/old?days=${days}`)
}
