export interface ApiResp<T> {
  code: number
  message: string
  data: T
}

export interface PageData<T> {
  list: T[]
  total: number
  page: number
  page_size: number
}

export interface UserInfo {
	 must_change_password?: boolean
  id: number
  username: string
  nickname?: string
  role: string
  status: number
  last_login?: string
  created_at?: string
}

export interface AuthEndpoint {
  name: string; host: string; path: string; method: string; kind: string; format: string; password_fields: string[]
}
export interface WeakPasswordConfig {
  enabled: boolean; dictionary: string[]; representations: string[]; endpoints: AuthEndpoint[]
}
export interface WeakPasswordEvent {
  id: number; request_id: string; site_id: number; client_ip: string; endpoint: string; kind: string; path: string
  representation: string; dictionary_version: string; outcome: string; created_at: string
}
export interface MonitorConfig {
  enabled: boolean; interval_seconds: number; kafka_lag_threshold: number; queue_percent: number
  consumer_timeout_seconds: number; heap_limit_mb: number; proxy_error_percent: number; proxy_min_requests: number; proxy_p99_ms: number
}
export interface RuntimeSnapshot {
  sampled_at?: string; uptime_seconds: number; dependencies: Record<string, string>; kafka_lag: number | null
  consumer: { state?: string; stale?: boolean; heartbeat_at?: number; persisted?: number } | null
  log_pipeline: Record<string, number>; weak_password: Record<string, number | string | boolean>
  requests: { requests?: number; errors_5xx?: number; rps?: number; average_ms?: number; p99_bucket_ms?: number; error_percent?: number }
  heap_mb: number; goroutines: number; conditions: { key: string; severity: string; message: string }[]
  config_error: boolean; alert_store_error: boolean; alerts_enabled: boolean
}
export interface SecurityAlert {
  id: number; key: string; source: string; severity: string; message: string; status: string; occurrences: number
  created_at: string; last_seen: string; resolved_at?: string; acknowledged_at?: string; acknowledged_by: string
}

export interface Site {
	 tls_enabled: boolean
	 tls_certificate?: string
  id: number
  name: string
  domains: string | string[]
  listen_port: number
  upstream_targets: string | { host: string; port: number; weight: number }[]
  enabled: boolean
}

export interface Rule {
  id: number
  rule_id: string
  rule_file?: string
  category?: string
  severity?: string
  score?: number
  description?: string
  rule_content?: string
  enabled: boolean
  is_custom?: boolean
}

export interface RequestLog {
  id: number
  site_id?: number
  site_name?: string
  request_id?: string
  client_ip: string
  method: string
  uri: string
  risk_score: number
  attack_type: string
  decision_source?: string
  decision_reason?: string
  rule_evaluated?: boolean
  source_inferred?: boolean
  action: string
  created_at: string
  headers?: Record<string, unknown>
  body?: string
  response_code?: number
  response_headers?: Record<string, unknown>
  response_body?: string
  duration?: number
  total_score?: number
  matches?: Array<{
    id: number
    rule_id: string
    score: number
    rule_msg: string
    matched_data?: string
  }>
}

export interface IPItem {
  id: number
  ip: string
  reason?: string
  status: number
  type?: number
  expire_at?: string
}

export interface ProtectionConfig {
  id?: number
  enabled: boolean
  waf_mode: string
  score_threshold: number
  enabled_rule_categories: string[]
  disabled_rule_ids: string[]
  rule_engine_enabled: boolean
  crawler_detection_enabled: boolean
  crawler_scanner_action: string
  crawler_bot_action: string
  crawler_crawler_action: string
  cc_protection_enabled: boolean
  auto_block_enabled: boolean
  ip_blacklist_enabled: boolean
  ip_whitelist_enabled: boolean
  cc_requests_per_minute: number
  cc_action: string
  cc_delay_ms: number
  cc_uri_limits: string
  auto_block_threshold: number
  auto_block_duration: number
  auto_block_hours: number
}

export interface OperationLog {
  id: number
  user_id: number
  username: string
  action: string
  resource: string
  resource_id: number
  details: string
  ip: string
  user_agent?: string
  result: string
  error_msg?: string
  created_at: string
}

export interface OperationLogStatistics {
  total: number
  success: number
  failed: number
  by_action: Array<{ action: string; count: number }>
  by_user: Array<{ username: string; count: number }>
}

export interface ActionOption {
  value: string
  label: string
  category: string
}

// WAF Status
export interface WAFStatus {
  status: string
  site_count: number
  waf_mode: string
  online_users: number
}

// Statistics
export interface LogStatistics {
  total: number
  by_action: Array<{ action: string; count: number }>
}

export interface AttackType {
  attack_type: string
  count: number
}

export interface LogTrend {
  hour: string
  total: number
  block_count: number
}

export interface AttackIP {
  client_ip: string
  attack_count: number
  attack_types: string
  first_attack: string
  last_attack: string
}

export interface AttackGeo {
  client_ip: string
  attack_count: number
  attack_types: string
  country: string
  region: string
  city: string
  lat: number
  lon: number
}

// Crawler
export interface CrawlerStats {
  total_requests: number
  bot_count: number
  scanner_count: number
  crawler_count: number
  bot_rate: number
  scanner_rate: number
}

export interface CrawlerLog {
  id: number
  request_id?: string
  site_id?: number
  client_ip: string
  method: string
  uri: string
  crawler_type: string
  crawler_name?: string
  confidence: number
  action?: string
  user_agent?: string
  created_at: string
  detection_rules?: string[]
}

export interface CrawlerTrend {
  hour: string
  count: number
  bot_count: number
  scanner_count: number
  crawler_count: number
}
