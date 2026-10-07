<template>
  <div class="logs-page">
    <!-- Filters -->
    <div class="filters-bar">
      <div class="filter-group">
        <input
          v-model="filters.keyword"
          type="text"
          class="input search-input"
          placeholder="搜索 IP / URI / 攻击类型"
          @keyup.enter="fetchLogs"
        />
        <select v-model="filters.action" class="input select-input" @change="fetchLogs">
          <option value="">全部动作</option>
          <option value="block">拦截</option>
          <option value="pass">放行</option>
        </select>
        <select v-model="filters.attack_type" class="input select-input" @change="fetchLogs">
          <option value="">全部类型</option>
          <option value="SQL Injection">SQL注入</option>
          <option value="XSS">XSS</option>
          <option value="CC攻击">CC攻击</option>
          <option value="爬虫">爬虫</option>
          <option value="RCE">命令注入</option>
          <option value="LFI">文件包含</option>
        </select>
      </div>
      <div class="filter-actions">
        <button class="btn btn-secondary" @click="resetFilters">重置</button>
        <button class="btn btn-primary" @click="fetchLogs">搜索</button>
      </div>
    </div>

    <!-- Logs Table -->
    <div class="table-card">
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>客户端IP</th>
              <th>请求方法</th>
              <th>请求URI</th>
              <th>攻击类型</th>
              <th>规则评分</th><th>处理来源</th>
              <th>动作</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="log in logs" :key="log.id" @click="viewDetail(log)">
              <td class="cell-time">{{ formatTime(log.created_at) }}</td>
              <td class="cell-ip">{{ log.client_ip }}</td>
              <td>
                <span class="method-badge" :class="log.method.toLowerCase()">{{ log.method }}</span>
              </td>
              <td class="cell-uri">{{ log.uri }}</td>
              <td>
                <span class="attack-badge" :class="getAttackClass(log.attack_type)">
                  {{ log.attack_type || (log.action === 'block' ? decisionLabel(log) : '未检出攻击') }}
                </span>
              </td>
              <td>
                <span class="score-badge" :class="getScoreClass(log.risk_score)">
                  {{ scoreLabel(log) }}
                </span>
              </td>
              <td :title="log.decision_reason">{{ decisionLabel(log) }}<small v-if="log.source_inferred">历史推断</small></td>
              <td>
                <span class="action-badge" :class="log.action">
                  {{ getActionText(log.action) }}
                </span>
              </td>
              <td class="cell-actions" @click.stop>
                <button class="action-btn" @click="viewDetail(log)">详情</button>
              </td>
            </tr>
            <tr v-if="logs.length === 0">
              <td colspan="9" class="empty-cell">
                <div class="empty-state">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                  </svg>
                  <span>暂无数据</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div class="pagination">
        <div class="pagination-info">
          共 {{ total }} 条，第 {{ currentPage }} / {{ totalPages }} 页
        </div>
        <div class="pagination-controls">
          <select class="page-size-select" v-model.number="pageSize" @change="goToPage(1)">
            <option :value="20">20条/页</option>
            <option :value="50">50条/页</option>
            <option :value="100">100条/页</option>
          </select>
          <button class="page-btn" :disabled="currentPage <= 1" @click="goToPage(1)">首页</button>
          <button class="page-btn" :disabled="currentPage <= 1" @click="goToPage(currentPage - 1)">上一页</button>
          <button class="page-btn" :disabled="currentPage >= totalPages" @click="goToPage(currentPage + 1)">下一页</button>
          <button class="page-btn" :disabled="currentPage >= totalPages" @click="goToPage(totalPages)">末页</button>
          <span class="page-jump">
            跳转<input type="number" class="page-jump-input" :min="1" :max="totalPages" v-model.number="jumpPage" @keyup.enter="goToPage(jumpPage)" />页
          </span>
        </div>
      </div>
    </div>

    <!-- Detail Modal -->
    <div class="modal-overlay" v-if="showDetail" @click="closeDetail">
      <div class="modal-content large" @click.stop>
        <div class="modal-header">
          <h3>日志详情 #{{ detailData?.log?.id }}</h3>
          <button class="close-btn" @click="closeDetail">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <div class="modal-body" v-if="detailData && detailData.log">
<div class="detail-section">
            <h4>基本信息</h4>
            <div class="detail-grid">
              <div class="detail-item">
                <span class="detail-label">请求ID</span>
                <span class="detail-value mono">{{ detailData.log.request_id || '-' }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">被防护网站</span>
                <span class="detail-value">{{ detailData.log.site_name || '-' }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">时间</span>
                <span class="detail-value">{{ formatTime(detailData.log.created_at) }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">客户端IP</span>
                <span class="detail-value mono">{{ detailData.log.client_ip }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">请求方法</span>
                <span class="detail-value">{{ detailData.log.method }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">攻击类型</span>
                <span class="detail-value">{{ detailData.log.attack_type || '-' }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">风险评分</span>
                <span class="detail-value">{{ scoreLabel(detailData.log) }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">处理动作</span>
                <span class="detail-value">{{ getActionText(detailData.log.action) }}</span>
              </div>
              <div class="detail-item" v-if="detailData.log.response_code !== undefined">
                <span class="detail-label">响应码</span>
                <span class="detail-value">{{ detailData.log.response_code }}</span>
              </div>
              <div class="detail-item" v-if="detailData.log.duration !== undefined">
                <span class="detail-label">耗时</span>
                <span class="detail-value">{{ detailData.log.duration }}ms</span>
              </div>
            </div>
          </div>

          <div class="detail-section">
            <h4>处理依据</h4><p>{{ decisionLabel(detailData.log) }} · {{ detailData.log.decision_reason || '未记录具体原因' }}</p><p v-if="!detailData.log.rule_evaluated">{{ detailData.log.source_inferred ? '历史日志缺少完整规则执行信息，处理来源按已记录信息推断。' : '此请求未经过规则评分，拦截可以由限流、名单等策略决定。' }}</p></div><div class="detail-section"><h4>请求包</h4>
            <pre class="http-packet">{{ formatRequestPacket() }}</pre>
          </div>

          <div class="detail-section" v-if="detailData.log.body">
            <h4>请求体</h4>
            <pre class="http-packet body-packet">{{ decodeBody(detailData.log.body) }}</pre>
          </div>

          <div class="detail-section" v-if="detailData.log.response_headers">
            <h4>响应头</h4>
            <pre class="http-packet">{{ formatResponsePacket() }}</pre>
          </div>

          <div class="detail-section" v-if="detailData.log.response_body">
            <h4>响应体</h4>
            <pre class="http-packet body-packet">{{ decodeBody(detailData.log.response_body) }}</pre>
          </div>

        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="closeDetail">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { api } from '@/api'
import { decisionLabel, scoreLabel, decodeBody } from '@/utils/request'
import type { RequestLog } from '@/types/api'

const logs = ref<RequestLog[]>([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)
const jumpPage = ref(1)
const showDetail = ref(false)
const detailData = ref<{ log: RequestLog; total_score?: number; matches?: Array<{ id: number; rule_id: string; score: number; rule_msg: string; matched_data?: string }> } | null>(null)

// 站点名称缓存
const siteNames = ref<Record<number, string>>({})

const filters = reactive({
  keyword: '',
  action: '',
  attack_type: ''
})

const totalPages = computed(() => Math.ceil(total.value / pageSize.value) || 1)

// 获取站点名称
const fetchSiteNames = async () => {
  try {
    const result = await api.sites({ page: 1, page_size: 1000 })
    const sites = result.list || []
    sites.forEach((site: { id: number; name: string }) => {
      siteNames.value[site.id] = site.name
    })
  } catch (error) {
    console.error('Failed to fetch site names:', error)
  }
}

const fetchLogs = async () => {
  try {
    const params: Record<string, string | number | undefined> = {
      page: currentPage.value,
      page_size: pageSize.value,
      action: filters.action || undefined,
      keyword: filters.keyword || undefined,
      attack_type: filters.attack_type || undefined
    }

    const result = await api.logs(params)
    logs.value = result.list || []
    total.value = result.total || 0
    // 更新日志的站点名称
    logs.value.forEach(log => {
      if (log.site_id && siteNames.value[log.site_id]) {
        log.site_name = siteNames.value[log.site_id]
      }
    })
  } catch (error) {
    console.error('Failed to fetch logs:', error)
  }
}

const resetFilters = () => {
  filters.keyword = ''
  filters.action = ''
  filters.attack_type = ''
  currentPage.value = 1
  fetchLogs()
}

const goToPage = (page: number) => {
  currentPage.value = page
  fetchLogs()
}

const viewDetail = async (log: RequestLog) => {
  console.log('viewDetail called with log id:', log.id)
  try {
    const detail = await Promise.race([
      api.logDetail(log.id),
      new Promise<null>((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000))
    ])
    console.log('logDetail response:', detail)
    if (detail && typeof detail === 'object' && 'log' in detail) {
      detailData.value = {
        log: { ...log, ...(detail.log as RequestLog) },
        total_score: (detail as { total_score?: number }).total_score,
        matches: (detail as { matches?: Array<{ id: number; rule_id: string; score: number; rule_msg: string; matched_data?: string }> }).matches
      }
      // 添加站点名称
      if (detailData.value.log.site_id && siteNames.value[detailData.value.log.site_id]) {
        detailData.value.log.site_name = siteNames.value[detailData.value.log.site_id]
      }
    } else if (detail && typeof detail === 'object') {
      // 可能是直接返回的 log 对象
      detailData.value = { log: { ...log, ...(detail as unknown as RequestLog) } }
    } else {
      // API 返回的不是期望的结构，直接使用传入的 log
      detailData.value = { log }
    }
    showDetail.value = true
  } catch (error) {
    console.error('Failed to fetch log detail:', error)
    // 即使 API 调用失败，也显示列表页的简要数据
    detailData.value = { log }
    showDetail.value = true
  }
}

const closeDetail = () => {
  showDetail.value = false
  detailData.value = null
}

const formatTime = (time: string): string => {
  if (!time) return '-'
  const date = new Date(time)
  return date.toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

const getAttackClass = (type: string): string => {
  if (!type) return ''
  if (type.includes('SQL')) return 'sql'
  if (type.includes('XSS')) return 'xss'
  if (type.includes('CC')) return 'cc'
  if (type.includes('爬虫')) return 'crawler'
  return ''
}

const getScoreClass = (score: number): string => {
  if (score >= 80) return 'high'
  if (score >= 50) return 'medium'
  return 'low'
}

const getActionText = (action: string): string => {
  switch (action) {
    case 'block': return '拦截'
    case 'pass': return '放行'
    case 'allow': return '放行'
    default: return action
  }
}

const parseHeaders = (headersStr: unknown): Record<string, unknown> => {
  if (!headersStr) return {}
  // 如果是字符串，尝试解析 JSON
  if (typeof headersStr === 'string') {
    // 跳过已经是格式化好的 HTTP 头字符串（如 "Host: xxx\nAccept: yyy"）
    if (headersStr.includes(': ') && !headersStr.trim().startsWith('{')) {
      const obj: Record<string, unknown> = {}
      headersStr.split('\n').forEach(line => {
        const idx = line.indexOf(':')
        if (idx > 0) {
          const key = line.substring(0, idx).trim()
          const val = line.substring(idx + 1).trim()
          obj[key] = val
        }
      })
      return obj
    }
    try {
      const parsed = JSON.parse(headersStr)
      // 如果解析后是数组
      if (Array.isArray(parsed)) {
        // 检查是否是 [["key", "value"], ...] 格式
        if (parsed.length > 0 && Array.isArray(parsed[0])) {
          const obj: Record<string, unknown> = {}
          parsed.forEach((item: unknown[]) => {
            if (Array.isArray(item) && item.length >= 2) {
              obj[String(item[0])] = item[1]
            }
          })
          return obj
        }
        // 如果是 ["key: value", ...] 格式
        if (typeof parsed[0] === 'string') {
          const obj: Record<string, unknown> = {}
          parsed.forEach((line: string) => {
            const idx = line.indexOf(':')
            if (idx > 0) {
              const key = line.substring(0, idx).trim()
              const val = line.substring(idx + 1).trim()
              obj[key] = val
            }
          })
          return obj
        }
      }
      // 如果解析后是对象但键是数字索引（字符数组被错误解析）
      if (typeof parsed === 'object' && parsed !== null) {
        const keys = Object.keys(parsed)
        const isCharArray = keys.every(k => /^\d+$/.test(k))
        if (isCharArray && keys.length > 50) {
          // 这可能是字符数组，转回字符串再解析
          const str = keys.sort((a, b) => Number(a) - Number(b)).map(k => String(parsed[k as keyof typeof parsed])).join('')
          return parseHeaders(str)
        }
      }
      return parsed as Record<string, unknown>
    } catch {
      return {}
    }
  }
  // 如果已经是对象
  if (typeof headersStr === 'object') return headersStr as Record<string, unknown>
  return {}
}

const formatRequestPacket = (): string => {
  if (!detailData.value?.log) return ''
  const lines: string[] = []
  // 请求行
  lines.push(`${detailData.value.log.method || 'GET'} ${detailData.value.log.uri || '/'} HTTP/1.1`)
  // 请求头
  const headers = parseHeaders(detailData.value.log.headers) || {}
  Object.entries(headers).forEach(([key, val]) => {
    lines.push(`${key}: ${formatHeaderValue(val)}`)
  })
  return lines.join('\n')
}

const formatResponsePacket = (): string => {
  if (!detailData.value?.log) return ''
  const lines: string[] = []
  // 状态行
  const statusCode = detailData.value.log.response_code || 200
  const statusText = getStatusText(statusCode)
  lines.push(`HTTP/1.1 ${statusCode} ${statusText}`)
  // 响应头
  const headers = parseHeaders(detailData.value.log.response_headers) || {}
  Object.entries(headers).forEach(([key, val]) => {
    lines.push(`${key}: ${formatHeaderValue(val)}`)
  })
  return lines.join('\n')
}

const formatHeaderValue = (val: unknown): string => {
  if (Array.isArray(val)) return val.map(v => String(v)).join(', ')
  if (val && typeof val === 'object') return JSON.stringify(val)
  return String(val ?? '')
}

const getStatusText = (code: number): string => {
  const statusMap: Record<number, string> = {
    200: 'OK',
    301: 'Moved Permanently',
    302: 'Found',
    304: 'Not Modified',
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    500: 'Internal Server Error',
    502: 'Bad Gateway',
    503: 'Service Unavailable'
  }
  return statusMap[code] || ''
}

onMounted(() => {
  fetchSiteNames()
  fetchLogs()
})
</script>

<style scoped>
.logs-page {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  height: 100%;
}

.filters-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--spacing-md);
  flex-wrap: wrap;
}

.filter-group {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
}

.search-input {
  width: 260px;
}

.select-input {
  width: 130px;
}

.filter-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.table-card {
  flex: 1;
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.table-wrapper {
  flex: 1;
  overflow-x: auto;
}

.data-table {
  width: 100%;
  border-collapse: collapse;
}

.data-table th,
.data-table td {
  padding: var(--spacing-sm) var(--spacing-md);
  text-align: left;
  border-bottom: 1px solid var(--color-border);
}

.data-table th {
  background: var(--color-secondary);
  font-size: var(--text-sm);
  font-weight: 600;
  color: var(--color-text-secondary);
  white-space: nowrap;
}

.data-table tr {
  cursor: pointer;
  transition: background var(--transition-fast);
}

.data-table tbody tr:hover {
  background: var(--color-secondary);
}

.cell-time {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--color-text-muted);
  white-space: nowrap;
}

.cell-ip {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
}

.cell-uri {
  max-width: 250px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  font-size: var(--text-sm);
}

.method-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
  font-weight: 600;
  font-family: var(--font-mono);
}

.method-badge.get { background: rgba(34, 197, 94, 0.2); color: var(--color-success); }
.method-badge.post { background: rgba(59, 130, 246, 0.2); color: var(--color-info); }
.method-badge.put { background: rgba(245, 158, 11, 0.2); color: var(--color-warning); }
.method-badge.delete { background: rgba(239, 68, 68, 0.2); color: var(--color-danger); }
.method-badge.patch { background: rgba(139, 92, 246, 0.2); color: #8B5CF6; }

.attack-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
}

.attack-badge.sql { background: rgba(239, 68, 68, 0.2); color: var(--color-danger); }
.attack-badge.xss { background: rgba(245, 158, 11, 0.2); color: var(--color-warning); }
.attack-badge.cc { background: rgba(139, 92, 246, 0.2); color: #8B5CF6; }
.attack-badge.crawler { background: rgba(59, 130, 246, 0.2); color: var(--color-info); }

.score-badge {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  font-weight: 600;
}

.score-badge.high { color: var(--color-danger); }
.score-badge.medium { color: var(--color-warning); }
.score-badge.low { color: var(--color-text-muted); }

.action-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
}

.action-badge.block { background: rgba(239, 68, 68, 0.2); color: var(--color-danger); }
.action-badge.allow { background: rgba(34, 197, 94, 0.2); color: var(--color-success); }
.action-badge.detect { background: rgba(59, 130, 246, 0.2); color: var(--color-info); }
.action-badge.log { background: rgba(100, 116, 139, 0.2); color: var(--color-text-muted); }

.cell-actions {
  white-space: nowrap;
}

.action-btn {
  padding: 4px 12px;
  font-size: var(--text-xs);
  color: var(--color-accent);
  background: transparent;
  border: 1px solid var(--color-accent);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.action-btn:hover {
  background: var(--color-accent);
  color: var(--color-on-primary);
}

.empty-cell {
  text-align: center;
  padding: var(--spacing-xl) !important;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-sm);
  color: var(--color-text-muted);
}

.empty-state svg {
  width: 48px;
  height: 48px;
  opacity: 0.5;
}

/* Pagination */
.pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md);
  border-top: 1px solid var(--color-border);
}

.pagination-info {
  font-size: var(--text-sm);
  color: var(--color-text-muted);
}

.pagination-controls {
  display: flex;
  gap: var(--spacing-xs);
}

.page-btn {
  padding: var(--spacing-xs) var(--spacing-md);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  background: var(--color-secondary);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.page-btn:hover:not(:disabled) {
  border-color: var(--color-accent);
  color: var(--color-accent);
}

.page-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.page-size-select {
  padding: var(--spacing-xs) var(--spacing-sm);
  font-size: var(--text-sm);
  color: var(--color-text);
  background: var(--color-secondary);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  cursor: pointer;
}

.page-jump {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
}

.page-jump-input {
  width: 60px;
  padding: var(--spacing-xs) var(--spacing-sm);
  font-size: var(--text-sm);
  color: var(--color-text);
  background: var(--color-secondary);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  text-align: center;
}

.page-jump-input:focus {
  outline: none;
  border-color: var(--color-accent);
}

/* Modal */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: var(--z-modal);
}

.modal-content {
  width: 600px;
  max-height: 85vh;
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.modal-content.large {
  width: 800px;
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md) var(--spacing-lg);
  border-bottom: 1px solid var(--color-border);
}

.modal-header h3 {
  font-size: var(--text-lg);
  font-weight: 600;
}

.close-btn {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--color-text-muted);
  border-radius: var(--radius-sm);
  transition: all var(--transition-fast);
}

.close-btn:hover {
  background: var(--color-secondary);
  color: var(--color-foreground);
}

.close-btn svg {
  width: 18px;
  height: 18px;
}

.modal-body {
  padding: var(--spacing-lg);
  overflow-y: auto;
  flex: 1;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  padding: var(--spacing-md) var(--spacing-lg);
  border-top: 1px solid var(--color-border);
}

/* Detail Sections */
.detail-section {
  margin-bottom: var(--spacing-lg);
}

.detail-section:last-child {
  margin-bottom: 0;
}

.detail-section h4 {
  font-size: var(--text-sm);
  font-weight: 600;
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-md);
  text-transform: uppercase;
  letter-spacing: 1px;
}

.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md);
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.detail-item.full {
  grid-column: span 2;
}

.detail-label {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
  text-transform: uppercase;
}

.detail-value {
  font-size: var(--text-sm);
  color: var(--color-foreground);
}

.detail-value.mono {
  font-family: var(--font-mono);
  word-break: break-all;
}

.detail-code {
  background: var(--color-secondary);
  padding: var(--spacing-md);
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 200px;
  overflow-y: auto;
  margin: 0;
}

.rules-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-sm);
}

.rule-tag {
  display: inline-block;
  padding: 4px 12px;
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--color-accent);
}

.http-packet {
  background: var(--color-secondary);
  padding: var(--spacing-md);
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  white-space: pre-wrap;
  word-break: break-all;
  line-height: 1.6;
  margin: 0;
  border-left: 3px solid var(--color-accent);
}

.http-packet.body-packet {
  border-left-color: var(--color-info);
  max-height: 300px;
  overflow-y: auto;
}
.cell-actions+td small,td small{display:block;font-size:12px;color:var(--color-text-muted)}
</style>
