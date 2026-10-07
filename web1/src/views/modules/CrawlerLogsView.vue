<template>
  <div class="crawler-logs-page">
    <!-- Page Header -->
    <div class="page-header">
      <div class="header-left">
        <h2>爬虫检测日志</h2>
      </div>
      <div class="header-right">
        <select v-model="filters.type" class="input select-input" @change="fetchLogs">
          <option value="">全部类型</option>
          <option value="bot">爬虫</option>
          <option value="scanner">扫描器</option>
          <option value="crawler">搜索引擎</option>
          <option value="human">正常用户</option>
        </select>
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
              <th>类型</th>
              <th>爬虫名称</th>
              <th>置信度</th>
              <th>User-Agent</th>
              <th>请求信息</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="log in logs" :key="log.id">
              <td class="cell-time">{{ formatTime(log.created_at) }}</td>
              <td class="cell-ip">{{ log.client_ip }}</td>
              <td>
                <span class="type-badge" :class="log.crawler_type">{{ getTypeName(log.crawler_type) }}</span>
              </td>
              <td>{{ log.crawler_name || '-' }}</td>
              <td>
                <div class="confidence-bar">
                  <div
                    class="confidence-fill"
                    :class="log.confidence >= 0.8 ? 'high' : log.confidence >= 0.5 ? 'medium' : 'low'"
                    :style="{ width: `${log.confidence * 100}%` }"
                  ></div>
                </div>
                <span class="confidence-text">{{ (log.confidence * 100).toFixed(0) }}%</span>
              </td>
              <td class="cell-ua" :title="log.user_agent || ''">{{ log.user_agent || '-' }}</td>
              <td class="cell-req">
                <span class="method-badge">{{ log.method }}</span>
                <span class="uri-text" :title="log.uri || ''">{{ log.uri }}</span>
              </td>
              <td class="cell-actions">
                <button class="action-btn" @click="viewDetail(log)">详情</button>
              </td>
            </tr>
            <tr v-if="logs.length === 0">
              <td colspan="8" class="empty-cell">
                <div class="empty-state">暂无数据</div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
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
    <div class="modal-overlay" v-if="showDetail" @click="showDetail = false">
      <div class="modal-content large" @click.stop>
        <div class="modal-header">
          <h3>爬虫检测日志详情</h3>
          <button class="close-btn" @click="showDetail = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <div class="modal-body" v-if="detailData">
          <div class="detail-grid">
            <div class="detail-item">
              <span class="detail-label">日志ID</span>
              <span class="detail-value">{{ detailData.id }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">请求ID</span>
              <span class="detail-value">{{ detailData.request_id || '-' }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">客户端IP</span>
              <span class="detail-value">{{ detailData.client_ip }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">请求方法</span>
              <span class="detail-value">{{ detailData.method }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">爬虫类型</span>
              <span class="type-badge" :class="detailData.crawler_type">{{ getTypeName(detailData.crawler_type) }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">爬虫名称</span>
              <span class="detail-value">{{ detailData.crawler_name || '-' }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">置信度</span>
              <span class="detail-value">{{ (detailData.confidence * 100).toFixed(1) }}%</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">处理动作</span>
              <span class="detail-value">{{ detailData.action || '-' }}</span>
            </div>
            <div class="detail-item full">
              <span class="detail-label">请求URI</span>
              <span class="detail-value mono">{{ detailData.uri }}</span>
            </div>
          </div>

          <div class="detail-section" v-if="detailData.user_agent">
            <h4>User-Agent</h4>
            <div class="code-block">{{ detailData.user_agent }}</div>
          </div>

          <div class="detail-section" v-if="detailData.detection_rules && detailData.detection_rules.length > 0">
            <h4>检测规则</h4>
            <div class="rules-grid">
              <span v-for="(rule, idx) in detailData.detection_rules" :key="idx" class="rule-tag">{{ rule }}</span>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="showDetail = false">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { api } from '@/api'
import type { CrawlerLog } from '@/types/api'

const logs = ref<CrawlerLog[]>([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)
const totalPages = computed(() => Math.ceil(total.value / pageSize.value) || 1)
const filters = reactive({ type: '' })

const showDetail = ref(false)
const detailData = ref<CrawlerLog | null>(null)
const jumpPage = ref(1)

const fetchLogs = async () => {
  try {
    const result = await api.crawlerLogs({
      page: currentPage.value,
      page_size: pageSize.value,
      type: filters.type || undefined
    }) as unknown as { list: CrawlerLog[]; total: number }
    logs.value = result.list || []
    total.value = result.total || 0
  } catch (error) {
    console.error('Failed to fetch crawler logs:', error)
  }
}

const goToPage = (page: number) => {
  currentPage.value = page
  fetchLogs()
}

const viewDetail = async (log: CrawlerLog) => {
  try {
    detailData.value = await api.crawlerLogDetail(log.id) as unknown as CrawlerLog
    showDetail.value = true
  } catch (error) {
    console.error('Failed to fetch log detail:', error)
  }
}

const getTypeName = (type: string): string => {
  const typeMap: Record<string, string> = {
    bot: '爬虫',
    scanner: '扫描器',
    crawler: '搜索引擎',
    human: '正常用户'
  }
  return typeMap[type] || type
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

onMounted(() => {
  fetchLogs()
})
</script>

<style scoped>
.crawler-logs-page {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  height: 100%;
  overflow-y: auto;
}

.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-sm) 0;
}

.page-header h2 {
  font-size: var(--text-lg);
  font-weight: 600;
}

.header-right {
  display: flex;
  gap: var(--spacing-sm);
}

.select-input {
  width: 120px;
}

.table-card {
  flex: 1;
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.table-wrapper {
  flex: 1;
  overflow-x: auto;
  overflow-y: auto;
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
  font-size: var(--text-sm);
}

.data-table th {
  background: var(--color-secondary);
  font-weight: 600;
  color: var(--color-text-secondary);
  position: sticky;
  top: 0;
  z-index: 1;
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

.cell-ua {
  max-width: 150px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

.cell-req {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  max-width: 200px;
}

.method-badge {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  padding: 2px 6px;
  background: rgba(59, 130, 246, 0.2);
  color: var(--color-info);
  border-radius: var(--radius-sm);
  flex-shrink: 0;
}

.uri-text {
  font-size: var(--text-xs);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cell-actions {
  white-space: nowrap;
}

.empty-cell {
  text-align: center;
  padding: var(--spacing-xl) !important;
}

.empty-state {
  color: var(--color-text-muted);
}

/* Type Badge */
.type-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
  font-weight: 500;
}

.type-badge.bot {
  background: rgba(59, 172, 254, 0.2);
  color: #4facfe;
}

.type-badge.scanner {
  background: rgba(255, 59, 92, 0.2);
  color: #ff3b5c;
}

.type-badge.crawler {
  background: rgba(255, 107, 53, 0.2);
  color: #ff6b35;
}

.type-badge.human {
  background: rgba(0, 212, 170, 0.2);
  color: #00d4aa;
}

/* Confidence Bar */
.confidence-bar {
  width: 50px;
  height: 4px;
  background: var(--color-border);
  border-radius: 2px;
  overflow: hidden;
  display: inline-block;
  vertical-align: middle;
}

.confidence-fill {
  height: 100%;
  border-radius: 2px;
}

.confidence-fill.low { background: #00d4aa; }
.confidence-fill.medium { background: #ff6b35; }
.confidence-fill.high { background: #ff3b5c; }

.confidence-text {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
  margin-left: var(--spacing-xs);
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

/* Action Button */
.action-btn {
  padding: 4px 12px;
  font-size: var(--text-xs);
  color: var(--color-text-secondary);
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.action-btn:hover {
  border-color: var(--color-accent);
  color: var(--color-accent);
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
  width: 500px;
  max-height: 80vh;
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.modal-content.large {
  width: 700px;
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

/* Detail Styles */
.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md);
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-item.full {
  grid-column: 1 / -1;
}

.detail-label {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
  font-weight: 500;
}

.detail-value {
  font-size: var(--text-sm);
}

.detail-value.mono {
  font-family: var(--font-mono);
  word-break: break-all;
}

.detail-section {
  margin-top: var(--spacing-lg);
}

.detail-section h4 {
  font-size: var(--text-sm);
  font-weight: 600;
  margin-bottom: var(--spacing-sm);
}

.code-block {
  padding: var(--spacing-md);
  background: var(--color-secondary);
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  word-break: break-all;
  white-space: pre-wrap;
}

.rules-grid {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-xs);
}

.rule-tag {
  padding: 4px 10px;
  background: rgba(139, 92, 246, 0.2);
  color: #8B5CF6;
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
}
</style>