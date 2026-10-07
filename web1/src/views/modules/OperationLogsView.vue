<template>
  <div class="logs-page">
    <!-- Statistics Overview -->
    <div class="stats-grid" v-if="statistics">
      <div class="stat-card">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ statistics.total || 0 }}</div>
          <div class="stat-label">总操作数</div>
        </div>
      </div>
      <div class="stat-card success">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
            <polyline points="22,4 12,14.01 9,11.01"/>
          </svg>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ statistics.success || 0 }}</div>
          <div class="stat-label">成功</div>
        </div>
      </div>
      <div class="stat-card danger">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ statistics.failed || 0 }}</div>
          <div class="stat-label">失败</div>
        </div>
      </div>
    </div>
    <div class="stats-grid" v-else>
      <div class="stat-card loading">
        <span>加载中...</span>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters-bar">
      <div class="filter-group">
        <input
          v-model="filters.keyword"
          type="text"
          class="input search-input"
          placeholder="搜索操作内容"
          @keyup.enter="fetchLogs"
        />
        <select v-model="filters.action" class="input select-input" @change="fetchLogs">
          <option value="">全部操作</option>
          <optgroup v-for="cat in categories" :key="cat" :label="cat">
            <option v-for="opt in getActionsByCategory(cat)" :key="opt.value" :value="opt.value">
              {{ opt.label }}
            </option>
          </optgroup>
        </select>
        <select v-model="filters.result" class="input select-input" @change="fetchLogs">
          <option value="">全部结果</option>
          <option value="success">成功</option>
          <option value="failed">失败</option>
        </select>
        <button class="btn btn-secondary" @click="resetFilters">重置</button>
      </div>
    </div>

    <!-- Logs Table -->
    <div class="table-card">
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>用户</th>
              <th>操作</th>
              <th>资源</th>
              <th>详情</th>
              <th>IP</th>
              <th>结果</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="log in logs" :key="log.id">
              <td class="cell-time">{{ formatTime(log.created_at) }}</td>
              <td class="cell-user">{{ log.username }}</td>
              <td>
                <span class="action-badge">{{ log.action }}</span>
              </td>
              <td>{{ log.resource }}</td>
              <td class="cell-details">{{ log.details || '-' }}</td>
              <td class="cell-ip">{{ log.ip }}</td>
              <td>
                <span class="result-badge" :class="log.result">
                  {{ log.result === 'success' ? '成功' : '失败' }}
                </span>
              </td>
            </tr>
            <tr v-if="logs.length === 0">
              <td colspan="7" class="empty-cell">
                <div class="empty-state">暂无操作日志</div>
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
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { api } from '@/api'
import type { OperationLog, ActionOption } from '@/types/api'

const logs = ref<OperationLog[]>([])
const actionOptions = ref<ActionOption[]>([])
const statistics = ref<{ total: number; success: number; failed: number; by_action: unknown[]; by_user: unknown[] } | null>(null)
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)
const totalPages = computed(() => Math.ceil(total.value / pageSize.value) || 1)
const jumpPage = ref(1)

const filters = reactive({
  keyword: '',
  action: '',
  result: ''
})

const categories = computed(() => {
  const cats = new Set(actionOptions.value.map(a => a.category))
  return Array.from(cats)
})

const getActionsByCategory = (category: string) => {
  return actionOptions.value.filter(a => a.category === category)
}

const fetchLogs = async () => {
  try {
    const result = await api.operationLogs({
      page: currentPage.value,
      page_size: pageSize.value,
      keyword: filters.keyword || undefined,
      action: filters.action || undefined,
      result: filters.result || undefined
    })
    logs.value = result.list || []
    total.value = result.total || 0
  } catch (error) {
    console.error('Failed to fetch operation logs:', error)
  }
}

const goToPage = (page: number) => {
  currentPage.value = page
  fetchLogs()
}

const fetchStatistics = async () => {
  try {
    statistics.value = await api.operationLogsStatistics()
  } catch (error) {
    console.error('Failed to fetch statistics:', error)
  }
}

const fetchActions = async () => {
  try {
    actionOptions.value = await api.operationLogsActions()
  } catch (error) {
    console.error('Failed to fetch actions:', error)
  }
}

const resetFilters = () => {
  filters.keyword = ''
  filters.action = ''
  filters.result = ''
  currentPage.value = 1
  fetchLogs()
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
  fetchActions()
  fetchStatistics()
})
</script>

<style scoped>
.logs-page {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  height: 100%;
}

/* Stats Grid */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--spacing-md);
}

.stat-card {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-lg);
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
}

.stat-card.loading {
  justify-content: center;
  color: var(--color-text-muted);
}

.stat-icon {
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(59, 130, 246, 0.1);
  color: var(--color-info);
  border-radius: var(--radius-md);
}

.stat-icon svg { width: 24px; height: 24px; }

.stat-card.success .stat-icon {
  background: rgba(34, 197, 94, 0.1);
  color: var(--color-success);
}

.stat-card.danger .stat-icon {
  background: rgba(239, 68, 68, 0.1);
  color: var(--color-danger);
}

.stat-value {
  font-family: var(--font-mono);
  font-size: var(--text-2xl);
  font-weight: 700;
}

.stat-label {
  font-size: var(--text-sm);
  color: var(--color-text-muted);
}

.filters-bar {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.filter-group {
  display: flex;
  gap: var(--spacing-sm);
}

.search-input { width: 240px; }
.select-input { width: 160px; }

.table-card {
  flex: 1;
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.table-wrapper { flex: 1; overflow-x: auto; }

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

.cell-time {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--color-text-muted);
  white-space: nowrap;
}

.cell-user { font-weight: 500; }

.cell-details {
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: var(--text-sm);
}

.cell-ip {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

.action-badge {
  display: inline-block;
  padding: 2px 8px;
  background: rgba(59, 130, 246, 0.2);
  color: var(--color-info);
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
}

.result-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
}

.result-badge.success {
  background: rgba(34, 197, 94, 0.2);
  color: var(--color-success);
}

.result-badge.failed {
  background: rgba(239, 68, 68, 0.2);
  color: var(--color-danger);
}

.empty-cell { text-align: center; padding: var(--spacing-xl) !important; }
.empty-state { color: var(--color-text-muted); }

.pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md);
  border-top: 1px solid var(--color-border);
}

.pagination-info { font-size: var(--text-sm); color: var(--color-text-muted); }
.pagination-controls { display: flex; gap: var(--spacing-xs); }

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

.page-btn:hover:not(:disabled) { border-color: var(--color-accent); color: var(--color-accent); }
.page-btn:disabled { opacity: 0.5; cursor: not-allowed; }

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
</style>
