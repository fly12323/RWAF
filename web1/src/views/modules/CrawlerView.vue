<template>
  <div class="crawler-page">
    <header class="page-heading"><div><h2>爬虫检测</h2><p>查看自动化访问、扫描器和搜索引擎的识别结果。</p></div><div class="heading-actions"><RouterLink v-if="auth.canWrite" class="btn btn-secondary" to="/protection?section=crawler">配置爬虫策略</RouterLink><button class="btn btn-secondary" :disabled="refreshing" @click="refreshAll">{{ refreshing ? '刷新中…' : '刷新数据' }}</button></div></header>
    <p v-if="errorMessage" class="error-message" role="alert">{{ errorMessage }}</p>
    <div class="overview-grid"><div class="overview-item"><span>累计检测请求</span><strong>{{ stats.total_requests || 0 }}</strong><small>所有识别类型</small></div><button class="overview-item" @click="selectType('bot')"><span>自动化爬虫</span><strong>{{ stats.bot_count || 0 }}</strong><small>占比 {{ stats.bot_rate || 0 }}%</small></button><button class="overview-item risk" @click="selectType('scanner')"><span>扫描器</span><strong>{{ stats.scanner_count || 0 }}</strong><small>查看扫描行为</small></button><button class="overview-item" @click="selectType('crawler')"><span>搜索引擎</span><strong>{{ stats.crawler_count || 0 }}</strong><small>查看已识别搜索引擎</small></button></div>
    <!-- Tabs -->
    <div class="tabs">
      <button
        class="tab-btn"
        :class="{ active: activeTab === 'trend' }"
        @click="activeTab = 'trend'"
      >
        趋势与来源
      </button>
      <button
        class="tab-btn"
        :class="{ active: activeTab === 'logs' }"
        @click="activeTab = 'logs'"
      >
        检测日志
      </button>
    </div>

    <!-- Trend Content -->
    <template v-if="activeTab === 'trend'">
      <!-- Charts Row -->
      <div class="charts-row">
        <div class="chart-card">
          <div class="chart-header">
            <h3>爬虫检测趋势</h3>
            <div class="chart-controls">
              <button
                v-for="period in periodOptions"
                :key="period.value"
                class="period-btn"
                :class="{ active: selectedPeriod === period.value }"
                @click="selectedPeriod = period.value; fetchTrend()"
              >
                {{ period.label }}
              </button>
            </div>
          </div>
          <div class="chart-body">
            <div ref="trendChartRef" class="chart-container"></div>
          </div>
        </div>
      </div>

      <!-- Top IPs Table -->
      <div class="table-card">
        <div class="table-header">
          <h3>高频自动化访问来源</h3>
        </div>
        <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>排名</th>
              <th>IP 地址</th>
              <th>机器人</th>
              <th>扫描器</th>
              <th>总计</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(item, idx) in topIPs" :key="idx">
              <td class="cell-rank">{{ idx + 1 }}</td>
              <td class="cell-ip">{{ item.client_ip }}</td>
              <td>{{ item.bot_count || 0 }}</td>
              <td>{{ item.scanner_count || 0 }}</td>
              <td class="cell-total">{{ item.count || 0 }}</td>
            </tr>
            <tr v-if="topIPs.length === 0">
              <td colspan="5" class="empty-cell">
                <div class="empty-state">暂无数据</div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    </template>

    <!-- Logs Table -->
    <div v-show="activeTab === 'logs'" class="table-card">
      <div class="table-header">
        <h3>爬虫检测日志</h3>
        <div class="header-right">
          <span class="result-count">共 {{ total }} 条</span>
        </div>
      </div>
      <nav class="type-filters" aria-label="爬虫类型"><button v-for="item in typeOptions" :key="item.value" :class="{active: filters.type === item.value}" :aria-pressed="filters.type === item.value" @click="selectType(item.value)">{{ item.label }}</button></nav>
      <p class="detection-note">识别类型和置信度是检测结果，是否拦截由全局爬虫策略决定。</p>
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
      <div class="modal-content large" role="dialog" aria-modal="true" aria-label="爬虫检测日志详情" @click.stop>
        <div class="modal-header">
          <h3>爬虫检测日志详情</h3>
          <button class="close-btn" aria-label="关闭详情" @click="showDetail = false">
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
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="showDetail = false">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted, watch } from 'vue'
import * as echarts from 'echarts'
import { useTheme } from '@/stores/theme'
const { theme } = useTheme()
const chartColor = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim()
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'
import type { CrawlerStats, CrawlerTrend, CrawlerLog } from '@/types/api'

const activeTab = ref('logs')
const auth = useAuthStore()
const refreshing = ref(false), errorMessage = ref('')
const typeOptions = [{label:'全部类型',value:''},{label:'自动化爬虫',value:'bot'},{label:'扫描器',value:'scanner'},{label:'搜索引擎',value:'crawler'},{label:'正常用户',value:'human'}]
const selectType = (type: string) => { filters.type = type; currentPage.value = 1; activeTab.value = 'logs'; fetchLogs() }
const refreshAll = async () => { refreshing.value = true; errorMessage.value = ''; try { await Promise.all([fetchStats(),fetchLogs(),fetchTrend(),fetchTopIPs()]) } finally { refreshing.value = false } }
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
    errorMessage.value = '数据加载失败，请重试'; console.error('Failed to fetch crawler logs:', error)
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
    errorMessage.value = '数据加载失败，请重试'; console.error('Failed to fetch log detail:', error)
  }
}

const stats = ref<CrawlerStats>({
  total_requests: 0,
  bot_count: 0,
  scanner_count: 0,
  crawler_count: 0,
  bot_rate: 0,
  scanner_rate: 0
})

const trendData = ref<CrawlerTrend[]>([])
const topIPs = ref<Array<{ client_ip: string; count: number; bot_count: number; scanner_count: number }>>([])
const selectedPeriod = ref(24)
const periodOptions = [
  { label: '24H', value: 24 },
  { label: '7D', value: 168 }
]

const trendChartRef = ref<HTMLElement | null>(null)
let trendChart: echarts.ECharts | null = null

const fetchStats = async () => {
  try {
    stats.value = await api.crawlerStats()
  } catch (error) {
    errorMessage.value = '数据加载失败，请重试'; console.error('Failed to fetch crawler stats:', error)
  }
}

const fetchTrend = async () => {
  try {
    trendData.value = (await api.crawlerTrend({ hours: selectedPeriod.value })) ?? []
    initTrendChart()
  } catch (error) {
    errorMessage.value = '数据加载失败，请重试'; console.error('Failed to fetch trend:', error)
  }
}

const fetchTopIPs = async () => {
  try {
    topIPs.value = (await api.crawlerTopIPs({ limit: 10 })) ?? []
  } catch (error) {
    errorMessage.value = '数据加载失败，请重试'; console.error('Failed to fetch top IPs:', error)
  }
}

const getTypeName = (type: string): string => {
  const typeMap: Record<string, string> = {
    bot: '自动化爬虫',
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

const initTrendChart = () => {
  if (!trendChartRef.value) return
  if (trendChart) trendChart.dispose()

  trendChart = echarts.init(trendChartRef.value)
  const hours = trendData.value.map(item => item.hour)
  const botCount = trendData.value.map(item => item.bot_count)
  const scannerCount = trendData.value.map(item => item.scanner_count)

  const option = {
    backgroundColor: 'transparent',
    grid: { top: 40, right: 20, bottom: 40, left: 50 },
    xAxis: {
      type: 'category',
      data: hours,
      axisLine: { lineStyle: { color: chartColor('--color-border') } },
      axisLabel: { color: chartColor('--color-text-muted'), fontSize: 11, rotate: hours.length > 12 ? 45 : 0 }
    },
    yAxis: {
      type: 'value',
      axisLine: { show: false },
      axisLabel: { color: chartColor('--color-text-muted') },
      splitLine: { lineStyle: { color: chartColor('--color-primary') } }
    },
    tooltip: { trigger: 'axis', backgroundColor: chartColor('--color-primary'), borderColor: chartColor('--color-border'), textStyle: { color: chartColor('--color-foreground') } },
    legend: { data: ['机器人', '扫描器'], top: 10, right: 20, textStyle: { color: chartColor('--color-text-secondary') } },
    series: [
      {
        name: '机器人',
        type: 'bar',
        data: botCount,
        itemStyle: { color: '#EF4444' }
      },
      {
        name: '扫描器',
        type: 'bar',
        data: scannerCount,
        itemStyle: { color: '#F59E0B' }
      }
    ]
  }
  trendChart.setOption(option)
}

const resizeChart = () => trendChart?.resize()
watch(activeTab, (tab) => { if (tab === 'trend') initTrendChart(); else { trendChart?.dispose(); trendChart = null } }, { flush:'post' })
watch(theme, initTrendChart, { flush: 'post' })
onMounted(() => {
  refreshAll()
  window.addEventListener('resize', resizeChart)
})

onUnmounted(() => {
  window.removeEventListener('resize', resizeChart)
  trendChart?.dispose()
})
</script>

<style scoped>
.crawler-page {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  overflow-y: auto;
  height: 100%;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--spacing-md);
}

.stat-card {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
}

.stat-icon {
  width: 44px;
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(59, 130, 246, 0.1);
  color: var(--color-info);
  border-radius: var(--radius-sm);
}

.stat-icon svg { width: 22px; height: 22px; }
.stat-card.danger .stat-icon { background: rgba(239, 68, 68, 0.1); color: var(--color-danger); }
.stat-card.warning .stat-icon { background: rgba(245, 158, 11, 0.1); color: var(--color-warning); }
.stat-card.info .stat-icon { background: rgba(139, 92, 246, 0.1); color: #8B5CF6; }

.stat-value {
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  font-weight: 700;
}

.stat-label {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

.charts-row {
  display: grid;
  grid-template-columns: 1fr;
  gap: var(--spacing-md);
}

.chart-card {
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  overflow: hidden;
}

.chart-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-sm) var(--spacing-md);
  border-bottom: 1px solid var(--color-border);
}

.chart-title { font-size: var(--text-sm); font-weight: 600; }

.chart-controls { display: flex; gap: var(--spacing-xs); }

.period-btn {
  padding: 4px 10px;
  font-size: var(--text-xs);
  color: var(--color-text-secondary);
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.period-btn:hover { border-color: var(--color-accent); color: var(--color-accent); }
.period-btn.active { background: var(--color-accent); border-color: var(--color-accent); color: var(--color-on-primary); }

.chart-body { padding: var(--spacing-sm); }
.chart-container { width: 100%; height: 200px; }

.table-card {
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.table-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-sm) var(--spacing-md);
  border-bottom: 1px solid var(--color-border);
}

.table-header h3 { font-size: var(--text-sm); font-weight: 600; }

.table-wrapper { flex: 1; overflow-x: auto; }

.data-table {
  width: 100%;
  border-collapse: collapse;
}

.data-table th,
.data-table td {
  padding: var(--spacing-xs) var(--spacing-sm);
  text-align: left;
  border-bottom: 1px solid var(--color-border);
  font-size: var(--text-xs);
}

.data-table th {
  background: var(--color-secondary);
  font-weight: 600;
  color: var(--color-text-secondary);
}

.cell-rank {
  width: 40px;
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

.cell-ip {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
}

.cell-total {
  font-family: var(--font-mono);
  font-weight: 600;
  color: var(--color-danger);
}

.empty-cell {
  text-align: center;
  padding: var(--spacing-xl) !important;
}

.empty-state {
  color: var(--color-text-muted);
}

/* Tabs */
.tabs {
  display: flex;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) 0;
}

.tab-btn {
  padding: var(--spacing-xs) var(--spacing-md);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.tab-btn:hover {
  border-color: var(--color-accent);
  color: var(--color-accent);
}

.tab-btn.active {
  background: var(--color-accent);
  border-color: var(--color-accent);
  color: var(--color-on-primary);
}

.action-row {
  display: flex;
  justify-content: center;
  padding: var(--spacing-md);
}

.action-row .btn svg {
  width: 18px;
  height: 18px;
}

/* Table Header */
.table-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-sm) var(--spacing-md);
  border-bottom: 1px solid var(--color-border);
}

.table-header h3 {
  font-size: var(--text-sm);
  font-weight: 600;
}

.header-left {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.header-right {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
}

.select-input {
  width: 100px;
  padding: var(--spacing-xs) var(--spacing-sm);
}

/* Cell Styles */
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
  max-width: 180px;
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
  max-width: 250px;
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
  width: 60px;
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
.page-heading,.heading-actions{display:flex;align-items:center;justify-content:space-between;gap:12px}.page-heading h2{font-size:22px}.page-heading p{color:var(--color-text-muted);font-size:14px;margin-top:8px}.overview-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.overview-item{background:var(--color-primary);border:1px solid var(--color-border);border-radius:8px;padding:20px;text-align:left;color:var(--color-foreground)}button.overview-item:hover{border-color:var(--color-accent)}.overview-item span,.overview-item small{display:block;color:var(--color-text-secondary);font-size:13px}.overview-item strong{display:block;font-size:30px;margin:10px 0;line-height:1.2;font-variant-numeric:tabular-nums}.overview-item.risk strong{color:var(--color-warning)}.type-filters{display:flex;flex-wrap:wrap;gap:8px;padding:16px 20px 0}.type-filters button{padding:8px 14px;border:1px solid var(--color-border);border-radius:6px;color:var(--color-text-secondary)}.type-filters button.active{color:var(--color-accent);border-color:var(--color-accent);background:var(--color-secondary)}.detection-note{padding:12px 20px;font-size:13px;color:var(--color-text-muted)}.result-count{color:var(--color-text-muted);font-size:13px}.error-message{color:var(--color-danger)}.data-table td{vertical-align:middle}.data-table tbody tr:hover{background:var(--color-secondary)}@media(max-width:900px){.overview-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:600px){.page-heading{align-items:flex-start;flex-direction:column}.heading-actions{flex-wrap:wrap}.overview-item{padding:14px}.overview-item strong{font-size:24px}}
</style>
