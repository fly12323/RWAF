<template>
  <div class="overview">
    <div class="overview-heading"><div><h2>安全概览</h2><p>了解站点防护、近期事件和运行状态</p></div><router-link class="btn btn-secondary" to="/monitor">查看运行监控</router-link></div>
    <section class="alert-panel">
      <div class="alert-heading"><h3>待处理事项 <span class="alert-count">{{ alertTotal }}</span></h3><router-link to="/monitor">查看全部告警</router-link></div>
      <p v-if="monitorError" class="overview-error" role="alert">{{ monitorError }}</p>
      <div v-for="alert in openAlerts" :key="alert.id" class="overview-alert"><span class="alert-severity" :class="{ critical: alert.severity === 'critical' }">{{ alert.severity === 'critical' ? '严重' : '警告' }}</span><div class="alert-message"><strong>{{ alert.message }}</strong><small>{{ alert.source === 'weak_password' ? '弱口令检测' : '运行监控' }} · {{ alert.occurrences }} 次 · {{ formatTime(alert.last_seen) }}</small></div><router-link class="btn btn-secondary" :to="alert.source === 'weak_password' ? '/weak-password' : '/monitor'">查看详情</router-link></div>
      <p v-if="!openAlerts.length && !monitorError" class="overview-empty">{{ monitorLoaded ? '暂无待处理告警' : '正在读取告警…' }}</p>
    </section>
    <section v-if="runtime" class="runtime-strip"><div v-for="(status, name) in runtime.dependencies" :key="name"><span>{{ name }}</span><strong :class="status === 'ok' ? 'success' : 'overview-error'">{{ status === 'ok' ? '正常' : status }}</strong></div><div><span>Kafka 消费积压</span><strong>{{ runtime.kafka_lag ?? '未知' }} 条</strong></div><div><span>转发 P99 延迟桶</span><strong>{{ runtime.requests.p99_bucket_ms ?? '—' }} ms</strong></div></section>
    <!-- Stats Cards -->
    <div class="stats-grid">
      <div class="stat-card" v-for="stat in statsData" :key="stat.label">
        <div class="stat-icon" :style="{ color: stat.color }">
          <component :is="stat.icon" />
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ stat.value }}</div>
          <div class="stat-label">{{ stat.label }}</div>
        </div>
        <div class="stat-trend" :class="stat.trend > 0 ? 'up' : 'down'" v-if="stat.trend !== undefined">
          <span>{{ stat.trend > 0 ? '+' : '' }}{{ stat.trend }}%</span>
        </div>
      </div>
    </div>

    <!-- Charts Row -->
    <div class="charts-row">
      <!-- Attack Trend Chart -->
      <div class="chart-card wide">
        <div class="chart-header">
          <h3 class="chart-title">攻击趋势</h3>
          <div class="chart-controls">
            <button
              v-for="period in periodOptions"
              :key="period.value"
              class="period-btn"
              :class="{ active: selectedPeriod === period.value }"
              @click="selectedPeriod = period.value; fetchTrendData()"
            >
              {{ period.label }}
            </button>
          </div>
        </div>
        <div class="chart-body">
          <div ref="trendChartRef" class="chart-container"></div>
        </div>
      </div>

      <!-- Attack Types Pie -->
      <div class="chart-card">
        <div class="chart-header">
          <h3 class="chart-title">攻击类型分布</h3>
        </div>
        <div class="chart-body">
          <div ref="pieChartRef" class="chart-container"></div>
        </div>
      </div>
    </div>

    <!-- Bottom Row -->
    <div class="bottom-row">
      <!-- Top Attack IPs -->
      <div class="list-card">
        <div class="list-header">
          <h3 class="list-title">Top 攻击来源</h3>
          <span class="list-badge live">实时</span>
        </div>
        <div class="list-body">
          <div class="list-item" v-for="(item, idx) in topAttackers" :key="idx">
            <div class="item-rank">{{ idx + 1 }}</div>
            <div class="item-info">
              <span class="item-ip">{{ item.client_ip }}</span>
              <span class="item-location">{{ item.attack_types || '未知' }}</span>
            </div>
            <div class="item-count">
              <span class="count-value">{{ item.attack_count }}</span>
              <span class="count-label">次</span>
            </div>
            <div class="item-bar">
              <div class="bar-fill" :style="{ width: getBarWidth(item.attack_count) + '%' }"></div>
            </div>
          </div>
          <div v-if="topAttackers.length === 0" class="empty-state">
            暂无数据
          </div>
        </div>
      </div>

      <!-- Recent Alerts -->
      <div class="list-card">
        <div class="list-header">
          <h3 class="list-title">最近日志</h3>
          <router-link to="/logs" class="list-link">查看更多</router-link>
        </div>
        <div class="list-body">
          <div class="log-item" v-for="(log, idx) in recentLogs" :key="idx">
            <div class="log-icon" :class="getActionClass(log.action)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path v-if="log.action === 'block'" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path v-else d="M12 8v4m0 4h.01"/>
              </svg>
            </div>
            <div class="log-content">
              <span class="log-type">{{ log.attack_type || '正常请求' }}</span>
              <span class="log-meta">{{ log.client_ip }} - {{ log.method }} {{ log.uri }}</span>
            </div>
            <div class="log-time">{{ formatTime(log.created_at) }}</div>
          </div>
          <div v-if="recentLogs.length === 0" class="empty-state">
            暂无日志
          </div>
        </div>
      </div>

      <!-- WAF Status -->
      <div class="status-card">
        <div class="list-header">
          <h3 class="list-title">防护状态</h3>
        </div>
        <div class="status-body">
          <div class="status-item">
            <span class="status-label">全局执行模式</span>
            <span class="status-value" :class="(wafStatus.protection_mode ? wafStatus.protection_mode === 'block' : wafStatus.waf_mode === 'On') ? 'success' : ''">
              {{ wafStatus.protection_mode ? protectionModeLabel(wafStatus.protection_mode) : wafStatus.waf_mode === 'On' ? '防护中' : wafStatus.waf_mode === 'DetectionOnly' ? '观察模式' : '未防护' }}
            </span>
          </div>
          <div class="status-item">
            <span class="status-label">站点数</span>
            <span class="status-value">{{ wafStatus.site_count }} 个</span>
          </div>
          <div class="status-item">
            <span class="status-label">在线用户</span>
            <span class="status-value">{{ wafStatus.online_users }} 人</span>
          </div>
          <div class="status-item">
            <span class="status-label">总请求</span>
            <span class="status-value">{{ formatNumber(totalStats.total) }}</span>
          </div>
          <div class="status-item">
            <span class="status-label">被拦截</span>
            <span class="status-value danger">{{ formatNumber(totalStats.blocked) }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, h, watch } from 'vue'
import * as echarts from 'echarts'
import { api } from '@/api'
import { protectionModeLabel } from '@/utils/request'
import { useTheme } from '@/stores/theme'
import type { LogTrend, AttackType, AttackIP, RequestLog, WAFStatus, RuntimeSnapshot, SecurityAlert } from '@/types/api'

const { theme } = useTheme()
const runtime = ref<RuntimeSnapshot | null>(null)
const openAlerts = ref<SecurityAlert[]>([])
const alertTotal = ref(0), monitorError = ref(''), monitorLoaded = ref(false)
const fetchMonitor = async () => {
  const results = await Promise.allSettled([api.monitorStatus(), api.alerts(1, 'open')])
  const errors: string[] = []
  if (results[0].status === 'fulfilled') runtime.value = results[0].value
  else errors.push('运行状态读取失败')
  if (results[1].status === 'fulfilled') { openAlerts.value = (results[1].value.list ?? []).slice(0, 3); alertTotal.value = results[1].value.total; monitorLoaded.value = true }
  else errors.push('告警读取失败')
  monitorError.value = errors.length ? errors.join('，') + '，请刷新或进入运行监控查看。' : ''
}
const chartColor = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim()

// Icon Components
const IconShield = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' })
])

const IconBlock = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('circle', { cx: '12', cy: '12', r: '10' }),
  h('line', { x1: '4.93', y1: '4.93', x2: '19.07', y2: '19.07' })
])

const IconAlert = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('path', { d: 'M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z' }),
  h('line', { x1: '12', y1: '9', x2: '12', y2: '13' }),
  h('line', { x1: '12', y1: '17', x2: '12.01', y2: '17' })
])

const IconTrend = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('polyline', { points: '23,6 13.5,15.5 8.5,10.5 1,18' }),
  h('polyline', { points: '17,6 23,6 23,12' })
])

interface StatData {
  label: string
  value: string
  icon: () => ReturnType<typeof h>
  color: string
  trend?: number
}

const statsData = ref<StatData[]>([
  { label: '今日请求', value: '-', icon: IconShield, color: '#22C55E' },
  { label: '被拦截', value: '-', icon: IconBlock, color: '#EF4444' },
  { label: '放行请求', value: '-', icon: IconAlert, color: '#F59E0B' },
  { label: '在线站点', value: '-', icon: IconTrend, color: '#3B82F6' }
])

const wafStatus = reactive<WAFStatus>({
  status: 'running',
  site_count: 0,
  waf_mode: 'On',
  online_users: 0
})

const totalStats = reactive({
  total: 0,
  blocked: 0
})

const periodOptions = [
  { label: '24H', value: 24 },
  { label: '7D', value: 168 },
  { label: '30D', value: 720 }
]
const selectedPeriod = ref(24)

const trendData = ref<LogTrend[]>([])
const attackTypesData = ref<AttackType[]>([])
const topAttackers = ref<AttackIP[]>([])
const recentLogs = ref<RequestLog[]>([])

const trendChartRef = ref<HTMLElement | null>(null)
const pieChartRef = ref<HTMLElement | null>(null)

let trendChart: echarts.ECharts | null = null
let pieChart: echarts.ECharts | null = null

const getTodayStart = (): string => {
  const now = new Date()
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`
}

const fetchStats = async () => {
  try {
    const todayStr = getTodayStart()

    // Today's stats for the stat cards
    const todayStats = await api.stats({ start_time: todayStr })
    const todayTotal = todayStats.total || 0
    const todayBlocked = todayStats.by_action?.find((a: { action: string; count: number }) => a.action === 'block')?.count || 0

    statsData.value[0].value = formatNumber(todayTotal)
    statsData.value[1].value = formatNumber(todayBlocked)
    statsData.value[2].value = formatNumber(todayStats.by_action?.find((a: { action: string; count: number }) => a.action === 'pass')?.count || 0)

    // Total stats for the status panel
    const allStats = await api.stats()
    totalStats.total = allStats.total || 0
    totalStats.blocked = allStats.by_action?.find((a: { action: string; count: number }) => a.action === 'block')?.count || 0
  } catch (error) {
    console.error('Failed to fetch stats:', error)
  }
}

const fetchWafStatus = async () => {
  try {
    const status = await api.wafStatus()
    Object.assign(wafStatus, status)
    statsData.value[3].value = String(status.site_count)
  } catch (error) {
    console.error('Failed to fetch WAF status:', error)
  }
}

const fetchTrendData = async () => {
  try {
    trendData.value = (await api.logsTrend({ hours: selectedPeriod.value })) ?? []
    initTrendChart()
  } catch (error) {
    console.error('Failed to fetch trend data:', error)
  }
}

const fetchAttackTypes = async () => {
  try {
    attackTypesData.value = (await api.attackTypes()) ?? []
    initPieChart()
  } catch (error) {
    console.error('Failed to fetch attack types:', error)
  }
}

const fetchTopAttackers = async () => {
  try {
    topAttackers.value = (await api.attackIps({})) ?? []
    topAttackers.value = topAttackers.value.slice(0, 5)
  } catch (error) {
    console.error('Failed to fetch top attackers:', error)
  }
}

const fetchRecentLogs = async () => {
  try {
    const result = await api.logs({ page: 1, page_size: 10 })
    recentLogs.value = result.list ?? []
  } catch (error) {
    console.error('Failed to fetch recent logs:', error)
  }
}

const formatNumber = (num: number): string => {
  if (num >= 10000) {
    return (num / 10000).toFixed(1) + 'w'
  }
  return String(num)
}

const formatTime = (time: string): string => {
  if (!time) return ''
  const date = new Date(time)
  const now = new Date()
  const diff = now.getTime() - date.getTime()

  if (diff < 60000) return '刚刚'
  if (diff < 3600000) return Math.floor(diff / 60000) + '分钟前'
  if (diff < 86400000) return Math.floor(diff / 3600000) + '小时前'
  return date.toLocaleDateString('zh-CN')
}

const getBarWidth = (count: number): number => {
  if (!topAttackers.value.length) return 0
  const max = topAttackers.value[0]?.attack_count || 1
  return (count / max) * 100
}

const getActionClass = (action: string): string => {
  switch (action) {
    case 'block': return 'danger'
    case 'allow': return 'success'
    default: return 'warning'
  }
}

const initTrendChart = () => {
  if (!trendChartRef.value) return

  if (trendChart) {
    trendChart.dispose()
  }

  trendChart = echarts.init(trendChartRef.value)

  const hours = trendData.value.map(item => item.hour)
  const total = trendData.value.map(item => item.total)
  const blocked = trendData.value.map(item => item.block_count)

  const option = {
    backgroundColor: 'transparent',
    grid: {
      top: 40,
      right: 20,
      bottom: 40,
      left: 50
    },
    xAxis: {
      type: 'category',
      data: hours,
      axisLine: { lineStyle: { color: chartColor('--color-border') } },
      axisLabel: {
        color: chartColor('--color-text-muted'),
        fontSize: 11,
        rotate: hours.length > 12 ? 45 : 0
      },
      splitLine: { show: false }
    },
    yAxis: {
      type: 'value',
      axisLine: { show: false },
      axisLabel: { color: chartColor('--color-text-muted'), fontSize: 11 },
      splitLine: { lineStyle: { color: chartColor('--color-primary') } }
    },
    tooltip: {
      trigger: 'axis',
      backgroundColor: chartColor('--color-primary'),
      borderColor: chartColor('--color-border'),
      textStyle: { color: chartColor('--color-foreground') }
    },
    legend: {
      data: ['总请求', '拦截'],
      top: 10,
      right: 20,
      textStyle: { color: chartColor('--color-text-secondary') }
    },
    series: [
      {
        name: '总请求',
        type: 'line',
        data: total,
        smooth: true,
        lineStyle: { color: '#3B82F6', width: 2 },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(59, 130, 246, 0.3)' },
            { offset: 1, color: 'rgba(59, 130, 246, 0)' }
          ])
        },
        itemStyle: { color: '#3B82F6' }
      },
      {
        name: '拦截',
        type: 'line',
        data: blocked,
        smooth: true,
        lineStyle: { color: '#22C55E', width: 2 },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(34, 197, 94, 0.3)' },
            { offset: 1, color: 'rgba(34, 197, 94, 0)' }
          ])
        },
        itemStyle: { color: '#22C55E' }
      }
    ]
  }

  trendChart.setOption(option)
}

const initPieChart = () => {
  if (!pieChartRef.value) return

  if (pieChart) {
    pieChart.dispose()
  }

  pieChart = echarts.init(pieChartRef.value)

  const pieData = attackTypesData.value.map((item, idx) => ({
    name: item.attack_type || '其他',
    value: item.count,
    itemStyle: {
      color: ['#EF4444', '#F59E0B', '#8B5CF6', '#3B82F6', chartColor('--color-text-muted')][idx % 5]
    }
  }))

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: chartColor('--color-primary'),
      borderColor: chartColor('--color-border'),
      textStyle: { color: chartColor('--color-foreground') }
    },
    legend: {
      orient: 'vertical',
      right: 10,
      top: 'center',
      textStyle: { color: chartColor('--color-text-secondary') }
    },
    series: [
      {
        type: 'pie',
        radius: ['50%', '70%'],
        center: ['35%', '50%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 4,
          borderColor: chartColor('--color-primary'),
          borderWidth: 2
        },
        label: { show: false },
        emphasis: {
          label: { show: true, fontSize: 14, fontWeight: 'bold', color: chartColor('--color-foreground') }
        },
        labelLine: { show: false },
        data: pieData.length > 0 ? pieData : [{ name: '暂无数据', value: 1, itemStyle: { color: chartColor('--color-border') } }]
      }
    ]
  }

  pieChart.setOption(option)
}

let refreshInterval: number

const fetchAllData = async () => {
  await Promise.all([
    fetchMonitor(),
    fetchStats(),
    fetchWafStatus(),
    fetchTrendData(),
    fetchAttackTypes(),
    fetchTopAttackers(),
    fetchRecentLogs()
  ])
}

const resizeCharts = () => { trendChart?.resize(); pieChart?.resize() }
watch(theme, () => { initTrendChart(); initPieChart() }, { flush: 'post' })

onMounted(() => {
  fetchAllData()

  refreshInterval = window.setInterval(() => {
    fetchMonitor()
    fetchStats()
    fetchTopAttackers()
    fetchRecentLogs()
  }, 30000)

  window.addEventListener('resize', resizeCharts)
})

onUnmounted(() => {
  window.removeEventListener('resize', resizeCharts)
  clearInterval(refreshInterval)
  trendChart?.dispose()
  pieChart?.dispose()
})
</script>

<style scoped>
.overview {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
  min-height: 100%;
}

/* Stats Grid */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
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
  transition: all var(--transition-normal);
}

.stat-card:hover {
  border-color: var(--color-accent);
  box-shadow: none;
}

.stat-icon {
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--color-active-bg);
  border-radius: var(--radius-md);
}

.stat-icon svg {
  width: 24px;
  height: 24px;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-family: var(--font-mono);
  font-size: var(--text-2xl);
  font-weight: 700;
  color: var(--color-foreground);
}

.stat-label {
  font-size: var(--text-sm);
  color: var(--color-text-muted);
}

.stat-trend {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  font-weight: 500;
  padding: 4px 8px;
  border-radius: var(--radius-sm);
}

.stat-trend.up {
  background: var(--color-active-bg);
  color: var(--color-success);
}

.stat-trend.down {
  background: rgba(239, 68, 68, 0.1);
  color: var(--color-danger);
}

/* Charts Row */
.charts-row {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: var(--spacing-md);
}

.chart-card {
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

.chart-card.wide {
  min-height: 320px;
}

.chart-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md) var(--spacing-lg);
  border-bottom: 1px solid var(--color-border);
}

.chart-title {
  font-size: var(--text-base);
  font-weight: 600;
  color: var(--color-foreground);
}

.chart-controls {
  display: flex;
  gap: var(--spacing-xs);
}

.period-btn {
  padding: 4px 12px;
  font-size: var(--text-xs);
  color: var(--color-text-secondary);
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.period-btn:hover {
  border-color: var(--color-accent);
  color: var(--color-accent);
}

.period-btn.active {
  background: var(--color-accent);
  border-color: var(--color-accent);
  color: var(--color-on-primary);
}

.chart-body {
  padding: var(--spacing-md);
}

.chart-container {
  width: 100%;
  height: 250px;
}

/* Bottom Row */
.bottom-row {
  display: grid;
  grid-template-columns: 1fr 1fr 300px;
  gap: var(--spacing-md);
  flex: 1;
  min-height: 0;
}

.list-card,
.status-card {
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.list-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md) var(--spacing-lg);
  border-bottom: 1px solid var(--color-border);
}

.list-title {
  font-size: var(--text-base);
  font-weight: 600;
  color: var(--color-foreground);
}

.list-badge {
  font-size: var(--text-xs);
  padding: 2px 8px;
  border-radius: 9999px;
  background: var(--color-active-bg);
  color: var(--color-success);
}

.list-badge.live {
  animation: pulse-glow 2s ease-in-out infinite;
}

.list-link {
  font-size: var(--text-xs);
  color: var(--color-accent);
}

.list-body {
  flex: 1;
  padding: var(--spacing-sm);
  overflow-y: auto;
}

.empty-state {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100px;
  color: var(--color-text-muted);
  font-size: var(--text-sm);
}

/* List Items */
.list-item {
  display: grid;
  grid-template-columns: 28px 1fr auto;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--radius-md);
  transition: background var(--transition-fast);
  position: relative;
}

.list-item:hover {
  background: var(--color-secondary);
}

.item-rank {
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: 600;
  background: var(--color-secondary);
  border-radius: var(--radius-sm);
  color: var(--color-text-muted);
}

.list-item:first-child .item-rank {
  background: var(--color-accent);
  color: var(--color-on-primary);
}

.item-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.item-ip {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  color: var(--color-foreground);
}

.item-location {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

.item-count {
  text-align: right;
}

.count-value {
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  font-weight: 600;
  color: var(--color-danger);
}

.count-label {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
  margin-left: 2px;
}

.item-bar {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: var(--color-secondary);
}

.bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--color-danger), transparent);
  transition: width var(--transition-normal);
}

/* Log Items */
.log-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--radius-md);
  transition: background var(--transition-fast);
}

.log-item:hover {
  background: var(--color-secondary);
}

.log-icon {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-md);
}

.log-icon svg {
  width: 16px;
  height: 16px;
}

.log-icon.danger {
  background: rgba(239, 68, 68, 0.1);
  color: var(--color-danger);
}

.log-icon.success {
  background: var(--color-active-bg);
  color: var(--color-success);
}

.log-icon.warning {
  background: rgba(245, 158, 11, 0.1);
  color: var(--color-warning);
}

.log-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.log-type {
  font-size: var(--text-sm);
  color: var(--color-foreground);
}

.log-meta {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.log-time {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
  white-space: nowrap;
}

/* Status Card */
.status-body {
  padding: var(--spacing-md);
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.status-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--spacing-md);
}

.status-label {
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
}

.status-value {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  color: var(--color-foreground);
}

.status-value.success {
  color: var(--color-success);
}

.status-value.danger {
  color: var(--color-danger);
}
.overview-heading{display:flex;justify-content:space-between;align-items:center;gap:16px}.overview-heading h2{font-size:24px}.overview-heading p{margin-top:6px;color:var(--color-text-secondary)}
.alert-panel{border:1px solid var(--color-border);border-radius:8px;background:var(--color-primary)}.alert-heading{padding:18px 22px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--color-border)}.alert-heading h3{font-size:16px}.alert-count{margin-left:8px;font-size:12px;color:var(--color-warning)}.overview-alert{padding:16px 22px;display:flex;align-items:center;gap:16px;border-bottom:1px solid var(--color-border)}.overview-alert:last-child{border-bottom:0}.alert-message{flex:1;min-width:0}.alert-message strong{font-weight:500;display:block;overflow-wrap:anywhere}.alert-message small{display:block;color:var(--color-text-muted);margin-top:6px}.alert-severity{color:var(--color-warning);white-space:nowrap}.alert-severity.critical,.overview-error{color:var(--color-danger)}.overview-error,.overview-empty{padding:18px 22px}.overview-empty{color:var(--color-text-muted)}.runtime-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));background:var(--color-primary);border:1px solid var(--color-border);border-radius:8px}.runtime-strip>div{padding:16px 20px}.runtime-strip span{display:block;color:var(--color-text-muted);font-size:12px}.runtime-strip strong{display:block;font-size:14px;margin-top:8px;font-weight:500}.success{color:var(--color-success)}
.stat-icon{width:36px;height:36px;background:var(--color-secondary)}.stat-icon svg{width:20px;height:20px}.stat-card{padding:20px}.stat-value{font-family:var(--font-sans);font-size:28px}.stat-card:hover{border-color:var(--color-border)}
@media(max-width:600px){.overview-heading{align-items:flex-start;flex-direction:column}.overview-alert{align-items:flex-start;flex-wrap:wrap}.stats-grid{grid-template-columns:1fr 1fr}.stat-card{padding:14px;gap:8px}.stat-icon{display:none}.stat-value{font-size:24px}.alert-heading{gap:12px;font-size:12px}}
</style>
