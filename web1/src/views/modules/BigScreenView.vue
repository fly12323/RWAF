<template>
  <div class="big-screen" :class="{ fullscreen: isFullscreen }">
    <div class="big-screen-header">
      <h1>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        WAF 安全态势感知
      </h1>
      <div class="header-right">
        <div class="time">{{ currentTime }}</div>
        <button class="refresh-btn" @click="refresh" title="刷新地图">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M23 4v6h-6M1 20v-6h6"/>
            <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
          </svg>
        </button>
        <button class="fullscreen-btn" @click="toggleFullscreen" :title="isFullscreen ? '退出全屏' : '全屏'">
          <svg v-if="!isFullscreen" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M8 3H5a2 2 0 00-2 2v3m18 0V5a2 2 0 00-2-2h-3m0 18h3a2 2 0 002-2v-3M3 16v3a2 2 0 002 2h3"/>
          </svg>
          <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M8 3v3a2 2 0 01-2 2H3m18 0h-3a2 2 0 01-2-2V3m0 18v-3a2 2 0 012-2h3M3 16h3a2 2 0 012 2v3"/>
          </svg>
        </button>
      </div>
    </div>

    <div class="big-screen-content">
      <!-- Left Column -->
      <div class="column left">
        <div class="panel">
          <h3>实时防护状态</h3>
          <div class="status-grid">
            <div class="status-item">
              <span class="label">防护站点</span>
              <span class="value">{{ wafStatus.site_count || 0 }}</span>
            </div>
            <div class="status-item">
              <span class="label">WAF模式</span>
              <span class="value" :class="wafStatus.waf_mode === 'On' ? 'success' : ''">
                {{ wafStatus.waf_mode === 'On' ? '防护中' : wafStatus.waf_mode === 'DetectionOnly' ? '监控模式' : '关闭' }}
              </span>
            </div>
            <div class="status-item highlight">
              <span class="label">今日请求</span>
              <span class="value accent">{{ formatNumber(todayStats.total) }}</span>
            </div>
            <div class="status-item highlight">
              <span class="label">攻击拦截</span>
              <span class="value danger">{{ formatNumber(todayStats.blocked) }}</span>
            </div>
          </div>
        </div>

        <div class="panel chart-panel">
          <h3>攻击趋势</h3>
          <div ref="trendChartRef" class="chart"></div>
        </div>

        <div class="panel">
          <h3>防护模式</h3>
          <div class="defense-status">
            <div class="defense-item" :class="{ active: securityConfig.rule_engine_enabled }">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>规则引擎</span>
            </div>
            <div class="defense-item" :class="{ active: securityConfig.crawler_detection_enabled }">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="11" width="18" height="10" rx="2"/>
                <circle cx="12" cy="5" r="2"/>
              </svg>
              <span>爬虫防护</span>
            </div>
            <div class="defense-item" :class="{ active: securityConfig.cc_protection_enabled }">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
              </svg>
              <span>CC防护</span>
            </div>
          </div>
        </div>

        <div class="panel">
          <h3>Top 攻击来源</h3>
          <div class="attacker-list">
            <div class="attacker-item" v-for="(item, i) in topAttackers" :key="i">
              <span class="rank">{{ i + 1 }}</span>
              <div class="attacker-info">
                <span class="ip">{{ item.client_ip }}</span>
                <span class="types">{{ item.attack_types || '未知' }}</span>
              </div>
              <span class="count">{{ formatNumber(item.attack_count) }}</span>
            </div>
            <div v-if="topAttackers.length === 0" class="empty-list">
              暂无数据
            </div>
          </div>
        </div>
      </div>

      <!-- Center Column -->
      <div class="column center">
        <div class="panel hero">
          <div class="hero-bg">
            <div class="glow-orb orb-1"></div>
            <div class="glow-orb orb-2"></div>
            <div class="scan-line"></div>
          </div>
          <div class="hero-content">
            <div class="hero-stat">
              <span class="hero-value text-glow">{{ formatNumber(stats.total) }}</span>
              <span class="hero-label">总请求数</span>
            </div>
            <div class="hero-divider"></div>
            <div class="hero-stat">
              <span class="hero-value text-glow danger">{{ formatNumber(stats.blocked) }}</span>
              <span class="hero-label">攻击拦截</span>
            </div>
          </div>
          <div class="shield-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
          </div>
        </div>

        <div class="panel map-panel">
          <h3>全球攻击来源</h3>
          <div ref="mapChartRef" class="chart map-chart"></div>
        </div>
      </div>

      <!-- Right Column -->
      <div class="column right">
        <div class="panel">
          <h3>实时攻击流</h3>
          <div ref="streamRef" class="stream-list">
            <div v-for="l in streamLogs" :key="l.id" class="stream-line">
              <span class="t">{{ formatTime(l.created_at) }}</span>
              <span class="ip" :class="{ hot: l.risk_score >= 10 || l.action === 'block' }">{{ l.client_ip }}</span>
              <span class="m">{{ l.method }}</span>
              <span class="a" v-if="l.attack_type">{{ l.attack_type }}</span>
              <span class="b" v-if="l.action === 'block'">BLOCK</span>
            </div>
            <div v-if="streamLogs.length === 0" class="empty-list">
              等待日志输入...
            </div>
          </div>
        </div>

        <div class="panel">
          <h3>最近攻击</h3>
          <div class="alert-list">
            <div class="alert-item" v-for="(log, i) in recentLogs" :key="i">
              <div class="alert-icon" :class="getLogClass(log.attack_type)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                </svg>
              </div>
              <div class="alert-content">
                <span class="type">{{ log.attack_type || '正常' }}</span>
                <span class="ip">{{ log.client_ip }}</span>
              </div>
              <span class="action" :class="log.action">{{ getActionText(log.action) }}</span>
            </div>
            <div v-if="recentLogs.length === 0" class="empty-list">
              暂无数据
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, nextTick, watch } from 'vue'
import * as echarts from 'echarts'
import { useTheme } from '@/stores/theme'
const { theme } = useTheme()
const chartColor = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim()
import { api } from '@/api'
import type { WAFStatus, LogTrend, AttackIP, RequestLog, AttackGeo } from '@/types/api'

const currentTime = ref('')
const isFullscreen = ref(false)
const trendChartRef = ref<HTMLElement | null>(null)
const mapChartRef = ref<HTMLElement | null>(null)
const streamRef = ref<HTMLElement | null>(null)

let trendChart: echarts.ECharts | null = null
let mapChart: echarts.ECharts | null = null
let timer: number
let streamTimer: number | null = null

const wafStatus = reactive<WAFStatus>({
  status: 'running',
  site_count: 0,
  waf_mode: 'On',
  online_users: 0
})

const stats = reactive({
  total: 0,
  blocked: 0
})

const todayStats = reactive({
  total: 0,
  blocked: 0
})

const trendData = ref<LogTrend[]>([])
const topAttackers = ref<AttackIP[]>([])
const recentLogs = ref<RequestLog[]>([])
const streamLogs = ref<RequestLog[]>([])
const seenStreamIds = new Set<number>()

const securityConfig = reactive({
  rule_engine_enabled: true,
  anomaly_detection_enabled: false,
  crawler_detection_enabled: true,
  cc_protection_enabled: true
})

// World map loading
const ensureWorldMap = async () => {
  const exists = (echarts as any).getMap?.('world')
  if (exists?.geoJson) return
  const urls = [
    "https://cdn.jsdelivr.net/npm/echarts@5.6.0/map/json/world.json",
    "https://fastly.jsdelivr.net/npm/echarts@5.6.0/map/json/world.json",
    "https://unpkg.com/echarts@5.6.0/map/json/world.json",
    "https://cdn.jsdelivr.net/npm/echarts@3.7.1/map/json/world.json",
    "https://unpkg.com/echarts@3.7.1/map/json/world.json",
  ]
  let lastStatus = ""
  for (const url of urls) {
    try {
      const res = await fetch(url, { cache: "force-cache" })
      if (!res.ok) {
        lastStatus = `${res.status}`
        continue
      }
      const geoJson = await res.json()
      ;(echarts as any).registerMap?.("world", geoJson)
      return
    } catch (e) {
      lastStatus = String(e)
    }
  }
  throw new Error(`load world map failed: ${lastStatus || "unknown"}`)
}

const buildMapPoints = (ips: AttackGeo[]) => {
  const m = new Map<string, { name: string; coord: [number, number]; count: number; examples: string[] }>()
  ips.forEach((row) => {
    const ip = String(row.client_ip || '')
    const cnt = Number(row.attack_count || 0)
    const lat = Number(row.lat || 0)
    const lon = Number(row.lon || 0)
    if (!ip || !cnt || lat === 0 || lon === 0) return
    const name = row.city || row.country || ip
    const key = `${lat},${lon}`
    const prev = m.get(key)
    if (!prev) m.set(key, { name, coord: [lon, lat], count: cnt, examples: [ip] })
    else {
      prev.count += cnt
      if (prev.examples.length < 3) prev.examples.push(ip)
    }
  })
  return Array.from(m.values()).map((x) => ({
    name: x.name,
    value: [x.coord[0], x.coord[1], x.count] as [number, number, number],
    count: x.count,
    examples: x.examples
  }))
}

// 攻击目标点（中国作为中心目标）
const targetCity = { name: '攻击目标', coord: [105, 35] as [number, number] }

const initMapChart = async () => {
  if (!mapChartRef.value) return
  try {
    await ensureWorldMap()
    if (mapChart) mapChart.dispose()
    mapChart = echarts.init(mapChartRef.value)

    const ips = await api.attackGeo({ limit: 100 })
    const points = buildMapPoints(ips || [])

    // 生成飞线数据：从攻击源到目标（只显示前10个）
    const topPoints = points.slice(0, 10)
    const flyLines = topPoints.map(p => ({
      fromName: p.name,
      toName: targetCity.name,
      coords: [p.value.slice(0, 2) as [number, number], targetCity.coord]
    }))

    mapChart.setOption({
      tooltip: {
        trigger: 'item',
        backgroundColor: 'rgba(0, 8, 20, 0.9)',
        borderColor: chartColor('--color-accent'),
        textStyle: { color: chartColor('--color-accent') },
        formatter: (p: any) => {
          if (!p?.data) return String(p?.name || '')
          const d = p.data
          if (d.type === 'line') {
            return `${d.fromName} → ${d.toName}`
          }
          const ex = Array.isArray(d.examples) ? d.examples.join(', ') : ''
          return `<b>${d.name}</b><br/>攻击次数: ${d.count}${ex ? `<br/>示例IP: ${ex}` : ''}`
        }
      },
      geo: {
        map: 'world',
        roam: true,
        zoom: 1.2,
        center: [10, 20],
        itemStyle: {
          areaColor: chartColor('--color-secondary'),
          borderColor: chartColor('--color-border'),
          borderWidth: 1
        },
        emphasis: {
          itemStyle: { areaColor: chartColor('--color-active-bg') },
          label: { show: false }
        },
        label: { show: false },
        silent: false
      },
      series: [
        // 攻击飞线（更细虚线 + 飞动光点）
        {
          name: '攻击路径',
          type: 'lines',
          coordinateSystem: 'geo',
          zlevel: 2,
          symbol: 'none',
          effect: {
            show: true,
            period: 2.5,
            trailLength: 0.5,
            color: chartColor('--color-accent'),
            symbol: 'arrow',
            symbolSize: 4
          },
          lineStyle: {
            color: chartColor('--color-accent'),
            width: 0.5,
            opacity: 0.15,
            curveness: 0.2,
            type: 'dashed'
          },
          data: flyLines
        },
        // 攻击源点
        {
          name: '攻击来源',
          type: 'effectScatter',
          coordinateSystem: 'geo',
          zlevel: 3,
          showEffectOn: 'render',
          rippleEffect: {
            brushType: 'stroke',
            scale: 3,
            period: 3
          },
          symbolSize: (val: any) => Math.max(5, Math.min(18, Math.sqrt(Number(val?.[2] || 0)) * 1.8)),
          itemStyle: {
            color: '#ff4d5b',
            shadowBlur: 20,
            shadowColor: '#ff4d5b'
          },
          data: points,
        },
        // 目标点
        {
          name: '攻击目标',
          type: 'effectScatter',
          coordinateSystem: 'geo',
          zlevel: 3,
          showEffectOn: 'render',
          rippleEffect: { brushType: 'stroke', scale: 6 },
          symbolSize: 20,
          symbol: 'circle',
          itemStyle: {
            color: chartColor('--color-accent'),
            shadowBlur: 30,
            shadowColor: chartColor('--color-accent')
          },
          data: [{ ...targetCity, value: [targetCity.coord[0], targetCity.coord[1], 9999] }]
        },
      ],
    })
  } catch (e) {
    console.error('Map init error:', e)
  }
}

const loadStream = async () => {
  try {
    const data = await api.logs({ page: 1, page_size: 80 })
    const list = (data?.list || []) as RequestLog[]
    const ordered = list.slice().sort((a, b) => Number(a.id || 0) - Number(b.id || 0))
    const added: RequestLog[] = []
    ordered.forEach((l) => {
      const id = Number(l.id || 0)
      if (!id || seenStreamIds.has(id)) return
      seenStreamIds.add(id)
      added.push(l)
    })
    if (added.length) {
      streamLogs.value = [...streamLogs.value, ...added].slice(-120)
      await nextTick()
      if (streamRef.value) streamRef.value.scrollTop = streamRef.value.scrollHeight
    }
  } catch {
    return
  }
}

const startStream = () => {
  if (streamTimer) window.clearInterval(streamTimer)
  loadStream()
  streamTimer = window.setInterval(loadStream, 1800)
}

const stopStream = () => {
  if (!streamTimer) return
  window.clearInterval(streamTimer)
  streamTimer = null
}

const refresh = async () => {
  await initMapChart()
}

// Fullscreen toggle
const toggleFullscreen = async () => {
  try {
    if (!isFullscreen.value) {
      await document.documentElement.requestFullscreen()
      isFullscreen.value = true
    } else {
      await document.exitFullscreen()
      isFullscreen.value = false
    }
  } catch (error) {
    console.error('Fullscreen error:', error)
  }
}

const updateTime = () => {
  currentTime.value = new Date().toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  })
}

const formatNumber = (num: number): string => {
  if (!num) return '0'
  if (num >= 10000) return (num / 10000).toFixed(1) + 'w'
  return num.toLocaleString()
}

const formatTime = (time?: string): string => {
  if (!time) return ''
  const d = new Date(time)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

const getLogClass = (type?: string): string => {
  if (!type) return ''
  if (type.includes('SQL')) return 'danger'
  if (type.includes('XSS')) return 'warning'
  if (type.includes('CC')) return 'purple'
  return 'info'
}

const getActionText = (action: string): string => {
  switch (action) {
    case 'block': return '拦截'
    case 'allow': return '放行'
    default: return action
  }
}

const getTodayStart = (): string => {
  const now = new Date()
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`
}

const fetchData = async () => {
  try {
    // WAF Status
    try {
      const status = await api.wafStatus()
      Object.assign(wafStatus, status)
      const policy = await api.protectionConfig()
      securityConfig.rule_engine_enabled = policy.enabled && policy.rule_engine_enabled
      securityConfig.crawler_detection_enabled = policy.enabled && policy.crawler_detection_enabled
      securityConfig.cc_protection_enabled = policy.enabled && policy.cc_protection_enabled
    } catch {}

    // Stats - today (left panel)
    try {
      const todayStr = getTodayStart()
      const todayData = await api.stats({ start_time: todayStr })
      todayStats.total = todayData.total || 0
      todayStats.blocked = todayData.by_action?.find((a: { action: string }) => a.action === 'block')?.count || 0
    } catch {}

    // Stats - total (center panel)
    try {
      const totalData = await api.stats()
      stats.total = totalData.total || 0
      stats.blocked = totalData.by_action?.find((a: { action: string }) => a.action === 'block')?.count || 0
    } catch {}

    // Trend
    try {
      trendData.value = await api.logsTrend({ hours: 24 })
      initTrendChart()
    } catch {}

    // Top Attackers
    try {
      topAttackers.value = (await api.attackIps({})).slice(0, 5)
    } catch {}

    // Recent Logs
    try {
      const result = await api.logs({ page: 1, page_size: 10 })
      recentLogs.value = result.list || []
    } catch {}
  } catch (error) {
    console.error('Failed to fetch data:', error)
  }
}

const initTrendChart = () => {
  if (!trendChartRef.value || !trendData.value.length) return
  if (trendChart) trendChart.dispose()

  trendChart = echarts.init(trendChartRef.value)
  const option = {
    backgroundColor: 'transparent',
    grid: { top: 20, right: 20, bottom: 30, left: 50 },
    xAxis: {
      type: 'category',
      data: trendData.value.map(item => item.hour),
      axisLine: { lineStyle: { color: chartColor('--color-border') } },
      axisLabel: { color: chartColor('--color-text-muted'), fontSize: 10 }
    },
    yAxis: {
      type: 'value',
      axisLine: { show: false },
      axisLabel: { color: chartColor('--color-text-muted'), fontSize: 10 },
      splitLine: { lineStyle: { color: chartColor('--color-primary') } }
    },
    tooltip: { trigger: 'axis', backgroundColor: chartColor('--color-primary'), borderColor: chartColor('--color-border'), textStyle: { color: chartColor('--color-foreground') } },
    series: [
      {
        type: 'line',
        data: trendData.value.map(item => item.total),
        smooth: true,
        lineStyle: { color: '#3B82F6', width: 2 },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(59, 130, 246, 0.3)' },
            { offset: 1, color: 'rgba(59, 130, 246, 0)' }
          ])
        },
        itemStyle: { color: '#3B82F6' }
      }
    ]
  }
  trendChart.setOption(option)
}

watch(theme, () => { initTrendChart(); initMapChart() }, { flush: 'post' })
onMounted(() => {
  updateTime()
  timer = window.setInterval(() => {
    updateTime()
    fetchData()
  }, 5000)

  fetchData()
  initMapChart()
  startStream()

  // Listen for fullscreen change
  document.addEventListener('fullscreenchange', () => {
    isFullscreen.value = !!document.fullscreenElement
  })

  window.addEventListener('resize', () => {
    trendChart?.resize()
    mapChart?.resize()
  })
})

onUnmounted(() => {
  clearInterval(timer)
  stopStream()
  trendChart?.dispose()
  mapChart?.dispose()
})
</script>

<style scoped>
.big-screen {
  width: 100%;
  height: 100%;
  background: var(--color-background);
  display: flex;
  flex-direction: column;
}

.big-screen-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-md) var(--spacing-xl);
  border-bottom: 1px solid var(--color-border);
  background: var(--color-primary);
}

.big-screen-header h1 {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-family: var(--font-mono);
  font-size: var(--text-xl);
  color: var(--color-accent);
}

.big-screen-header h1 svg {
  width: 28px;
  height: 28px;
}

.header-right {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.big-screen-header .time {
  font-family: var(--font-mono);
  color: var(--color-text-secondary);
}

.fullscreen-btn {
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--color-secondary);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  color: var(--color-text-secondary);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.fullscreen-btn:hover,
.refresh-btn:hover {
  background: var(--color-accent);
  color: var(--color-on-primary);
  border-color: var(--color-accent);
}

.fullscreen-btn svg,
.refresh-btn svg {
  width: 18px;
  height: 18px;
}

.refresh-btn {
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--color-secondary);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  color: var(--color-text-secondary);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.big-screen.fullscreen {
  position: fixed;
  inset: 0;
  z-index: 9999;
}

.big-screen.fullscreen .big-screen-content {
  max-width: 1920px;
  margin: 0 auto;
  width: 100%;
  padding: var(--spacing-md) var(--spacing-xl);
}

.big-screen-content {
  flex: 1;
  display: grid;
  grid-template-columns: 1fr 2fr 1fr;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  overflow: hidden;
  min-height: 0;
}

.column {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  overflow: hidden;
  min-height: 0;
}

.panel {
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  padding: var(--spacing-sm);
  overflow: hidden;
}

.panel h3 {
  font-size: 11px;
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-sm);
  text-transform: uppercase;
  letter-spacing: 1px;
}

.status-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-xs);
}

.status-item {
  text-align: center;
  padding: 4px;
}

.status-item .label {
  display: block;
  font-size: 10px;
  color: var(--color-text-muted);
  margin-bottom: 2px;
}

.status-item .value {
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  font-weight: 700;
}

.status-item .value.success { color: var(--color-success); }
.status-item .value.accent { color: var(--color-accent); }
.status-item .value.danger { color: var(--color-danger); }

.chart-panel .chart {
  height: 80px;
}

.map-panel {
  flex: 1 1 auto;
  display: flex;
  flex-direction: column;
  min-height: 0;
  min-height: 450px;
}

.map-panel .chart {
  flex: 1;
  min-height: 0;
  height: 450px;
}

.defense-status {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 4px;
}

.defense-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: var(--spacing-sm);
  background: var(--color-secondary);
  border-radius: var(--radius-md);
  opacity: 0.5;
  transition: all var(--transition-fast);
}

.defense-item.active {
  opacity: 1;
  background: rgba(34, 197, 94, 0.1);
}

.defense-item svg {
  width: 18px;
  height: 18px;
  color: var(--color-text-muted);
}

.defense-item.active svg {
  color: var(--color-success);
}

.defense-item span {
  font-size: 10px;
  color: var(--color-text-muted);
}

.defense-item.active span {
  color: var(--color-success);
}

/* Hero Panel */
.panel.hero {
  height: 90px;
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: center;
  position: relative;
  overflow: hidden;
  flex-shrink: 0;
}

.hero-bg {
  position: absolute;
  inset: 0;
  background: radial-gradient(circle at center, rgba(34, 197, 94, 0.1), transparent 70%);
  pointer-events: none;
}

.glow-orb {
  position: absolute;
  border-radius: 50%;
  filter: blur(60px);
  opacity: 0.2;
  animation: pulse 4s ease-in-out infinite;
  pointer-events: none;
}

.orb-1 {
  width: 100px;
  height: 100px;
  background: var(--color-accent);
  top: -20px;
  left: -20px;
  animation-delay: 0s;
}

.orb-2 {
  width: 80px;
  height: 80px;
  background: var(--color-danger);
  bottom: -10px;
  right: -10px;
  animation-delay: 2s;
}

@keyframes pulse {
  0%, 100% { opacity: 0.2; transform: scale(1); }
  50% { opacity: 0.4; transform: scale(1.1); }
}

.scan-line {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--color-accent), transparent);
  animation: scan 3s linear infinite;
  opacity: 0.5;
}

@keyframes scan {
  0% { top: 0; }
  100% { top: 100%; }
}

.hero-content {
  display: flex;
  gap: var(--spacing-xl);
  position: relative;
  z-index: 1;
}

.hero-stat {
  text-align: center;
}

.hero-value {
  display: block;
  font-family: var(--font-mono);
  font-size: var(--text-2xl);
  font-weight: 700;
  color: var(--color-foreground);
}

.hero-value.danger {
  color: var(--color-danger);
}

.hero-label {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

.hero-divider {
  width: 2px;
  height: 40px;
  background: var(--color-border);
}

.shield-icon {
  position: absolute;
  right: var(--spacing-md);
  top: 50%;
  transform: translateY(-50%);
  width: 36px;
  height: 36px;
  color: var(--color-accent);
  opacity: 0.3;
}

.shield-icon svg {
  width: 100%;
  height: 100%;
}

/* Attacker List */
.attacker-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  overflow-y: auto;
  max-height: 160px;
}

.attacker-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: 6px var(--spacing-sm);
  background: var(--color-secondary);
  border-radius: var(--radius-md);
  font-size: 11px;
}

.attacker-item .rank {
  width: 20px;
  height: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--color-accent);
  color: var(--color-on-primary);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 600;
  flex-shrink: 0;
}

.attacker-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
}

.attacker-info .ip {
  font-family: var(--font-mono);
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.attacker-info .types {
  font-size: 10px;
  color: var(--color-text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.attacker-item .count {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  color: var(--color-danger);
  flex-shrink: 0;
}

/* Alert List */
.alert-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  overflow-y: auto;
  max-height: 180px;
}

.alert-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: 6px var(--spacing-sm);
  background: var(--color-secondary);
  border-radius: var(--radius-md);
}

.alert-icon {
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-md);
  flex-shrink: 0;
}

.alert-icon svg {
  width: 12px;
  height: 12px;
}

.alert-icon.danger { background: rgba(239, 68, 68, 0.2); color: var(--color-danger); }
.alert-icon.warning { background: rgba(245, 158, 11, 0.2); color: var(--color-warning); }
.alert-icon.purple { background: rgba(139, 92, 246, 0.2); color: #8B5CF6; }
.alert-icon.info { background: rgba(59, 130, 246, 0.2); color: var(--color-info); }

.alert-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
}

.alert-content .type {
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.alert-content .ip {
  font-size: 10px;
  color: var(--color-text-muted);
  font-family: var(--font-mono);
}

.alert-item .action {
  font-size: var(--text-xs);
  padding: 2px 8px;
  border-radius: var(--radius-sm);
}

.alert-item .action.block {
  background: rgba(239, 68, 68, 0.2);
  color: var(--color-danger);
}

.alert-item .action.allow {
  background: rgba(34, 197, 94, 0.2);
  color: var(--color-success);
}

.empty-list {
  text-align: center;
  padding: var(--spacing-lg);
  color: var(--color-text-muted);
  font-size: var(--text-sm);
}

/* Stream List */
.stream-list {
  height: 200px;
  overflow: auto;
  font-family: var(--font-mono);
}

.stream-line {
  display: flex;
  gap: 8px;
  align-items: baseline;
  font-size: 11px;
  line-height: 1.8;
  color: rgba(140, 255, 182, 0.7);
}

.stream-line .t {
  color: rgba(140, 255, 182, 0.45);
  min-width: 60px;
}

.stream-line .ip {
  color: #8cffb6;
  min-width: 100px;
}

.stream-line .ip.hot {
  color: #ff4d5b;
  font-weight: 700;
}

.stream-line .m {
  color: #56b2c2;
  min-width: 40px;
}

.stream-line .a {
  color: #e5c07b;
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.stream-line .b {
  color: #ff4d5b;
  font-weight: 800;
}
</style>
