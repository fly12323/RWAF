<template>
  <div class="monitor-page">
    <header class="page-header"><div><h2>运行监控与告警</h2><p>后台定期采样，页面每 10 秒刷新。采样时间：{{ currentHealth.status !== 'starting' && snapshot?.sampled_at ? time(snapshot.sampled_at) : '等待首次采样' }}</p></div><button class="btn btn-secondary" :disabled="busy" @click="refresh">刷新</button></header>
    <p class="error" v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <div class="page-tabs" role="tablist" aria-label="页面内容"><button role="tab" :aria-selected="activeTab === 'events'" :class="{ active: activeTab === 'events' }" @click="activeTab = 'events'">运行状态与告警</button><button role="tab" :aria-selected="activeTab === 'quarantine'" :class="{ active: activeTab === 'quarantine' }" @click="activeTab = 'quarantine'">异常日志隔离</button><button v-if="auth.canWrite" role="tab" :aria-selected="activeTab === 'config'" :class="{ active: activeTab === 'config' }" @click="activeTab = 'config'">告警阈值</button></div>
    <LogQuarantinePanel v-if="activeTab === 'quarantine'" />
    <div v-show="activeTab === 'events'" class="tab-content">
    <section v-if="snapshot" class="panel">
      <p :class="currentHealth.status === 'healthy' ? 'healthy' : 'error'" role="status">{{ healthLabels[currentHealth.status] ?? currentHealth.status }} · {{ currentHealth.ready ? '服务已就绪' : '服务尚未就绪' }}<span v-if="currentHealth.status !== 'starting'"> · 采样距今 {{ currentHealth.age_seconds }} 秒</span></p>
      <div class="dependencies"><span v-for="(state, name) in snapshot.dependencies" :key="name" :class="state === 'ok' ? 'healthy' : 'error'">{{ name }} · {{ state === 'ok' ? '正常' : state === 'unknown' ? '等待采样' : '不可用' }}</span><span :class="snapshot.consumer && !snapshot.consumer.stale && snapshot.consumer.state === 'running' ? 'healthy' : 'error'">消费者 · {{ snapshot.consumer && !snapshot.consumer.stale && snapshot.consumer.state === 'running' ? '心跳正常' : (currentHealth.status === 'starting' ? '等待采样' : snapshot.consumer?.state === 'retrying' ? '重试中' : '缺失 / 超时 / 未运行') }}</span></div>
      <div class="metrics">
        <div><span>Kafka 消费积压</span><strong>{{ snapshot.kafka_lag ?? '不可用' }}</strong></div>
        <div><span>代理请求 / 秒</span><strong>{{ fixed(snapshot.requests?.rps) }}</strong></div>
        <div><span>平均延迟</span><strong>{{ fixed(snapshot.requests?.average_ms) }} ms</strong></div>
        <div><span>P99 延迟桶上界</span><strong>{{ snapshot.requests?.p99_bucket_ms ?? 0 }} ms</strong></div>
        <div><span>代理 5xx 比例</span><strong>{{ fixed(snapshot.requests?.error_percent) }}%</strong></div>
        <div><span>Go 堆内存 / 协程</span><strong>{{ snapshot.heap_mb }} MiB / {{ snapshot.goroutines }}</strong></div>
        <div><span>待发送日志</span><strong>{{ snapshot.log_pipeline?.queued ?? 0 }} 条</strong></div>
        <div v-if="snapshot.log_pipeline?.durable"><span>持久化缓冲占用</span><strong>{{ fixed((snapshot.log_pipeline.spool_bytes ?? 0) / 1048576) }} / {{ fixed((snapshot.log_pipeline.spool_capacity_bytes ?? 0) / 1048576) }} MiB</strong></div>
        <div><span>日志丢弃 / 发送错误</span><strong>{{ snapshot.log_pipeline?.dropped ?? 0 }} / {{ snapshot.log_pipeline?.errors ?? 0 }}</strong></div>
      </div>
      <div class="metrics">
        <div><span>数据库占用（含索引）</span><strong>{{ mib(snapshot.storage.database_bytes) }}</strong></div>
        <div><span>数据库增长估计</span><strong>{{ snapshot.storage.growth_mb_hour == null ? '等待 ≥60 秒窗口' : fixed(snapshot.storage.growth_mb_hour) + ' MiB/小时' }}</strong></div>
        <div><span>日志缓冲磁盘剩余空间</span><strong>{{ mib(snapshot.storage.spool_disk_free_bytes) }}</strong></div>
        <div><span>日志查询 / 错误 / 取消</span><strong>{{ snapshot.log_queries.count }} / {{ snapshot.log_queries.errors }} / {{ snapshot.log_queries.canceled }}</strong></div>
        <div><span>日志查询平均耗时</span><strong>{{ snapshot.log_queries.count ? fixed(snapshot.log_queries.average_ms) + ' ms' : '本周期无查询' }}</strong></div>
        <div><span>日志查询 P95 桶上界</span><strong>{{ snapshot.log_queries.count ? snapshot.log_queries.p95_bucket_ms + ' ms' : '本周期无查询' }}</strong></div>
      </div>
      <p class="hint">所有日志继续保留在数据库；容量阈值是人工配置的预算，不代表数据库磁盘总量。磁盘剩余空间属于 WAF 日志缓冲所在文件系统。增长估计基于 60–300 秒以上的采样窗口；查询指标包含缓存命中与响应处理，用户离开页面造成的取消单独计数，60000 ms 是溢出桶标记。</p>
      <p v-if="snapshot.storage.database_error || snapshot.storage.spool_disk_error" class="error">容量采样部分失败，请检查依赖及磁盘路径。不可用数据不代表零占用。</p>
      <div v-if="snapshot.storage.tables.length" class="table-scroll"><table><thead><tr><th>日志表</th><th>占用（含索引）</th><th>估计行数</th></tr></thead><tbody><tr v-for="table in snapshot.storage.tables" :key="table.name"><td>{{ table.name }}</td><td>{{ mib(table.bytes) }}</td><td>{{ table.estimated_rows }}</td></tr></tbody></table></div>
      <p class="hint" v-if="snapshot.storage.tables.length">行数来自 PostgreSQL 统计估计，依赖 ANALYZE 更新；不是精确计数。</p>
      <p class="hint">代理指标对应上一采样周期；延迟采用直方图估算，60000 ms 为最后一个溢出桶标记。内存和累计队列指标属于当前 WAF 进程；Kafka 积压属于配置的消费者组。</p>
      <p class="error" v-if="snapshot.config_error">监控配置读取失败，继续使用上一份配置。</p><p class="error" v-if="snapshot.alert_store_error">告警无法写入数据库，以下实时异常仍可查看。</p>
      <p class="hint" v-if="!snapshot.alerts_enabled">运行告警持久化已关闭，健康采样继续执行。</p>
      <ul v-if="snapshot.conditions.length" class="conditions"><li v-for="condition in snapshot.conditions" :key="condition.key">{{ condition.severity === 'critical' ? '严重' : '警告' }} · {{ condition.message }}</li></ul><p v-else :class="currentHealth.status === 'healthy' ? 'healthy hint' : 'hint'">{{ currentHealth.status === 'starting' ? '等待首次采样' : currentHealth.stale ? '采样已过期，请检查后台监控' : '本次采样未发现运行异常' }}</p>
    </section>
    <section class="panel"><h3>告警记录</h3><div class="filters"><label>状态<select class="input" v-model="status" @change="filter"><option value="">全部</option><option value="open">未恢复</option><option value="resolved">已恢复 / 已处理</option></select></label><label>来源<select class="input" v-model="source" @change="filter"><option value="">全部</option><option value="runtime">运行监控</option><option value="weak_password">弱口令检测</option><option value="log_quarantine">日志隔离</option></select></label></div>
      <p class="hint">运行告警自动去重与恢复；确认表示已阅，不关闭仍存在的故障。弱口令告警可在处理后手动关闭，再次命中会产生新告警。</p>
      <div class="table-scroll"><table><thead><tr><th>最近发生</th><th>级别 / 来源</th><th>内容</th><th>次数</th><th>状态</th><th>处理</th></tr></thead><tbody>
        <tr v-for="alert in alerts" :key="alert.id"><td>{{ time(alert.last_seen) }}</td><td :class="alert.severity === 'critical' ? 'error' : ''">{{ alert.severity === 'critical' ? '严重' : '警告' }} / {{ alert.source === 'runtime' ? '运行监控' : alert.source === 'log_quarantine' ? '日志隔离' : '弱口令' }}</td><td>{{ alert.message }}</td><td>{{ alert.occurrences }}</td><td>{{ alert.status === 'open' ? '未恢复' : '已恢复 / 已处理' }}</td><td>
          <span v-if="alert.acknowledged_at">{{ alert.acknowledged_by }} 已确认</span><button v-else-if="auth.canWrite" class="btn btn-secondary" :disabled="actionBusy" @click="acknowledge(alert.id)">确认</button>
          <button v-if="auth.canWrite && alert.source === 'weak_password' && alert.status === 'open'" class="btn btn-secondary" :disabled="actionBusy" @click="resolve(alert.id)">已处理</button>
        </td></tr><tr v-if="!alerts.length"><td colspan="6">暂无告警</td></tr>
      </tbody></table></div><div class="pagination"><button class="btn btn-secondary" :disabled="page <= 1 || busy" @click="changePage(-1)">上一页</button><span>第 {{ page }} 页 / 共 {{ total }} 条</span><button class="btn btn-secondary" :disabled="page * 20 >= total || busy" @click="changePage(1)">下一页</button></div>
    </section>
    </div>
    <form v-if="auth.canWrite && config" v-show="activeTab === 'config'" class="panel" @submit.prevent="save"><h3>全局运行告警阈值</h3><SettingSwitch v-model="config.enabled" label="运行告警持久化" /><div class="fields">
      <label v-for="field in configFields" :key="field.key">{{ field.label }}<input class="input" type="number" v-model.number="config[field.key]" :min="field.min" :max="field.max" required /></label>
    </div><p class="hint">配置在下一次采样读取。消费者心跳每 5 秒更新；告警仅在系统内展示，暂不发送邮件或 Webhook。</p><button class="btn btn-primary" :disabled="saving">{{ saving ? '保存中…' : '保存监控配置' }}</button></form>
  </div>
</template>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api } from '@/api'
import SettingSwitch from '@/components/SettingSwitch.vue'
import LogQuarantinePanel from '@/components/LogQuarantinePanel.vue'
import { useAuthStore } from '@/stores/auth'
import type { MonitorConfig, RuntimeSnapshot, SecurityAlert } from '@/types/api'
const activeTab = ref('events')
const auth = useAuthStore(), snapshot = ref<RuntimeSnapshot | null>(null), config = ref<MonitorConfig | null>(null), alerts = ref<SecurityAlert[]>([])
const page = ref(1), total = ref(0), status = ref(''), source = ref(''), busy = ref(false), saving = ref(false), actionBusy = ref(false), error = ref(''), notice = ref('')
const clock = ref(Date.now()), receivedAt = ref(Date.now())
const currentHealth = computed(() => {
  const state = snapshot.value?.health ?? { status: 'starting', ready: false, stale: false, age_seconds: 0 }
  if (state.status === 'starting' || state.status === 'stopping') return state
  const age = state.age_seconds + Math.max(0, Math.floor((clock.value - receivedAt.value) / 1000))
  if (age > (snapshot.value?.interval_seconds ?? 15) + 15) return { ...state, status: 'stale', ready: false, stale: true, age_seconds: age }
  return { ...state, age_seconds: age }
})
const healthLabels: Record<string, string> = { starting: '启动中', healthy: '运行正常', degraded: '存在异常', stale: '采样已过期', stopping: '正在停止' }
const mib = (v: number | null) => v == null ? '不可用' : fixed(v / 1048576) + ' MiB'
const configFields = [
  { key: 'database_budget_mb', label: '数据库容量预算（MiB，80%预警）', min: 1, max: 1073741824 },
  { key: 'database_growth_mb_hour', label: '数据库增长阈值（MiB/小时）', min: 1, max: 1073741824 },
  { key: 'spool_disk_free_mb', label: '缓冲磁盘剩余空间阈值（MiB）', min: 1, max: 1073741824 },
  { key: 'log_query_p95_ms', label: '日志查询 P95 桶阈值（ms）', min: 1, max: 60000 },
  { key: 'interval_seconds', label: '采样间隔（秒）', min: 5, max: 300 }, { key: 'kafka_lag_threshold', label: 'Kafka 积压阈值（条）', min: 1, max: 1000000000 },
  { key: 'queue_percent', label: '日志缓冲占用阈值（%）', min: 1, max: 100 }, { key: 'consumer_timeout_seconds', label: '消费者心跳超时（秒）', min: 15, max: 300 },
  { key: 'heap_limit_mb', label: 'Go 堆内存阈值（MiB）', min: 1, max: 1048576 }, { key: 'proxy_error_percent', label: '代理 5xx 比例阈值（%）', min: 1, max: 100 },
  { key: 'proxy_min_requests', label: '代理告警最小采样请求数', min: 1, max: 1000000000 }, { key: 'proxy_p99_ms', label: '代理 P99 延迟桶阈值（ms）', min: 1, max: 60000 }
] as const
const time = (v: string) => new Date(v).toLocaleString(), fixed = (v?: number) => (v ?? 0).toFixed(2)
const refresh = async () => { if (busy.value) return; busy.value = true; error.value = ''; try {
  const results = await Promise.allSettled([api.monitorStatus(), api.alerts(page.value, status.value, source.value)])
  if (results[0].status === 'fulfilled') { snapshot.value = results[0].value; receivedAt.value = Date.now(); clock.value = receivedAt.value } else error.value = String(results[0].reason)
  if (results[1].status === 'fulfilled') { alerts.value = results[1].value.list ?? []; total.value = results[1].value.total } else error.value = String(results[1].reason)
} finally { busy.value = false } }
const filter = () => { page.value = 1; refresh() }, changePage = (delta: number) => { page.value += delta; refresh() }
const acknowledge = async (id: number) => { actionBusy.value = true; try { await api.acknowledgeAlert(id); await refresh() } catch (e) { error.value = e instanceof Error ? e.message : '确认失败' } finally { actionBusy.value = false } }
const resolve = async (id: number) => { actionBusy.value = true; try { await api.resolveWeakAlert(id); await refresh() } catch (e) { error.value = e instanceof Error ? e.message : '处理失败' } finally { actionBusy.value = false } }
const save = async () => { if (!config.value) return; saving.value = true; error.value = ''; notice.value = ''; try { config.value = await api.updateMonitorConfig(config.value); notice.value = '监控配置已保存，将在下一次采样读取' } catch (e) { error.value = e instanceof Error ? e.message : '保存失败' } finally { saving.value = false } }
let timer: ReturnType<typeof setInterval>, clockTimer: ReturnType<typeof setInterval>
onMounted(async () => { clockTimer = setInterval(() => { clock.value = Date.now() }, 1000); timer = setInterval(refresh, 10000); await refresh(); if (auth.canWrite) { try { config.value = await api.monitorConfig() } catch (e) { error.value = e instanceof Error ? e.message : '配置加载失败' } } })
onUnmounted(() => { clearInterval(timer); clearInterval(clockTimer) })
</script>
<style scoped>
.monitor-page { display:flex; flex-direction:column; gap:20px; } .page-header { display:flex; justify-content:space-between; align-items:center; gap:16px; } .page-header p,.hint { color:var(--color-text-muted); font-size:var(--text-sm); line-height:1.7; margin-top:8px; }
.panel { padding:24px; border:1px solid var(--color-border); border-radius:var(--radius-lg); background:var(--color-muted); } h3 { margin-bottom:16px; }
.dependencies,.pagination,.filters,.toggle { display:flex; gap:16px; align-items:center; flex-wrap:wrap; } .dependencies span { padding:8px 12px; border:1px solid var(--color-border); border-radius:var(--radius-md); }
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin-top:20px; } .metrics div { padding:16px; border:1px solid var(--color-border); border-radius:var(--radius-md); } .metrics span { display:block; color:var(--color-text-muted); font-size:var(--text-sm); } strong { display:block; font-size:22px; margin-top:8px; }
.fields { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin:20px 0; } .fields label,.filters label { display:flex; flex-direction:column; gap:8px; font-size:var(--text-sm); } .conditions { margin:16px 0 0 20px; line-height:1.9; }
.table-scroll { overflow:auto; margin-top:16px; } table { width:100%; border-collapse:collapse; font-size:var(--text-sm); } th,td { text-align:left; padding:12px; border-bottom:1px solid var(--color-border); } th { color:var(--color-text-muted); } td button { margin:4px; } .pagination { margin-top:18px; } .error { color:var(--color-danger); } .healthy { color:var(--color-accent); }
@media(max-width:600px){.page-header{align-items:flex-start;flex-direction:column}.panel{padding:16px}}
.page-tabs{display:flex;gap:8px;border-bottom:1px solid var(--color-border)}.page-tabs button{padding:12px 16px;color:var(--color-text-secondary);border-bottom:2px solid transparent}.page-tabs button.active{color:var(--color-accent);border-bottom-color:var(--color-accent)}.tab-content{display:flex;flex-direction:column;gap:20px}
</style>
