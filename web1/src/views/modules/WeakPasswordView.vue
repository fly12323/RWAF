<template>
  <div class="security-page">
    <header class="page-header"><div><h2>弱口令检测</h2><p>查看认证请求中的弱口令风险，点击事件查看原始请求。</p></div><div class="header-actions"><RouterLink v-if="auth.canWrite" class="btn btn-secondary" to="/protection?section=weak-password">配置检测策略</RouterLink><button class="btn btn-secondary" @click="refresh" :disabled="busy">刷新事件</button></div></header>
    <p class="error" v-if="error" role="alert">{{ error }}</p>
    <section class="metrics"><div v-for="item in metrics" :key="item.key"><span>{{ item.label }}</span><strong>{{ stats[item.key] ?? '—' }}</strong></div></section>
    <section class="panel"><div class="event-toolbar"><div><h3>检测事件 <span class="event-count">{{ total }}</span></h3></div><label>接口类型<select class="input" v-model="kindFilter" @change="page = 1; refresh()"><option value="">全部类型</option><option v-for="(title,key) in kinds" :key="key" :value="key">{{ title }}</option></select></label></div><p class="hint">命中表示提交了弱密码，不代表登录成功。密码、对应哈希和账号内容不保存在事件中。</p>
      <div class="table-scroll"><table><thead><tr><th>时间</th><th>站点 / IP</th><th>接口</th><th>类型</th><th>命中形式</th><th>结果</th><th>操作</th></tr></thead><tbody>
        <tr v-for="event in events" :key="event.id"><td>{{ time(event.created_at) }}</td><td>{{ event.site_id }} / {{ event.client_ip }}</td><td>{{ event.endpoint }}<small>{{ event.path }}</small></td><td>{{ kinds[event.kind] || event.kind }}</td><td><span class="encoding-badge">{{ event.representation }}</span></td><td><span class="outcome-badge">提交弱密码</span><small>登录结果未知</small></td><td><button class="btn btn-secondary" @click="viewDetail(event)">详情</button></td></tr>
        <tr v-if="!events.length"><td colspan="7">暂无检测事件</td></tr>
      </tbody></table></div>
      <div class="pagination"><button class="btn btn-secondary" :disabled="page <= 1 || busy" @click="changePage(-1)">上一页</button><span>第 {{ page }} 页 / 共 {{ total }} 条</span><button class="btn btn-secondary" :disabled="page * 20 >= total || busy" @click="changePage(1)">下一页</button></div>
    </section>
    <div v-if="selectedEvent" class="detail-overlay" @click.self="closeDetail" @keydown.esc="closeDetail"><section class="event-detail" role="dialog" aria-modal="true" aria-labelledby="weak-detail-title"><header><h3 id="weak-detail-title">弱口令事件 #{{ selectedEvent.id }}</h3><button ref="closeButton" class="btn btn-secondary" @click="closeDetail">关闭详情</button></header><p class="hint">仅证明提交了弱密码，登录结果未知。关联日志按原始内容展示，已脱敏的历史内容无法恢复。</p><dl class="event-meta"><div><dt>站点</dt><dd>{{ detail?.site_name || ('站点 ' + selectedEvent.site_id) }}</dd></div><div><dt>接口 / 业务类型</dt><dd>{{ selectedEvent.endpoint }} / {{ kinds[selectedEvent.kind] }}</dd></div><div><dt>路径</dt><dd>{{ selectedEvent.path }}</dd></div><div><dt>命中形式</dt><dd>{{ selectedEvent.representation }}</dd></div><div><dt>字典版本</dt><dd>{{ selectedEvent.dictionary_version }}</dd></div><div><dt>检测时间</dt><dd>{{ time(selectedEvent.created_at) }}</dd></div></dl><p v-if="detailBusy">正在读取关联请求…</p><p v-if="detailError" role="alert" class="error">{{ detailError }}</p><RequestEvidence v-if="detail?.request" :log="detail.request.log" /><p v-else-if="detail && !detailBusy" class="hint">{{ detail.request_notice || '关联请求暂不可用' }} · 请求 ID：{{ selectedEvent.request_id }}</p></section></div>
  </div>
</template>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, nextTick } from 'vue'
import { api } from '@/api'
import RequestEvidence from '@/components/RequestEvidence.vue'
import { useAuthStore } from '@/stores/auth'
import type { WeakPasswordEvent } from '@/types/api'
const selectedEvent = ref<WeakPasswordEvent | null>(null), detail = ref<Awaited<ReturnType<typeof api.weakPasswordEventDetail>> | null>(null)
const detailBusy = ref(false), detailError = ref(''), closeButton = ref<HTMLButtonElement | null>(null)
const closeDetail = () => { selectedEvent.value = null; detail.value = null }
const viewDetail = async (event: WeakPasswordEvent) => {
  selectedEvent.value = event; detail.value = null; detailError.value = ''; detailBusy.value = true
  await nextTick(); closeButton.value?.focus()
  try { const result = await api.weakPasswordEventDetail(event.id); if (selectedEvent.value?.id === event.id) detail.value = result }
  catch (e) { if (selectedEvent.value?.id === event.id) detailError.value = e instanceof Error ? e.message : '详情读取失败' }
  finally { if (selectedEvent.value?.id === event.id) detailBusy.value = false }
}
const auth = useAuthStore(), events = ref<WeakPasswordEvent[]>([]), total = ref(0), page = ref(1), stats = ref<Record<string, number | string | boolean>>({})
const error = ref(''), busy = ref(false)
const kinds: Record<string,string> = { login:'登录', register:'注册', password:'修改 / 重置密码' }
const kindFilter = ref('')
const metrics = computed(() => [{ key: 'matched', label: '本次运行命中' }, { key: 'processed', label: '已检测请求' }, { key: 'queued', label: '待检测请求' }, { key: 'dropped', label: '检测丢弃' }])
const time = (v: string) => new Date(v).toLocaleString()
const refresh = async () => { if (busy.value) return; busy.value = true; error.value = ''; try { const data = await api.weakPasswordEvents(page.value, kindFilter.value); events.value = data.list ?? []; total.value = data.total; stats.value = data.stats } catch (e) { error.value = e instanceof Error ? e.message : '读取失败' } finally { busy.value = false } }
const changePage = (delta: number) => { page.value += delta; refresh() }
let timer: ReturnType<typeof setInterval>
onMounted(async () => { timer = setInterval(refresh, 10000); await refresh() })
onUnmounted(() => clearInterval(timer))
</script>
<style scoped>
.security-page { display:flex; flex-direction:column; gap:20px; } .page-header { display:flex; justify-content:space-between; align-items:center; gap:16px; }
.page-header p,.hint { color:var(--color-text-muted); font-size:var(--text-sm); line-height:1.7; margin-top:8px; }
.panel { padding:24px; border:1px solid var(--color-border); border-radius:var(--radius-lg); background:var(--color-muted); } h3,h4 { margin-bottom:16px; } h4 { margin-top:24px; }
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:12px; } .metrics div { padding:16px; border:1px solid var(--color-border); border-radius:var(--radius-md); } .metrics span { display:block; color:var(--color-text-muted); font-size:var(--text-sm); } strong { display:block; font-size:24px; margin-top:8px; }
.fields { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; } .fields label,.field { display:flex; flex-direction:column; gap:8px; font-size:var(--text-sm); } .field { margin:12px 0; }
.representations,.actions,.toggle,.pagination { display:flex; align-items:center; gap:16px; flex-wrap:wrap; } .representations label { display:flex; gap:6px; } .endpoint { padding:16px 0; border-bottom:1px solid var(--color-border); } .endpoint button { margin-top:12px; } .actions,.pagination { margin-top:18px; }
.table-scroll { overflow:auto; margin-top:16px; } table { width:100%; border-collapse:collapse; font-size:var(--text-sm); } th,td { text-align:left; padding:12px; border-bottom:1px solid var(--color-border); } th,small { color:var(--color-text-muted); } small { display:block; } .error { color:var(--color-danger); }
@media(max-width:600px){.page-header{align-items:flex-start;flex-direction:column}.panel{padding:16px}}
.page-tabs{display:flex;gap:8px;border-bottom:1px solid var(--color-border)}.page-tabs button{padding:12px 16px;color:var(--color-text-secondary);border-bottom:2px solid transparent}.page-tabs button.active{color:var(--color-accent);border-bottom-color:var(--color-accent)}.tab-content{display:flex;flex-direction:column;gap:20px}
.detail-overlay{position:fixed;inset:0;background:#0006;z-index:500;display:flex;align-items:center;justify-content:center;padding:24px}.event-detail{width:min(920px,100%);max-height:90dvh;overflow:auto;background:var(--color-primary);border:1px solid var(--color-border);border-radius:8px;padding:24px}.event-detail header{display:flex;justify-content:space-between;align-items:center;gap:16px}.event-detail h3{margin:0}.event-meta{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:20px;font-size:14px}.event-meta dt{color:var(--color-text-secondary)}.event-meta dd{margin-top:6px;overflow-wrap:anywhere}@media(max-width:600px){.detail-overlay{padding:12px}.event-detail{padding:16px}.event-meta{grid-template-columns:1fr}}
.dictionary-toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center}.dictionary-toolbar>.input{flex:1;min-width:180px}.import-button{position:relative;cursor:pointer}.import-button input{position:absolute;inset:0;opacity:0;width:100%;cursor:pointer}.dictionary-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:10px;margin-top:16px}.dictionary-card{display:flex;align-items:center;border:1px solid var(--color-border);border-radius:6px;overflow:hidden;background:var(--color-primary)}.word-button{flex:1;min-width:0;text-align:left;padding:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--color-foreground)}.word-button:hover{background:var(--color-secondary);color:var(--color-accent)}.word-delete{padding:10px;color:var(--color-text-muted);font-size:20px}.word-delete:hover{color:var(--color-danger)}.encoding-detail{max-width:720px}.encoding-values{margin:20px 0}.encoding-values>div{padding:12px 0;border-bottom:1px solid var(--color-border)}.encoding-values dt{display:flex;gap:12px;align-items:center;color:var(--color-text-secondary)}.encoding-values dd{margin:8px 0 0;overflow-wrap:anywhere;user-select:all}.encoding-values small{display:inline}
.header-actions,.event-toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px}.event-toolbar h3{margin:0}.event-toolbar label{display:flex;align-items:center;gap:10px;color:var(--color-text-secondary);font-size:14px}.event-count{font-size:14px;padding:3px 8px;background:var(--color-secondary);border-radius:4px;color:var(--color-text-secondary)}.outcome-badge{display:inline-block;padding:4px 8px;color:var(--color-warning);background:var(--color-secondary);border-radius:4px}.encoding-badge{display:inline-block;padding:4px 8px;background:var(--color-secondary);border-radius:4px}.metrics>div:first-child{border-left:3px solid var(--color-warning)}tbody tr:hover{background:var(--color-secondary)}@media(max-width:600px){.event-toolbar{align-items:flex-start;flex-direction:column}.header-actions{flex-wrap:wrap}}
</style>
