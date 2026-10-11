<template>
  <section class="quarantine-panel">
    <h3>异常日志隔离</h3>
    <p class="hint">异常消息完整保留在数据库，隔离成功后继续消费。原始记录不会被重放覆盖；管理员可修复事件并重放入库，处理过程写入操作审计。</p>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <p v-if="notice" role="status">{{ notice }}</p>
    <div class="filters"><label>状态<select class="input" v-model="status" @change="filter"><option value="pending">待处理</option><option value="replayed">已重放</option><option value="">全部</option></select></label><button class="btn btn-secondary" :disabled="busy" @click="refresh">刷新</button></div>
    <div class="table-scroll"><table><thead><tr><th>时间 / ID</th><th>主题 / 分区 / offset</th><th>原因</th><th>大小 / 状态</th><th>操作</th></tr></thead><tbody>
      <tr v-for="item in items" :key="item.id"><td>{{ time(item.created_at) }} / {{ item.id }}</td><td>{{ item.topic }} / {{ item.partition }} / {{ item.offset }}</td><td>{{ item.reason }}</td><td>{{ item.payload_bytes }} 字节 / {{ item.status === 'pending' ? '待处理' : '已重放' }}</td><td><button class="btn btn-secondary" :disabled="actionBusy" @click="inspect(item.id)">查看详情</button></td></tr>
      <tr v-if="!items.length"><td colspan="5">暂无隔离记录</td></tr>
    </tbody></table></div>
    <div class="filters"><button class="btn btn-secondary" :disabled="busy || page <= 1" @click="changePage(-1)">上一页</button><span>第 {{ page }} 页 / 共 {{ total }} 条</span><button class="btn btn-secondary" :disabled="busy || page * 20 >= total" @click="changePage(1)">下一页</button></div>
    <section v-if="detail" class="detail">
      <h4>隔离记录 {{ detail.id }}</h4><p class="hint">消费者组：{{ detail.consumer_group }}；原始 SHA-256：{{ detail.payload_sha256 }}</p>
      <p v-if="detail.status === 'replayed'" class="hint">{{ detail.replayed_by }} 于 {{ time(detail.replayed_at!) }} 重放；事件：{{ detail.replay_event_id }}；原因：{{ detail.replay_reason }}</p>
      <details><summary>原始消息</summary><pre>{{ original }}</pre><a v-if="detail.payload" :href="`data:application/octet-stream;base64,${detail.payload}`" :download="`quarantined-${detail.id}.bin`">下载原始字节</a></details>
      <form v-if="auth.isAdmin && detail.status === 'pending'" @submit.prevent="replay">
        <label>修复后的事件 JSON<textarea class="input" v-model="draft" rows="14" spellcheck="false" required /></label>
        <label>重放原因<input class="input" v-model="reason" maxlength="500" required /></label>
        <p class="hint">重放只恢复日志，不向业务后端发送请求。重复事件 ID 沿用入库去重；成功后该隔离记录标为已重放。</p>
        <button class="btn btn-primary" :disabled="actionBusy || !reason.trim()">{{ actionBusy ? '重放中…' : '校验并重放入库' }}</button>
      </form>
      <p v-else-if="detail.status === 'pending'" class="hint">仅管理员可修复并重放。</p>
    </section>
  </section>
</template>
<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'
import type { QuarantinedEvent } from '@/types/api'
const auth = useAuthStore()
const items = ref<QuarantinedEvent[]>([]), detail = ref<QuarantinedEvent | null>(null)
const page = ref(1), total = ref(0), status = ref('pending'), busy = ref(false), actionBusy = ref(false)
const error = ref(''), notice = ref(''), draft = ref(''), original = ref(''), reason = ref('')
const time = (v: string) => new Date(v).toLocaleString()
const refresh = async () => { if (busy.value) return; busy.value = true; try { const result = await api.quarantinedEvents(page.value, status.value); items.value = result.list ?? []; total.value = result.total } catch (e) { error.value = e instanceof Error ? e.message : '隔离列表加载失败' } finally { busy.value = false } }
const filter = () => { page.value = 1; refresh() }, changePage = (delta: number) => { page.value += delta; refresh() }
const inspect = async (id: number) => { actionBusy.value = true; error.value = ''; notice.value = ''; try {
  const result = await api.quarantinedEvent(id)
  original.value = new TextDecoder().decode(Uint8Array.from(atob(result.payload ?? ''), c => c.charCodeAt(0)))
  draft.value = original.value; reason.value = ''; detail.value = result
} catch (e) { error.value = e instanceof Error ? e.message : '详情加载失败' } finally { actionBusy.value = false } }
const replay = async () => { if (!detail.value || actionBusy.value) return; actionBusy.value = true; error.value = ''; notice.value = ''; try {
  const result = await api.replayQuarantinedEvent(detail.value.id, JSON.parse(draft.value), reason.value.trim())
  detail.value = { ...detail.value, ...result }; notice.value = '日志已重放入库，原始隔离记录保留'; await refresh()
} catch (e) { error.value = e instanceof Error ? e.message : '重放失败，原记录保留' } finally { actionBusy.value = false } }
let timer: ReturnType<typeof setInterval>
onMounted(() => { refresh(); timer = setInterval(refresh, 10000) })
onUnmounted(() => clearInterval(timer))
</script>
<style scoped>
.quarantine-panel{padding:24px;border:1px solid var(--color-border);border-radius:var(--radius-lg);background:var(--color-muted)}
.hint{color:var(--color-text-muted);line-height:1.7;margin:12px 0;font-size:var(--text-sm)}.error{color:var(--color-danger)}
.filters{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin:16px 0}.table-scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:var(--text-sm)}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--color-border);overflow-wrap:anywhere}
.detail{border-top:1px solid var(--color-border);padding-top:20px;margin-top:20px}.detail form{display:flex;flex-direction:column;gap:16px;margin-top:20px}label{display:flex;flex-direction:column;gap:8px}textarea{width:100%;font-family:monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:300px;overflow:auto;margin:12px 0}a{color:var(--color-accent)}
</style>
