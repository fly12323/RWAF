<template><div class="weak-config"><p v-if="error" class="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p><p v-if="!configLoaded">正在加载弱口令配置…</p>    <form v-if="configLoaded" class="panel" @submit.prevent="save">
      <h3>弱口令检测配置</h3><SettingSwitch v-model="config.enabled" label="弱口令检测" />
      <p class="hint">所有站点共用这些识别规则，按顺序使用第一条匹配的规则。检测开关不影响请求日志记录。</p>
      <div class="page-tabs" aria-label="弱口令配置分组"><button type="button" :class="{active: configPage === 'dictionary'}" @click="configPage = 'dictionary'">字典与编码</button><button type="button" :class="{active: configPage === 'endpoints'}" @click="configPage = 'endpoints'">认证接口 <span>{{ endpoints.length }}</span></button></div>
      <section v-show="configPage === 'dictionary'"><h4>弱口令字典 <small>{{ dictionary.length }} 项</small></h4>
      <div class="dictionary-toolbar"><input class="input" v-model="newWord" aria-label="新增弱口令" placeholder="输入原始弱口令" @keydown.enter.prevent="addWord" /><button type="button" class="btn btn-secondary" @click="addWord">添加</button><label class="btn btn-secondary import-button">批量导入<input type="file" accept=".txt,text/plain" @change="importDictionary" /></label><input class="input" v-model="wordSearch" aria-label="搜索字典" placeholder="搜索字典" /></div>
      <p class="hint">点击查看对应编码，删除后需保存弱口令配置才生效。导入会合并已有字典并去重。</p>
      <div class="dictionary-grid"><div class="dictionary-card" v-for="word in visibleWords" :key="word"><button type="button" class="word-button" @click="viewWord(word)" :title="word">{{ word }}</button><button type="button" class="word-delete" :aria-label="'删除弱口令 ' + word" @click="removeWord(word)">×</button></div></div>
      <p v-if="!filteredWords.length" class="hint">{{ dictionary.length ? '没有匹配的弱口令' : '字典为空，请添加弱口令' }}</p>
      <div class="pagination" v-if="filteredWords.length > wordPageSize"><button type="button" class="btn btn-secondary" :disabled="wordPage <= 1" @click="wordPage--">上一页字典</button><span>{{ wordPage }} / {{ Math.max(1, Math.ceil(filteredWords.length / wordPageSize)) }}</span><button type="button" class="btn btn-secondary" :disabled="wordPage * wordPageSize >= filteredWords.length" @click="wordPage++">下一页字典</button></div>
      <div class="representations"><label v-for="format in formats" :key="format"><input type="checkbox" :value="format" v-model="config.representations" />{{ format }}</label></div>
      <p class="hint">加载时预生成各种形式，请求中直接精确匹配。MD5/SHA 支持大小写十六进制；其他形式区分大小写。随机盐和随机加密不能按固定字典识别。</p>
      </section><section v-show="configPage === 'endpoints'">
      <h4>认证接口规则</h4>
      <div v-for="(rule, index) in endpoints" :key="index" class="endpoint">
        <div class="fields"><label>名称<input class="input" v-model="rule.name" required maxlength="100" /></label><label>Host（空为全部站点）<input class="input" v-model="rule.host" placeholder="example.com，不带端口" /></label><label>路径<input class="input" v-model="rule.path" placeholder="/api/login，末尾支持 *" required /></label>
          <label>方法<select class="input" v-model="rule.method"><option>POST</option><option>PUT</option><option>PATCH</option></select></label>
          <label>业务类型<select class="input" v-model="rule.kind"><option value="login">登录</option><option value="register">注册</option><option value="password">修改 / 重置密码</option></select></label>
          <label>请求格式<select class="input" v-model="rule.format"><option value="auto">按 Content-Type 识别</option><option value="json">JSON</option><option value="form">表单</option></select></label>
          <label>密码字段（逗号分隔）<input class="input" v-model="rule.fields" placeholder="password, data.password" required /></label>
        </div><button class="btn btn-secondary" type="button" @click="endpoints.splice(index, 1)">删除此识别规则</button>
      </div>
      <p class="hint">JSON 支持 data.password 形式的嵌套字段；表单按字段名匹配。仅检测最多 64 KiB 的请求体，不解析文件上传。无法解析和超限请求会计入“未完成检测”。</p>
      </section><div class="actions"><button class="btn btn-secondary" type="button" @click="configPage = 'endpoints'; addEndpoint()">新增识别规则</button><button class="btn btn-primary" :disabled="saving">{{ saving ? '保存中…' : '保存弱口令配置' }}</button></div>
    </form>
    <div v-if="selectedWord !== null" class="detail-overlay" @click.self="selectedWord = null" @keydown.esc="selectedWord = null"><section class="event-detail encoding-detail" role="dialog" aria-modal="true" aria-labelledby="encoding-title"><header><h3 id="encoding-title">弱口令编码</h3><button ref="encodingClose" type="button" class="btn btn-secondary" @click="selectedWord = null">关闭编码详情</button></header><p class="hint">与检测引擎使用相同的生成方式；只有已勾选的形式参与检测。</p><p v-if="encodingBusy">正在生成…</p><p v-if="encodingError" class="error" role="alert">{{ encodingError }}</p><dl class="encoding-values"><div v-for="format in formats" :key="format"><dt>{{ format }} <small>{{ config.representations.includes(format) ? '参与检测' : '未启用' }}</small></dt><dd>{{ wordEncodings[format] || (format === 'plain' ? selectedWord : '—') }}</dd></div></dl><button type="button" class="btn btn-secondary" @click="removeWord(selectedWord)">删除此弱口令</button></section></div>
</div></template>
<script setup lang="ts">
import { computed, onMounted, reactive, ref, nextTick, watch } from 'vue'
import { api } from '@/api'
import SettingSwitch from '@/components/SettingSwitch.vue'
import type { AuthEndpoint, WeakPasswordConfig } from '@/types/api'
const configPage = ref('dictionary')
const config = reactive<WeakPasswordConfig>({ enabled: true, dictionary: [], representations: [], endpoints: [] })
const endpoints = ref<(Omit<AuthEndpoint, 'password_fields'> & { fields: string })[]>([]), dictionary = ref<string[]>([]), configLoaded = ref(false)
const error = ref(''), notice = ref(''), saving = ref(false)
const formats = ['plain', 'md5', 'sha1', 'sha256', 'base64', 'base64url']
const addEndpoint = () => endpoints.value.push({ name: '', host: '', path: '', method: 'POST', kind: 'login', format: 'auto', fields: 'password' })
const newWord = ref(''), wordSearch = ref(''), wordPage = ref(1), wordPageSize = 60
const selectedWord = ref<string | null>(null), wordEncodings = ref<Record<string,string>>({}), encodingBusy = ref(false), encodingError = ref(''), encodingClose = ref<HTMLButtonElement | null>(null)
const filteredWords = computed(() => dictionary.value.filter(word => word.includes(wordSearch.value)))
const visibleWords = computed(() => filteredWords.value.slice((wordPage.value - 1) * wordPageSize, wordPage.value * wordPageSize))
watch(wordSearch, () => { wordPage.value = 1 })
watch(() => filteredWords.value.length, count => { wordPage.value = Math.min(wordPage.value, Math.max(1, Math.ceil(count / wordPageSize))) })
const mergeWords = (words: string[]) => {
  const merged = [...new Set([...dictionary.value, ...words.filter(word => word.length > 0)])]
  if (merged.length > 10000 || merged.some(word => new TextEncoder().encode(word).length > 256)) { error.value = '字典最多 10000 项，每项最多 256 字节'; return false }
  dictionary.value = merged; error.value = ''; return true
}
const addWord = () => { if (!newWord.value) return; if (mergeWords([newWord.value])) { newWord.value = ''; wordSearch.value = ''; wordPage.value = Math.ceil(dictionary.value.length / wordPageSize) } }
const removeWord = (word: string) => { dictionary.value = dictionary.value.filter(value => value !== word); if (selectedWord.value === word) selectedWord.value = null }
const viewWord = async (word: string) => {
  selectedWord.value = word; wordEncodings.value = {}; encodingBusy.value = true; encodingError.value = ''
  await nextTick(); encodingClose.value?.focus()
  try { const values = await api.previewWeakPassword(word); if (selectedWord.value === word) wordEncodings.value = values }
  catch (e) { if (selectedWord.value === word) encodingError.value = e instanceof Error ? e.message : '编码生成失败' }
  finally { if (selectedWord.value === word) encodingBusy.value = false }
}
const importDictionary = async (e: Event) => { const input = e.target as HTMLInputElement; const file = input.files?.[0]; if (!file) return; try { if (file.size > 3 * 1024 * 1024) { error.value = '字典文件不能超过 3 MiB'; return }; mergeWords((await file.text()).replace(/^\uFEFF/, '').split(/\r?\n/)); wordPage.value = 1 } catch { error.value = '字典读取失败' } finally { input.value = '' } }
const save = async () => { saving.value = true; error.value = ''; notice.value = ''; try {
  const payload = { ...config, dictionary: [...dictionary.value], endpoints: endpoints.value.map(({ fields, ...rule }) => ({ ...rule, password_fields: fields.split(',').map(s => s.trim()).filter(Boolean) })) }
  Object.assign(config, await api.updateWeakPasswordConfig(payload)); dictionary.value = [...new Set(config.dictionary)]; notice.value = '已保存，所有站点共用此检测配置'
} catch (e) { error.value = e instanceof Error ? e.message : '保存失败' } finally { saving.value = false } }
const reload = async () => { try { Object.assign(config, await api.weakPasswordConfig()); dictionary.value = [...new Set(config.dictionary)]; endpoints.value = config.endpoints.map(({ password_fields, ...rule }) => ({ ...rule, fields: password_fields.join(', ') })); configLoaded.value = true } catch (e) { error.value = e instanceof Error ? e.message : '配置加载失败' } }
onMounted(reload)
defineExpose({ reload })
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
</style>
