<template>
  <div class="protection-page">
    <div class="page-header">
      <div><h2>全局防护配置</h2><p>所有已启用站点共用这套设置。保存后对所有站点生效。</p></div>
      <button class="btn btn-secondary" :disabled="loading || saving" @click="activePage === 5 ? weakPanel?.reload() : load()">重新加载</button>
    </div>
    <p v-if="error" class="message error" role="alert">{{ error }}</p>
    <p v-if="notice" class="message" role="status">{{ notice }}</p>
    <p v-if="loading">正在加载全局配置…</p>
    <nav v-if="loaded && !loading" class="config-nav" aria-label="防护配置分组"><button v-for="(title,index) in pages" :key="title" type="button" :aria-current="activePage === index ? 'page' : undefined" :class="{ active: activePage === index }" @click="activePage = index">{{ title }}</button></nav>
    <form v-if="loaded && !loading" v-show="activePage < 5" novalidate @submit.prevent="save">
      <section class="config-card" v-show="activePage === 0">
        <h3>防护开关</h3>
        <div class="switches">
          <SettingSwitch v-for="toggle in toggles" :key="toggle.key" v-model="form[toggle.key]" :label="toggle.label" />
        </div>
        <p class="hint">关闭防护总开关后，站点仍转发请求并记录日志。请求体大小限制仍有效。</p>
		<label class="field-label">全局执行模式<select class="input" v-model="form.waf_mode"><option value="block">拦截模式</option><option value="monitor">观察模式</option></select></label>
		<p class="hint">观察模式记录黑名单、CC、爬虫与规则命中，不执行阻断、延迟或自动封禁。请求体限制与依赖故障错误仍有效；IP 白名单豁免行为不变。</p>
      </section>
      <section class="config-card" v-show="activePage === 1">
        <h3>规则引擎</h3><SettingSwitch v-model="form.rule_engine_enabled" label="规则引擎" />
        <div class="preset-grid">
          <div v-for="preset in presets" :key="preset.id" class="preset-card">
            <strong>{{ preset.name }}</strong><span>PL{{ preset.paranoia_level }} · 异常分阈值 {{ preset.score_threshold }}</span>
            <p class="hint">{{ preset.description }}</p>
            <button type="button" class="btn btn-secondary" @click="stagePreset(preset)">填入此预设</button>
          </div>
        </div>
        <p class="hint">预设只填入检测级别和阈值，保存后才生效。保留现有分类范围、禁用 ID、执行模式与各模块开关；分类或禁用 ID 仍会限制检测覆盖。三个预设均采用阈值 5，低误报指相同阈值下相对其他 PL；若当前阈值更高，应用预设可能增加拦截。提高阈值可能放过单条攻击。</p>
        <div class="fields">
          <label>检测级别<select class="input" v-model.number="form.paranoia_level"><option :value="1">PL1 · 基础检测</option><option :value="2">PL2 · 扩展检测</option><option :value="3">PL3 · 严格检测</option><option :value="4">PL4 · 极严格检测</option></select></label>
          <label>CRS 入站异常分阈值<input class="input" type="number" min="1" required v-model.number="form.score_threshold" /></label>
        </div>
        <p class="hint">阈值使用 CRS 运行时异常分，不再按命中规则的严重级别重复求和。自定义规则中的显式 deny 仍可直接拒绝请求；仅提高阈值不会关闭这些规则。历史阈值数值保留，请根据新评分含义评估。</p>
        <label class="field-label">启用的攻击规则分类</label>
        <div class="switches"><label v-for="category in categories" :key="category.id"><input type="checkbox" :value="category.id" v-model="form.enabled_rule_categories" />{{ category.label }}</label></div>
        <p class="hint">不选择分类时启用全部；基础协议规则始终保留。自定义规则内容在“规则管理”维护。</p>
        <label class="field-label">全局禁用规则 ID<input class="input" v-model="disabledIDs" placeholder="例如：942100, 941100" /></label>
      </section>
      <section class="config-card" id="cc" v-show="activePage === 2">
        <h3>CC 防护</h3><SettingSwitch v-model="form.cc_protection_enabled" label="CC 防护" />
        <div class="fields">
          <label>每站点 / IP 请求限额（次 / 60 秒）<input class="input" type="number" min="1" required v-model.number="form.cc_requests_per_minute" /></label>
          <label>超限动作<select class="input" v-model="form.cc_action"><option value="block">拒绝请求（429）</option><option value="delay">有界等待，重新检查限额</option></select></label>
          <label>最长等待（毫秒）<input class="input" type="number" min="0" max="30000" required v-model.number="form.cc_delay_ms" /></label>
        </div>
        <label class="field-label">URI 限流规则<textarea class="input" rows="4" v-model="form.cc_uri_limits" spellcheck="false" /></label>
        <p class="hint">例如 [{"uri":"/login","requests_per_minute":20,"action":"block"}]。使用首个匹配 URI 项；其 action 可为 block 或 delay，省略时继承全局动作。总限额与 URI 限额同时有效，按实际超限项执行动作。每站点最多等待 64 个请求，队列满或等待结束仍超限时返回 429。各站点计数独立。</p>
      </section>
      <section class="config-card" v-show="activePage === 3">
        <h3>爬虫检测</h3><SettingSwitch v-model="form.crawler_detection_enabled" label="爬虫检测" />
        <div class="fields"><label v-for="crawler in crawlerActions" :key="crawler.key">{{ crawler.label }}<select class="input" v-model="form[crawler.key]"><option value="log">只记录</option><option value="block">拦截（403）</option></select></label></div>
      </section>
      <section class="config-card" id="auto-block" v-show="activePage === 4">
        <h3>自动封禁</h3><SettingSwitch v-model="form.auto_block_enabled" label="自动封禁" />
        <div class="fields">
          <label>触发阈值（次）<input class="input" type="number" min="1" required v-model.number="form.auto_block_threshold" /></label>
          <label>统计窗口（秒）<input class="input" type="number" min="1" required v-model.number="form.auto_block_duration" /></label>
          <label>封禁时长（小时，0 表示永久）<input class="input" type="number" min="0" required v-model.number="form.auto_block_hours" /></label>
        </div>
        <p class="hint">仅按站点 / IP 统计规则引擎实际拦截次数，CC、爬虫命中及观察模式不触发自动封禁。达到阈值后加入全局黑名单；需开启黑名单防护才能拒绝后续请求。</p>
      </section>
      <p class="hint">切换分组会保留未保存的修改。保存会提交前五组防护配置；弱口令检测在对应页单独保存。</p><div class="save-row"><button class="btn btn-primary" type="submit" :disabled="saving">{{ saving ? '保存中…' : '保存全局配置' }}</button></div>
    </form>
    <WeakPasswordConfigPanel ref="weakPanel" v-if="loaded && !loading" v-show="activePage === 5" />

  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { api } from '@/api'
import SettingSwitch from '@/components/SettingSwitch.vue'
import { useRoute } from 'vue-router'
import WeakPasswordConfigPanel from '@/components/WeakPasswordConfigPanel.vue'
import type { ProtectionConfig } from '@/types/api'

type Preset = { id: string; name: string; paranoia_level: number; score_threshold: number; description: string }
const presets = ref<Preset[]>([])
const stagePreset = (preset: Preset) => {
  form.paranoia_level = preset.paranoia_level; form.score_threshold = preset.score_threshold
  notice.value = `已填入“${preset.name}”，尚未保存。分类范围和禁用 ID 保持当前选择；所有站点将在保存后使用这些设置。`
}

const form = reactive<ProtectionConfig>({ enabled: true, waf_mode: 'block', score_threshold: 15, paranoia_level: 1,
  enabled_rule_categories: [], disabled_rule_ids: [], rule_engine_enabled: true,
  crawler_detection_enabled: true, crawler_scanner_action: 'log', crawler_bot_action: 'log', crawler_crawler_action: 'log',
  cc_protection_enabled: true, cc_requests_per_minute: 100, cc_action: 'block', cc_delay_ms: 1000, cc_uri_limits: '[]',
  auto_block_enabled: true, auto_block_threshold: 10, auto_block_duration: 60, auto_block_hours: 24,
  ip_blacklist_enabled: true, ip_whitelist_enabled: true })
const loading = ref(true), loaded = ref(false), saving = ref(false), disabledIDs = ref(''), error = ref(''), notice = ref('')
const weakPanel = ref<InstanceType<typeof WeakPasswordConfigPanel> | null>(null)
const activePage = ref(useRoute().query.section === 'weak-password' ? 5 : useRoute().query.section === 'crawler' ? 3 : useRoute().query.section === 'rules' ? 1 : 0)
const pages = ['基础与名单', '规则引擎', 'CC 防护', '爬虫检测', '自动封禁', '弱口令检测']
const toggles = [
  { key: 'enabled', label: '防护总开关' },

   { key: 'ip_blacklist_enabled', label: 'IP 黑名单' },
  { key: 'ip_whitelist_enabled', label: 'IP 白名单' }
] as const
const crawlerActions = [ { key: 'crawler_scanner_action', label: '扫描器' }, { key: 'crawler_bot_action', label: '机器人' }, { key: 'crawler_crawler_action', label: '爬虫' } ] as const
const categories = [ { id: 'sqli', label: 'SQL 注入' }, { id: 'xss', label: 'XSS' }, { id: 'lfi', label: '本地文件包含' },
  { id: 'rfi', label: '远程文件包含' }, { id: 'rce', label: '命令执行' }, { id: 'php', label: 'PHP' },
  { id: 'nodejs', label: '通用应用攻击（含 Node.js）' }, { id: 'java', label: 'Java' }, { id: 'scanner', label: '扫描器' },
  { id: 'session', label: '会话攻击' }, { id: 'custom', label: '自定义规则' } ]
const load = async () => {
  loading.value = true; error.value = ''; notice.value = ''
  try { Object.assign(form, await api.protectionConfig()); form.paranoia_level ||= 1; disabledIDs.value = form.disabled_rule_ids.join(', '); presets.value = await api.rulePresets(); loaded.value = true }
  catch (e) { loaded.value = false; error.value = e instanceof Error ? e.message : '配置加载失败' }
  finally { loading.value = false }
}
const save = async () => {
  saving.value = true; error.value = ''; notice.value = ''
  try {
    const limits = [{key:'score_threshold',min:1,max:2147483647,page:1},{key:'cc_requests_per_minute',min:1,max:2147483647,page:2},{key:'cc_delay_ms',min:0,max:30000,page:2},{key:'auto_block_threshold',min:1,max:2147483647,page:4},{key:'auto_block_duration',min:1,max:2147483647,page:4},{key:'auto_block_hours',min:0,max:2147483647,page:4}] as const
    for (const limit of limits) { const value = form[limit.key]; if (!Number.isInteger(value) || value < limit.min || value > limit.max) { activePage.value = limit.page; throw new Error('请检查当前分组的数值范围') } }
    try { JSON.parse(form.cc_uri_limits) } catch { activePage.value = 2; throw new Error('URI 限流规则需要有效的 JSON') }
    form.disabled_rule_ids = disabledIDs.value.split(/[\s,，]+/).filter(Boolean)
    Object.assign(form, await api.updateProtectionConfig(form))
    notice.value = '配置已保存，所有已启用站点使用这套全局防护设置。'
  } catch (e) { error.value = e instanceof Error ? e.message : '保存失败' }
  finally { saving.value = false }
}
onMounted(load)
</script>

<style scoped>
.preset-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:12px; margin:16px 0; }
.preset-card { display:flex; flex-direction:column; align-items:flex-start; gap:8px; padding:16px; border:1px solid var(--color-border); border-radius:var(--radius-md); }
.preset-card span { font-size:var(--text-sm); color:var(--color-text-muted); }
.protection-page { display: flex; flex-direction: column; gap: var(--spacing-md); }
.page-header { display: flex; justify-content: space-between; align-items: center; gap: var(--spacing-md); }
.page-header h2 { font-size: var(--text-lg); margin-bottom: 6px; }
.page-header p, .hint { color: var(--color-text-muted); font-size: var(--text-sm); line-height: 1.7; }
form { display: flex; flex-direction: column; gap: var(--spacing-md); }
.config-card { padding: var(--spacing-lg); border: 1px solid var(--color-border); border-radius: var(--radius-lg); background: var(--color-muted); }
h3 { margin-bottom: var(--spacing-md); }
.fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: var(--spacing-md); }
.fields label, .field-label { display: flex; flex-direction: column; gap: 8px; font-size: var(--text-sm); }
.field-label { margin-top: var(--spacing-md); }
.switches { display: flex; flex-wrap: wrap; gap: 18px; padding: 8px 0; }
.switches label { display: flex; gap: 8px; align-items: center; font-size: var(--text-sm); }
.hint { margin-top: 12px; }
.message { padding: 12px; border: 1px solid var(--color-border); border-radius: var(--radius-md); }
.error { color: var(--color-danger); }
.save-row { padding-bottom: var(--spacing-lg); }
@media (max-width: 600px) { .page-header { flex-direction: column; align-items: flex-start; } }
.config-nav{display:flex;flex-wrap:wrap;gap:8px;border-bottom:1px solid var(--color-border)}.config-nav button{padding:12px 16px;color:var(--color-text-secondary);border-bottom:2px solid transparent}.config-nav button.active{color:var(--color-accent);border-bottom-color:var(--color-accent)}.section-toggle{display:flex;gap:8px;align-items:center;margin-bottom:20px;font-size:14px}
.config-nav{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;border:0}.config-nav button{border:1px solid var(--color-border);border-radius:6px;padding:14px;text-align:left;background:var(--color-primary)}.config-nav button.active{border-color:var(--color-accent);color:var(--color-accent);background:var(--color-secondary)}
</style>
