<template>
 <section class="evidence">
  <h4>关联请求</h4><dl><div><dt>请求 ID</dt><dd>{{ log.request_id }}</dd></div><div><dt>请求</dt><dd>{{ log.method }} {{ log.uri }}</dd></div><div><dt>来源 IP</dt><dd>{{ log.client_ip }}</dd></div><div><dt>HTTP 状态</dt><dd>{{ log.response_code }}</dd></div><div><dt>处理动作 / 来源</dt><dd>{{ log.action === 'block' ? '拦截' : log.action === 'pass' ? '放行' : log.action }} / {{ decisionLabel(log) }}</dd></div><div><dt>规则评分</dt><dd>{{ scoreLabel(log) }} <small v-if="!log.rule_evaluated">{{ log.source_inferred ? '历史日志未完整记录规则执行过程。' : '未经过规则评分时，不使用分数解释处理结果。' }}</small></dd></div><div><dt>耗时</dt><dd>{{ log.duration }} ms</dd></div></dl>
  <p v-if="log.decision_reason" class="hint">{{ log.decision_reason }}</p>
	<p class="hint">执行模式：{{ protectionModeLabel(log.protection_mode) }} · 评分口径：{{ scoreBasisLabel(log) }}<br />策略配置版本：{{ log.policy_version || '历史日志未记录' }}</p>
	<ul v-if="log.detections?.length"><li v-for="(d, index) in log.detections" :key="index">{{ decisionLabels[d.source] || d.source }} · {{ detectionActionLabel(d.action) }} · {{ d.reason }}</li></ul>
  <h4>请求包</h4><pre>{{ log.method }} {{ log.uri }} HTTP/1.1
{{ headerLines(log.headers) }}

{{ decodeBody(log.body) }}</pre>
  <h4>响应包</h4><pre>HTTP {{ log.response_code }}
{{ headerLines(log.response_headers) }}

{{ decodeBody(log.response_body) }}</pre>
 </section>
</template>
<script setup lang="ts">
import type { RequestLog } from '@/types/api'
import { decisionLabel, scoreLabel, decodeBody, headerLines, protectionModeLabel, scoreBasisLabel, decisionLabels, detectionActionLabel } from '@/utils/request'
defineProps<{ log: RequestLog }>()
</script>
<style scoped>
.evidence{font-size:14px}h4{margin:20px 0 12px}dl{display:grid;grid-template-columns:1fr 1fr;gap:16px}dt,.hint,small{color:var(--color-text-secondary)}dd{margin-top:6px;overflow-wrap:anywhere}small{display:block;margin-top:6px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--color-secondary);padding:16px;border:1px solid var(--color-border);border-radius:6px;max-height:280px;overflow:auto;font-family:var(--font-mono);line-height:1.7}.hint{margin-top:16px}@media(max-width:600px){dl{grid-template-columns:1fr}}
</style>
