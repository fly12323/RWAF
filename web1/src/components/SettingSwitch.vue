<template>
  <div class="setting-switch">
    <span class="switch-label">{{ label }}</span>
    <button type="button" role="switch" :aria-label="label" :aria-checked="modelValue" :disabled="disabled" :class="{ enabled: modelValue }" @click="$emit('update:modelValue', !modelValue)"><span /></button>
    <span class="switch-state" :class="{ enabled: modelValue }">{{ modelValue ? '已开启' : '已关闭' }}</span>
  </div>
</template>
<script setup lang="ts">
defineProps<{ modelValue: boolean; label: string; disabled?: boolean }>()
defineEmits<{ 'update:modelValue': [value: boolean] }>()
</script>
<style scoped>
.setting-switch{display:flex;align-items:center;gap:12px;padding:12px 0;font-size:14px}.switch-label{min-width:120px;color:var(--color-foreground)}button{width:48px;height:28px;border:1px solid var(--color-text-muted);border-radius:16px;background:var(--color-text-muted);padding:3px;cursor:pointer;flex-shrink:0}button>span{display:block;width:20px;height:20px;border-radius:50%;background:#fff;box-shadow:0 1px 3px #0003;transition:transform .15s}button.enabled{background:var(--color-accent);border-color:var(--color-accent)}button.enabled>span{transform:translateX(20px)}button:disabled{opacity:.5;cursor:default}.switch-state{color:var(--color-text-muted);font-size:13px}.switch-state.enabled{color:var(--color-accent)}@media(prefers-reduced-motion:reduce){button>span{transition:none}}
</style>
