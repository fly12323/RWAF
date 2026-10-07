<template>
  <button class="theme-toggle" type="button" :aria-label="theme === 'dark' ? '切换到浅色主题' : '切换到深色主题'" :aria-pressed="theme === 'dark'" :title="theme === 'dark' ? '切换浅色' : '切换深色'" @click="toggleTheme">
    <svg v-if="theme === 'dark'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/></svg>
    <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20.5 14A8.5 8.5 0 0110 3.5 8.5 8.5 0 1020.5 14z"/></svg>
    <span v-if="!compact">{{ theme === 'dark' ? '切换浅色' : '切换深色' }}</span>
  </button>
</template>
<script setup lang="ts">
import { useTheme } from '@/stores/theme'
defineProps<{ compact?: boolean }>()
const { theme, toggleTheme } = useTheme()
</script>
<style scoped>
.theme-toggle{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid var(--color-border);border-radius:6px;color:var(--color-text-secondary);background:var(--color-primary);width:100%;justify-content:center;font-size:14px}
.theme-toggle:hover{background:var(--color-secondary);color:var(--color-foreground)}svg{width:18px;height:18px;flex-shrink:0}
</style>
