import { ref } from 'vue'

type Theme = 'light' | 'dark'
const storageKey = 'waf-console-theme'
const theme = ref<Theme>('light')

export function initializeTheme() {
  try { theme.value = localStorage.getItem(storageKey) === 'dark' ? 'dark' : 'light' } catch { theme.value = 'light' }
  document.documentElement.dataset.theme = theme.value
}

export function useTheme() {
  const toggleTheme = () => {
    theme.value = theme.value === 'dark' ? 'light' : 'dark'
    document.documentElement.dataset.theme = theme.value
    try { localStorage.setItem(storageKey, theme.value) } catch { /* Theme still works without storage. */ }
  }
  return { theme, toggleTheme }
}
