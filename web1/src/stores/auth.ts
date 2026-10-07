import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { api } from '../api'
import { bindHttpHooks } from '../api/http'
import type { UserInfo } from '../types/api'

const STORAGE_KEY = 'waf_console_auth'

// Role constants
export const Role = {
  Admin: 'admin',
  Operator: 'operator',
  Auditor: 'auditor'
} as const

// Role name mapping
export const RoleNames: Record<string, string> = {
  admin: '管理员',
  operator: '操作员',
  auditor: '审计员'
}

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string>('')
  const user = ref<UserInfo | null>(null)
  const status = ref<string>('')

  const setStatus = (msg: string) => {
    status.value = msg
  }

  const loadLocal = () => {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return
    try {
      const parsed = JSON.parse(raw)
      token.value = parsed.token || ''
      user.value = parsed.user || null
    } catch {
      localStorage.removeItem(STORAGE_KEY)
    }
  }

  const saveLocal = () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ token: token.value, user: user.value }))
  }

  const clear = () => {
    token.value = ''
    user.value = null
    localStorage.removeItem(STORAGE_KEY)
  }

  const login = async (username: string, password: string) => {
    const data = await api.login(username, password)
    token.value = data.token
    user.value = data.user
    saveLocal()
    setStatus('登录成功')
  }

  const fetchMe = async () => {
    if (!token.value) return
    try {
      const me = await api.me()
      user.value = me
      saveLocal()
    } catch {
      clear()
    }
  }

  const logout = async () => {
    try {
      await api.logout()
    } catch {
      // ignore
    }
    clear()
  }

  const onAuthFailed = () => {
    clear()
    window.location.href = '/login'
  }

  bindHttpHooks(() => token.value, onAuthFailed)

  // Role check methods
  const isAdmin = computed(() => user.value?.role === Role.Admin)
  const isOperator = computed(() => user.value?.role === Role.Operator)
  const isAuditor = computed(() => user.value?.role === Role.Auditor)

  // Permission check methods
  const canManageUsers = computed(() => isAdmin.value)
  const canWrite = computed(() => isAdmin.value || isOperator.value)
  const canViewLogs = computed(() => isAdmin.value || isOperator.value || isAuditor.value)
  const canViewBigScreen = computed(() => isAdmin.value || isOperator.value || isAuditor.value)

  return {
    token,
    user,
    status,
    setStatus,
    loadLocal,
    saveLocal,
    clear,
    login,
    fetchMe,
    logout,
    onAuthFailed,
    // Roles
    Role,
    RoleNames,
    isAdmin,
    isOperator,
    isAuditor,
    canManageUsers,
    canWrite,
    canViewLogs,
    canViewBigScreen
  }
})
