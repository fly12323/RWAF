<template>
  <div class="layout">
    <!-- Sidebar -->
    <aside class="sidebar" :class="{ collapsed: sidebarCollapsed }">
      <div class="sidebar-header">
        <div class="logo">
          <svg class="logo-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M9 12l2 2 4-4"/>
          </svg>
          <span v-if="!sidebarCollapsed" class="logo-text">RWAF</span>
        </div>
        <button class="collapse-btn" :aria-label="sidebarCollapsed ? '展开导航' : '收起导航'" @click="toggleSidebar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path v-if="sidebarCollapsed" d="M9 18l6-6-6-6"/>
            <path v-else d="M15 18l-6-6 6-6"/>
          </svg>
        </button>
      </div>

      <nav class="sidebar-nav">
        <template v-for="group in navGroups" :key="group.label">
        <div v-if="!sidebarCollapsed" class="nav-group-label">{{ group.label }}</div>
        <router-link
          v-for="item in group.items"
          :key="item.path"
          :to="item.path"
          :aria-label="item.label"
          :title="sidebarCollapsed ? item.label : undefined"
          class="nav-item"
          :class="{ active: currentRoute === item.path }"
        >
          <component :is="item.icon" class="nav-icon" />
          <span v-if="!sidebarCollapsed" class="nav-text">{{ item.label }}</span>
        </router-link>
        </template>
      </nav>

      <div class="sidebar-theme"><ThemeToggle :compact="sidebarCollapsed" /></div>
      <div class="sidebar-footer">
        <div class="user-info" v-if="!sidebarCollapsed">
          <div class="user-avatar">{{ userAvatar }}</div>
          <div class="user-details">
            <span class="user-name">{{ authStore.user?.username }}</span>
            <span class="user-role">{{ roleName }}</span>
          </div>
        </div>
        <button class="logout-btn" aria-label="退出登录" title="退出登录" @click="handleLogout">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/>
            <polyline points="16,17 21,12 16,7"/>
            <line x1="21" y1="12" x2="9" y2="12"/>
          </svg>
        </button>
      </div>
    </aside>

    <!-- Main Content -->
    <div class="main-wrapper">
      <!-- Top Header -->
      <header class="top-header">
        <div class="header-left">
          <h1 class="page-title">{{ pageTitle }}</h1>
        </div>
        <div class="header-right">
          <div class="header-time">{{ currentTime }}</div>
          <div class="waf-status" :class="{ online: wafOnline }">
            <span class="status-dot"></span>
            <span>{{ wafOnline ? '服务运行正常' : '服务连接异常' }}</span>
          </div>
        </div>
      </header>

      <!-- Page Content -->
      <main class="main-content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, h } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore, RoleNames } from '@/stores/auth'
import { api } from '@/api'
import ThemeToggle from '@/components/ThemeToggle.vue'

// Icons as render functions
const IconOverview = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('rect', { x: '3', y: '3', width: '7', height: '7' }),
  h('rect', { x: '14', y: '3', width: '7', height: '7' }),
  h('rect', { x: '14', y: '14', width: '7', height: '7' }),
  h('rect', { x: '3', y: '14', width: '7', height: '7' })
])

const IconLogs = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('path', { d: 'M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z' }),
  h('polyline', { points: '14,2 14,8 20,8' }),
  h('line', { x1: '16', y1: '13', x2: '8', y2: '13' }),
  h('line', { x1: '16', y1: '17', x2: '8', y2: '17' })
])

const IconSites = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('circle', { cx: '12', cy: '12', r: '10' }),
  h('line', { x1: '2', y1: '12', x2: '22', y2: '12' }),
  h('path', { d: 'M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z' })
])

const IconRules = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' })
])

const IconIP = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('circle', { cx: '12', cy: '12', r: '10' }),
  h('line', { x1: '12', y1: '8', x2: '12', y2: '12' }),
  h('line', { x1: '12', y1: '16', x2: '12.01', y2: '16' })
])

const IconCC = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('path', { d: 'M13 2L3 14h9l-1 8 10-12h-9l1-8z' })
])

const IconBot = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('rect', { x: '3', y: '11', width: '18', height: '10', rx: '2' }),
  h('circle', { cx: '12', cy: '5', r: '2' }),
  h('path', { d: 'M12 7v4' }),
  h('line', { x1: '8', y1: '16', x2: '8', y2: '16' }),
  h('line', { x1: '16', y1: '16', x2: '16', y2: '16' })
])

const IconUsers = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('path', { d: 'M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2' }),
  h('circle', { cx: '9', cy: '7', r: '4' }),
  h('path', { d: 'M23 21v-2a4 4 0 00-3-3.87' }),
  h('path', { d: 'M16 3.13a4 4 0 010 7.75' })
])

const IconOpLogs = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('path', { d: 'M12 20h9' }),
  h('path', { d: 'M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z' })
])

const IconBigScreen = () => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
  h('rect', { x: '2', y: '3', width: '20', height: '14', rx: '2', ry: '2' }),
  h('line', { x1: '8', y1: '21', x2: '16', y2: '21' }),
  h('line', { x1: '12', y1: '17', x2: '12', y2: '21' })
])

interface NavItem {
  path: string
  label: string
  icon: () => ReturnType<typeof h>
  requiresAuth?: boolean
  roles?: string[]
}

const navItems: NavItem[] = [
  { path: '/weak-password', label: '弱口令检测', icon: IconUsers, requiresAuth: true },
  { path: '/monitor', label: '运行监控与告警', icon: IconOverview, requiresAuth: true },
  { path: '/overview', label: '安全概览', icon: IconOverview },
  { path: '/logs', label: '请求日志', icon: IconLogs, requiresAuth: true },
  { path: '/sites', label: '站点管理', icon: IconSites, requiresAuth: true },
  { path: '/rules', label: '规则管理', icon: IconRules, requiresAuth: true },
  { path: '/ip-security', label: 'IP安全', icon: IconIP, requiresAuth: true },
  { path: '/protection', label: '全局防护', icon: IconCC, requiresAuth: true, roles: ['admin', 'operator'] },
  { path: '/crawler', label: '爬虫检测', icon: IconBot, requiresAuth: true },
  { path: '/users', label: '用户管理', icon: IconUsers, requiresAuth: true, roles: ['admin'] },
  { path: '/operation-logs', label: '操作日志', icon: IconOpLogs, requiresAuth: true, roles: ['admin'] },
  { path: '/big-screen', label: '大屏展示', icon: IconBigScreen, requiresAuth: true }
]

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

const sidebarCollapsed = ref(false)
const currentTime = ref('')
const wafOnline = ref(true)

const currentRoute = computed(() => route.path)

const pageTitle = computed(() => {
  const item = navItems.find(i => i.path === currentRoute.value)
  return item?.label || 'RWAF'
})

const userAvatar = computed(() => {
  return authStore.user?.username?.charAt(0).toUpperCase() || 'A'
})

const roleName = computed(() => {
  const role = authStore.user?.role
  return role ? RoleNames[role] || role : '用户'
})

const visibleNavItems = computed(() => {
  return navItems.filter(item => {
    if (!item.requiresAuth) return true
    if (item.roles && item.roles.length > 0) {
      return item.roles.includes(authStore.user?.role || '')
    }
    return true
  })
})

const navGroups = computed(() => [
  { label: '概览', paths: ['/overview'] },
  { label: '安全事件', paths: ['/logs', '/weak-password', '/crawler'] },
  { label: '站点与防护', paths: ['/sites', '/protection', '/rules', '/ip-security'] },
  { label: '运行与管理', paths: ['/monitor', '/users', '/operation-logs', '/big-screen'] }
].map(group => ({ label: group.label, items: group.paths.map(path => visibleNavItems.value.find(item => item.path === path)).filter((item): item is NavItem => !!item) })).filter(group => group.items.length))

let timeInterval: number
let wafCheckInterval: number

const updateTime = () => {
  const now = new Date()
  currentTime.value = now.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  })
}

const checkWafStatus = async () => {
  try {
    await api.wafStatus()
    wafOnline.value = true
  } catch {
    wafOnline.value = false
  }
}

const toggleSidebar = () => {
  sidebarCollapsed.value = !sidebarCollapsed.value
}

const handleLogout = async () => {
  await authStore.logout()
  router.push('/login')
}

onMounted(() => {
  updateTime()
  timeInterval = window.setInterval(updateTime, 1000)
  checkWafStatus()
  wafCheckInterval = window.setInterval(checkWafStatus, 30000)
})

onUnmounted(() => {
  clearInterval(timeInterval)
  clearInterval(wafCheckInterval)
})
</script>

<style scoped>
.layout {
  display: flex;
  width: 100%;
  height: 100vh;
  background-color: var(--color-background);
}

.sidebar {
  width: 224px;
  height: 100vh;
  background: var(--color-primary);
  border-right: 1px solid var(--color-border);
  display: flex;
  flex-direction: column;
  transition: width var(--transition-normal);
  position: relative;
  z-index: var(--z-fixed);
}

.sidebar.collapsed {
  width: 64px;
}

.sidebar-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md);
  border-bottom: 1px solid var(--color-border);
  height: 64px;
}

.logo {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  overflow: hidden;
}

.logo-icon {
  width: 28px;
  height: 28px;
  color: var(--color-accent);
  flex-shrink: 0;
}

.logo-text {
  font-family: var(--font-sans);
  font-size: var(--text-lg);
  font-weight: 600;
  color: var(--color-foreground);
  white-space: nowrap;
}

.collapse-btn {
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--color-text-secondary);
  transition: color var(--transition-fast);
  flex-shrink: 0;
}

.collapse-btn:hover {
  color: var(--color-accent);
}

.collapse-btn svg {
  width: 16px;
  height: 16px;
}

.sidebar-nav {
  flex: 1;
  padding: var(--spacing-sm);
  overflow-y: auto;
  overflow-x: hidden;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  margin-bottom: 4px;
  border-radius: var(--radius-md);
  color: var(--color-text-secondary);
  transition: all var(--transition-fast);
  text-decoration: none;
  white-space: nowrap;
  overflow: hidden;
}

.nav-item:hover {
  background: var(--color-secondary);
  color: var(--color-foreground);
}

.nav-item.active {
  background: var(--color-active-bg);
  color: var(--color-accent);
  font-weight: 600;
}

.nav-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.nav-text {
  font-size: var(--text-sm);
}

.sidebar-footer {
  padding: var(--spacing-md);
  border-top: 1px solid var(--color-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--spacing-sm);
}

.user-info {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  overflow: hidden;
}

.user-avatar {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background: var(--color-accent);
  color: var(--color-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  flex-shrink: 0;
}

.user-details {
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.user-name {
  font-size: var(--text-sm);
  font-weight: 500;
  white-space: nowrap;
}

.user-role {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

.logout-btn {
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--color-text-secondary);
  border-radius: var(--radius-md);
  transition: all var(--transition-fast);
}

.logout-btn:hover {
  background: rgba(239, 68, 68, 0.1);
  color: var(--color-danger);
}

.logout-btn svg {
  width: 18px;
  height: 18px;
}

.main-wrapper {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.top-header {
  height: 64px;
  padding: 0 var(--spacing-lg);
  background: var(--color-primary);
  border-bottom: 1px solid var(--color-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.header-left {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.page-title {
  font-size: var(--text-xl);
  font-weight: 600;
  font-family: var(--font-sans);
}

.header-right {
  display: flex;
  align-items: center;
  gap: var(--spacing-xl);
}

.header-time {
  font-family: var(--font-sans);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
}

.waf-status {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--text-sm);
  color: var(--color-text-muted);
}

.waf-status.online {
  color: var(--color-accent);
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--color-text-muted);
  transition: background var(--transition-fast);
}

.waf-status.online .status-dot {
  background: var(--color-accent);

}

@keyframes pulse-glow {
  0%, 100% { box-shadow: 0 0 5px var(--color-accent-glow); }
  50% { box-shadow: 0 0 15px var(--color-accent-glow); }
}

.main-content {
  flex: 1;
  padding: var(--spacing-lg);
  overflow-y: auto;
}
.sidebar-theme{padding:12px 16px 16px}
.nav-group-label{font-size:12px;color:var(--color-text-muted);padding:14px 16px 8px}
.sidebar-header{padding:16px 12px;flex-shrink:0}.logo-text{font-size:17px}.top-header{flex-shrink:0}.main-wrapper{min-width:0}.main-content{padding:28px 32px}.user-avatar{color:var(--color-on-primary);border-radius:8px}.page-title{font-size:18px}.sidebar-footer{flex-shrink:0}.sidebar-theme{flex-shrink:0}
@media(max-width:900px){.sidebar{width:200px}.main-content{padding:20px}.header-time{display:none}}
@media(max-width:600px){.sidebar{width:64px}.sidebar .logo-text,.sidebar .nav-text,.sidebar .nav-group-label,.sidebar .user-info,.sidebar .collapse-btn{display:none}.sidebar-header{justify-content:center;padding:8px}.sidebar-nav{padding:6px}.nav-item{padding:12px;justify-content:center}.sidebar-theme{padding:10px 6px}.sidebar-theme :deep(.theme-toggle span){display:none}.sidebar-theme :deep(.theme-toggle){padding:10px}.sidebar-footer{padding:10px;justify-content:center}.top-header{padding:0 16px}.main-content{padding:16px}.waf-status{font-size:12px}.header-right{gap:8px}.page-title{font-size:16px}}
</style>
