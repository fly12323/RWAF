import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const routes: RouteRecordRaw[] = [
  { path: '/change-password', component: () => import('@/views/ChangePasswordView.vue'), meta: { requiresAuth: true } },
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/LoginView.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/',
    component: () => import('@/layouts/MainLayout.vue'),
    redirect: '/overview',
    meta: { requiresAuth: true },
    children: [
      { path: 'weak-password', component: () => import('@/views/modules/WeakPasswordView.vue'), meta: { title: '弱口令检测' } },
      { path: 'monitor', component: () => import('@/views/modules/MonitorView.vue'), meta: { title: '运行监控与告警' } },
      {
        path: 'overview',
        name: 'Overview',
        component: () => import('@/views/modules/OverviewView.vue'),
        meta: { title: '总览' }
      },
      {
        path: 'logs',
        name: 'Logs',
        component: () => import('@/views/modules/LogsView.vue'),
        meta: { title: '攻击日志' }
      },
      {
        path: 'sites',
        name: 'Sites',
        component: () => import('@/views/modules/SitesView.vue'),
        meta: { title: '站点管理' }
      },
      {
        path: 'protection',
        name: 'Protection',
        component: () => import('@/views/modules/ProtectionView.vue'),
        meta: { title: '全局防护', roles: ['admin', 'operator'] }
      },
      {
        path: 'rules',
        name: 'Rules',
        component: () => import('@/views/modules/RulesView.vue'),
        meta: { title: '规则管理' }
      },
      {
        path: 'ip-security',
        name: 'IPSecurity',
        component: () => import('@/views/modules/IPSecurityView.vue'),
        meta: { title: 'IP安全' }
      },
      {
        path: 'cc-protection',
        redirect: '/protection'
      },
      {
        path: 'crawler',
        name: 'Crawler',
        component: () => import('@/views/modules/CrawlerView.vue'),
        meta: { title: '爬虫检测' }
      },
      {
        path: 'crawler-logs',
        name: 'CrawlerLogs',
        component: () => import('@/views/modules/CrawlerLogsView.vue'),
        meta: { title: '爬虫日志' }
      },
      {
        path: 'users',
        name: 'Users',
        component: () => import('@/views/modules/UsersView.vue'),
        meta: { title: '用户管理', roles: ['admin'] }
      },
      {
        path: 'operation-logs',
        name: 'OperationLogs',
        component: () => import('@/views/modules/OperationLogsView.vue'),
        meta: { title: '操作日志', roles: ['admin'] }
      },
      {
        path: 'big-screen',
        name: 'BigScreen',
        component: () => import('@/views/modules/BigScreenView.vue'),
        meta: { title: '大屏展示' }
      }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Navigation guard
router.beforeEach((to, _from, next) => {
  const authStore = useAuthStore()

  // Load auth state from localStorage on first load
  if (!authStore.token) {
    authStore.loadLocal()
  }

  const requiresAuth = to.matched.some(record => record.meta.requiresAuth !== false)

  if (requiresAuth && !authStore.token) {
    next('/login')
  } else if (authStore.token && authStore.user?.must_change_password && to.path !== '/change-password') {
    next('/change-password')
  } else if (to.path === '/login' && authStore.token) {
    next('/overview')
  } else {
    // Check role-based access
    const requiredRoles = to.matched
      .flatMap(record => record.meta?.roles as string[] | undefined)
      .filter(Boolean) as string[]

    if (requiredRoles.length > 0 && !requiredRoles.includes(authStore.user?.role || '')) {
      next('/overview')
    } else {
      next()
    }
  }
})

export default router
