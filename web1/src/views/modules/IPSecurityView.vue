<template>
  <div class="ip-security-page">
    <!-- Tabs -->
    <div class="tabs-bar">
      <button
        class="tab-btn"
        :class="{ active: activeTab === 'blacklist' }"
        @click="activeTab = 'blacklist'"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
        </svg>
        IP 黑名单
        <span class="tab-count">{{ blacklistTotal || 0 }}</span>
      </button>
      <button
        class="tab-btn"
        :class="{ active: activeTab === 'whitelist' }"
        @click="activeTab = 'whitelist'"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
          <polyline points="22,4 12,14.01 9,11.01"/>
        </svg>
        IP 白名单
        <span class="tab-count">{{ whitelistTotal || 0 }}</span>
      </button>
      <button
        class="tab-btn"
        :class="{ active: activeTab === 'auto-block' }"
        @click="activeTab = 'auto-block'"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>
        自动封禁配置
      </button>
    </div>

    <!-- Blacklist Tab -->
    <div v-if="activeTab === 'blacklist'" class="tab-content">
      <!-- Stats Cards -->
      <div class="stats-row">
        <div class="stat-item">
          <span class="stat-value">{{ blacklistTotal }}</span>
          <span class="stat-label">总数</span>
        </div>
        <div class="stat-item success">
          <span class="stat-value">{{ blacklistEnabledCount }}</span>
          <span class="stat-label">启用中</span>
        </div>
        <div class="stat-item danger">
          <span class="stat-value">{{ blacklistDisabledCount }}</span>
          <span class="stat-label">已停用</span>
        </div>
      </div>

      <div class="page-header">
        <div class="header-left">
          <input
            v-model="blacklistFilters.ip"
            type="text"
            class="input search-input"
            placeholder="搜索 IP 地址"
            @keyup.enter="fetchBlacklist"
          />
          <button class="btn btn-secondary" @click="fetchBlacklist">搜索</button>
        </div>
        <div class="header-right">
          <button class="btn btn-danger" @click="cleanExpired">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3,6 5,6 21,6"/>
              <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
            </svg>
            清理过期
          </button>
          <button class="btn btn-primary" @click="openBlacklistModal">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="12" y1="5" x2="12" y2="19"/>
              <line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
            添加黑名单
          </button>
        </div>
      </div>

      <div class="table-card">
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th>IP 地址</th>
                <th>原因</th>
                <th>状态</th>
                <th>过期时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in blacklist" :key="item.id">
                <td class="cell-ip">{{ item.ip }}</td>
                <td class="cell-reason">{{ item.reason || '-' }}</td>
                <td>
                  <span
                    class="toggle-badge"
                    :class="{ active: item.status === 1, expired: isExpired(item.expire_at) }"
                    @click="toggleBlacklist(item)"
                  >
                    {{ isExpired(item.expire_at) ? '已过期' : (item.status === 1 ? '生效中' : '已禁用') }}
                  </span>
                </td>
                <td class="cell-time">{{ formatTime(item.expire_at) }}</td>
                <td class="cell-actions">
                  <button
                    class="action-btn"
                    :class="item.status === 1 ? 'danger' : 'success'"
                    :disabled="isExpired(item.expire_at) || blacklistTogglingId === item.id"
                    @click="toggleBlacklist(item)"
                  >
                    {{ item.status === 1 ? '停用' : '启用' }}
                  </button>
                  <button class="action-btn danger" @click="deleteBlacklist(item)">删除</button>
                </td>
              </tr>
              <tr v-if="blacklist.length === 0">
                <td colspan="5" class="empty-cell">
                  <div class="empty-state">暂无黑名单数据</div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="pagination">
          <div class="pagination-info">共 {{ blacklistTotal }} 条</div>
          <div class="pagination-controls">
            <button class="page-btn" :disabled="blacklistPage <= 1" @click="blacklistPage = 1; fetchBlacklist()">首页</button>
            <button class="page-btn" :disabled="blacklistPage <= 1" @click="blacklistPage--; fetchBlacklist()">上一页</button>
            <button class="page-btn" :disabled="blacklistPage >= blacklistTotalPages" @click="blacklistPage++; fetchBlacklist()">下一页</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Whitelist Tab -->
    <div v-if="activeTab === 'whitelist'" class="tab-content">
      <!-- Stats Cards -->
      <div class="stats-row">
        <div class="stat-item">
          <span class="stat-value">{{ whitelistTotal }}</span>
          <span class="stat-label">总数</span>
        </div>
        <div class="stat-item success">
          <span class="stat-value">{{ whitelistEnabledCount }}</span>
          <span class="stat-label">启用中</span>
        </div>
        <div class="stat-item danger">
          <span class="stat-value">{{ whitelistDisabledCount }}</span>
          <span class="stat-label">已停用</span>
        </div>
      </div>

      <div class="page-header">
        <div class="header-left">
          <input
            v-model="whitelistFilters.ip"
            type="text"
            class="input search-input"
            placeholder="搜索 IP 地址"
            @keyup.enter="fetchWhitelist"
          />
          <button class="btn btn-secondary" @click="fetchWhitelist">搜索</button>
        </div>
        <div class="header-right">
          <button class="btn btn-primary" @click="openWhitelistModal">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="12" y1="5" x2="12" y2="19"/>
              <line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
            添加白名单
          </button>
        </div>
      </div>

      <div class="table-card">
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th>IP 地址</th>
                <th>原因</th>
                <th>状态</th>
                <th>过期时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in whitelist" :key="item.id">
                <td class="cell-ip">{{ item.ip }}</td>
                <td class="cell-reason">{{ item.reason || '-' }}</td>
                <td>
                  <span
                    class="toggle-badge"
                    :class="{ active: item.status === 1, expired: isExpired(item.expire_at) }"
                    @click="toggleWhitelist(item)"
                  >
                    {{ isExpired(item.expire_at) ? '已过期' : (item.status === 1 ? '生效中' : '已禁用') }}
                  </span>
                </td>
                <td class="cell-time">{{ formatTime(item.expire_at) }}</td>
                <td class="cell-actions">
                  <button
                    class="action-btn"
                    :class="item.status === 1 ? 'danger' : 'success'"
                    :disabled="isExpired(item.expire_at) || whitelistTogglingId === item.id"
                    @click="toggleWhitelist(item)"
                  >
                    {{ item.status === 1 ? '停用' : '启用' }}
                  </button>
                  <button class="action-btn danger" @click="deleteWhitelist(item)">删除</button>
                </td>
              </tr>
              <tr v-if="whitelist.length === 0">
                <td colspan="5" class="empty-cell">
                  <div class="empty-state">暂无白名单数据</div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="pagination">
          <div class="pagination-info">共 {{ whitelistTotal }} 条</div>
          <div class="pagination-controls">
            <button class="page-btn" :disabled="whitelistPage <= 1" @click="whitelistPage = 1; fetchWhitelist()">首页</button>
            <button class="page-btn" :disabled="whitelistPage <= 1" @click="whitelistPage--; fetchWhitelist()">上一页</button>
            <button class="page-btn" :disabled="whitelistPage >= whitelistTotalPages" @click="whitelistPage++; fetchWhitelist()">下一页</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Auto-Block Config Tab -->
    <div v-if="activeTab === 'auto-block'" class="tab-content">
      <div class="config-card">
        <h3>自动封禁设置</h3>
        <div class="config-form">
          <div class="config-item toggle-item">
            <div class="config-info">
              <span class="config-title">启用自动封禁</span>
              <span class="config-desc">当检测到异常访问时自动封禁 IP</span>
            </div>
            <label class="toggle-switch">
              <input type="checkbox" v-model="autoBlockConfig.auto_block_enabled" />
              <span class="toggle-slider"></span>
            </label>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label class="label">封禁阈值（次/小时）</label>
              <input
                v-model.number="autoBlockConfig.auto_block_threshold"
                type="number"
                class="input"
                placeholder="50"
                min="1"
              />
              <span class="hint">触发封禁的最小攻击次数</span>
            </div>
            <div class="form-group">
              <label class="label">封禁时长（小时）</label>
              <input
                v-model.number="autoBlockConfig.auto_block_duration"
                type="number"
                class="input"
                placeholder="24"
                min="1"
              />
              <span class="hint">封禁持续时间</span>
            </div>
          </div>

          <div class="form-group">
            <label class="label">IP 列表模式</label>
            <select v-model="autoBlockConfig.ip_list_mode" class="input select-input">
              <option value="block_first">黑名单优先（先检查白名单后检查黑名单）</option>
              <option value="whitelist_first">白名单优先（先检查白名单后检查黑名单）</option>
              <option value="blacklist_only">仅使用黑名单</option>
            </select>
          </div>

          <div class="form-actions">
            <button class="btn btn-primary" @click="saveAutoBlockConfig" :disabled="submitting">
              {{ submitting ? '保存中...' : '保存配置' }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Add Blacklist Modal -->
    <div class="modal-overlay" v-if="showBlacklistModal" @click="showBlacklistModal = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>添加黑名单</h3>
          <button class="close-btn" @click="showBlacklistModal = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <label class="label">IP 地址 *</label>
            <input
              v-model="blacklistForm.ip"
              type="text"
              class="input"
              placeholder="192.168.1.100 或 10.0.0.0/24"
              required
            />
            <span class="hint">支持单个IP或CIDR网段</span>
          </div>
          <div class="form-group">
            <label class="label">原因</label>
            <input
              v-model="blacklistForm.reason"
              type="text"
              class="input"
              placeholder="封禁原因（可选）"
            />
          </div>
          <div class="form-group">
            <label class="label">过期时间</label>
            <input
              v-model="blacklistForm.expire_at"
              type="datetime-local"
              class="input"
            />
            <span class="hint">留空表示永久封禁</span>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="showBlacklistModal = false">取消</button>
          <button class="btn btn-primary" @click="addBlacklist" :disabled="submitting">添加</button>
        </div>
      </div>
    </div>

    <!-- Add Whitelist Modal -->
    <div class="modal-overlay" v-if="showWhitelistModal" @click="showWhitelistModal = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>添加白名单</h3>
          <button class="close-btn" @click="showWhitelistModal = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <label class="label">IP 地址 *</label>
            <input
              v-model="whitelistForm.ip"
              type="text"
              class="input"
              placeholder="192.168.1.100 或 10.0.0.0/24"
              required
            />
          </div>
          <div class="form-group">
            <label class="label">原因</label>
            <input
              v-model="whitelistForm.reason"
              type="text"
              class="input"
              placeholder="添加原因（可选）"
            />
          </div>
          <div class="form-group">
            <label class="label">过期时间</label>
            <input
              v-model="whitelistForm.expire_at"
              type="datetime-local"
              class="input"
            />
            <span class="hint">留空表示永久有效</span>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="showWhitelistModal = false">取消</button>
          <button class="btn btn-primary" @click="addWhitelist" :disabled="submitting">添加</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'
import type { IPItem } from '@/types/api'

const auth = useAuthStore()
const activeTab = ref('blacklist')

// Blacklist
const blacklist = ref<IPItem[]>([])
const blacklistTotal = ref(0)
const blacklistEnabledCount = ref(0)
const blacklistDisabledCount = ref(0)
const blacklistPage = ref(1)
const blacklistPageSize = ref(20)
const blacklistFilters = reactive({ ip: '' })
const blacklistTogglingId = ref<number | null>(null)

const whitelistTotalPages = computed(() => Math.ceil(whitelistTotal.value / whitelistPageSize.value) || 1)
const blacklistTotalPages = computed(() => Math.ceil(blacklistTotal.value / blacklistPageSize.value) || 1)

// Whitelist
const whitelist = ref<IPItem[]>([])
const whitelistTotal = ref(0)
const whitelistEnabledCount = ref(0)
const whitelistDisabledCount = ref(0)
const whitelistPage = ref(1)
const whitelistPageSize = ref(20)
const whitelistFilters = reactive({ ip: '' })
const whitelistTogglingId = ref<number | null>(null)

// Auto Block Config
const autoBlockConfig = reactive({
  auto_block_enabled: false,
  auto_block_threshold: 50,
  auto_block_duration: 24,
  ip_list_mode: 'block_first'
})

// Modals
const showBlacklistModal = ref(false)
const showWhitelistModal = ref(false)
const submitting = ref(false)

const blacklistForm = reactive({
  ip: '',
  reason: '',
  expire_at: ''
})

const whitelistForm = reactive({
  ip: '',
  reason: '',
  expire_at: ''
})

// Fetch blacklist
const fetchBlacklist = async () => {
  try {
    const [result, stats] = await Promise.all([
      api.ipBlacklist({
        page: blacklistPage.value,
        page_size: blacklistPageSize.value,
        ip: blacklistFilters.ip || undefined
      }),
      api.ipBlacklistStats()
    ])
    blacklist.value = result.list || []
    blacklistTotal.value = result.total || 0
    blacklistEnabledCount.value = stats.enabled_count || 0
    blacklistDisabledCount.value = stats.disabled_count || 0
  } catch (error) {
    console.error('Failed to fetch blacklist:', error)
  }
}

// Fetch whitelist
const fetchWhitelist = async () => {
  try {
    const [result, stats] = await Promise.all([
      api.ipWhitelist({
        page: whitelistPage.value,
        page_size: whitelistPageSize.value,
        ip: whitelistFilters.ip || undefined
      }),
      api.ipWhitelistStats()
    ])
    whitelist.value = result.list || []
    whitelistTotal.value = result.total || 0
    whitelistEnabledCount.value = stats.enabled_count || 0
    whitelistDisabledCount.value = stats.disabled_count || 0
  } catch (error) {
    console.error('Failed to fetch whitelist:', error)
  }
}

// Fetch auto block config
const fetchAutoBlockConfig = async () => {
  try {
    const config = await api.autoBlockConfig()
    Object.assign(autoBlockConfig, config)
  } catch (error) {
    console.error('Failed to fetch auto block config:', error)
  }
}

// Toggle blacklist item
const toggleBlacklist = async (item: IPItem) => {
  if (blacklistTogglingId.value) return
  blacklistTogglingId.value = item.id
  try {
    await api.toggleIPBlacklist(item.id, item.status === 1 ? 0 : 1)
    auth.setStatus(`IP ${item.ip} 已${item.status === 1 ? '停用' : '启用'}`)
    await fetchBlacklist()
  } catch (error) {
    auth.setStatus(`切换状态失败: ${error instanceof Error ? error.message : error}`)
  } finally {
    blacklistTogglingId.value = null
  }
}

// Toggle whitelist item
const toggleWhitelist = async (item: IPItem) => {
  if (whitelistTogglingId.value) return
  whitelistTogglingId.value = item.id
  try {
    await api.toggleIPWhitelist(item.id, item.status === 1 ? 0 : 1)
    auth.setStatus(`IP ${item.ip} 已${item.status === 1 ? '停用' : '启用'}`)
    await fetchWhitelist()
  } catch (error) {
    auth.setStatus(`切换状态失败: ${error instanceof Error ? error.message : error}`)
  } finally {
    whitelistTogglingId.value = null
  }
}

// Delete blacklist item
const deleteBlacklist = async (item: IPItem) => {
  if (!confirm(`确定要删除 ${item.ip} 吗？`)) return
  try {
    await api.deleteIPBlacklist(item.id)
    fetchBlacklist()
  } catch (error) {
    console.error('Failed to delete blacklist:', error)
    alert(error instanceof Error ? error.message : '删除失败')
  }
}

// Delete whitelist item
const deleteWhitelist = async (item: IPItem) => {
  if (!confirm(`确定要删除 ${item.ip} 吗？`)) return
  try {
    await api.deleteIPWhitelist(item.id)
    fetchWhitelist()
  } catch (error) {
    console.error('Failed to delete whitelist:', error)
    alert(error instanceof Error ? error.message : '删除失败')
  }
}

// Clean expired blacklist
const cleanExpired = async () => {
  if (!confirm('确定要清理所有过期的黑名单吗？')) return
  try {
    await api.cleanExpiredBlacklist()
    fetchBlacklist()
    alert('清理完成')
  } catch (error) {
    console.error('Failed to clean expired:', error)
    alert(error instanceof Error ? error.message : '清理失败')
  }
}

// Save auto block config
const saveAutoBlockConfig = async () => {
  submitting.value = true
  try {
    await api.updateAutoBlockConfig({
      auto_block_enabled: autoBlockConfig.auto_block_enabled,
      auto_block_threshold: autoBlockConfig.auto_block_threshold,
      auto_block_duration: autoBlockConfig.auto_block_duration,
      ip_list_mode: autoBlockConfig.ip_list_mode
    })
    alert('配置保存成功')
  } catch (error) {
    console.error('Failed to save config:', error)
    alert(error instanceof Error ? error.message : '保存失败')
  } finally {
    submitting.value = false
  }
}

// Open modals
const openBlacklistModal = () => {
  blacklistForm.ip = ''
  blacklistForm.reason = ''
  blacklistForm.expire_at = ''
  showBlacklistModal.value = true
}

const openWhitelistModal = () => {
  whitelistForm.ip = ''
  whitelistForm.reason = ''
  whitelistForm.expire_at = ''
  showWhitelistModal.value = true
}

// Format time
const formatTime = (time: string | null | undefined): string => {
  if (!time) return '永久'
  const date = new Date(time)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'Asia/Shanghai'
  })
}

// Check if expired
const isExpired = (expire_at: string | null | undefined): boolean => {
  if (!expire_at) return false
  return new Date(expire_at) < new Date()
}

// Format datetime-local to RFC3339 (convert local time to UTC)
const formatToRFC3339 = (datetime: string): string | null => {
  if (!datetime) return null
  // datetime-local format: YYYY-MM-DDTHH:mm (local time)
  // Convert to UTC before sending to backend
  const date = new Date(datetime)
  return date.toISOString()
}

// Add to blacklist
const addBlacklist = async () => {
  if (!blacklistForm.ip) return
  submitting.value = true
  try {
    await api.createIPBlacklist({
      ip: blacklistForm.ip,
      reason: blacklistForm.reason || undefined,
      expire_at: formatToRFC3339(blacklistForm.expire_at)
    })
    showBlacklistModal.value = false
    fetchBlacklist()
  } catch (error) {
    console.error('Failed to add blacklist:', error)
    alert(error instanceof Error ? error.message : '添加失败')
  } finally {
    submitting.value = false
  }
}

// Add to whitelist
const addWhitelist = async () => {
  if (!whitelistForm.ip) return
  submitting.value = true
  try {
    await api.createIPWhitelist({
      ip: whitelistForm.ip,
      reason: whitelistForm.reason || undefined,
      expire_at: formatToRFC3339(whitelistForm.expire_at)
    })
    showWhitelistModal.value = false
    fetchWhitelist()
  } catch (error) {
    console.error('Failed to add whitelist:', error)
    alert(error instanceof Error ? error.message : '添加失败')
  } finally {
    submitting.value = false
  }
}

onMounted(() => {
  fetchBlacklist()
  fetchWhitelist()
  fetchAutoBlockConfig()
})
</script>

<style scoped>
.ip-security-page {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  height: 100%;
}

.tabs-bar {
  display: flex;
  gap: var(--spacing-sm);
  background: var(--color-muted);
  padding: var(--spacing-sm);
  border-radius: var(--radius-lg);
  border: 1px solid var(--color-border);
}

.tab-btn {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  background: transparent;
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.tab-btn:hover {
  background: var(--color-secondary);
  color: var(--color-foreground);
}

.tab-btn.active {
  background: var(--color-accent);
  color: var(--color-on-primary);
}

.tab-btn svg {
  width: 18px;
  height: 18px;
}

.tab-count {
  padding: 2px 8px;
  background: rgba(0, 0, 0, 0.2);
  border-radius: 9999px;
  font-size: var(--text-xs);
  font-family: var(--font-mono);
}

.tab-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  overflow: hidden;
}

.stats-row {
  display: flex;
  gap: var(--spacing-md);
}

.stat-item {
  flex: 1;
  padding: var(--spacing-md);
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  text-align: center;
}

.stat-item.success .stat-value {
  color: var(--color-success);
}

.stat-item.danger .stat-value {
  color: var(--color-danger);
}

.stat-value {
  display: block;
  font-family: var(--font-mono);
  font-size: var(--text-2xl);
  font-weight: 700;
  color: var(--color-foreground);
}

.stat-label {
  font-size: var(--text-sm);
  color: var(--color-text-muted);
}

.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--spacing-md);
}

.header-left {
  display: flex;
  gap: var(--spacing-sm);
}

.search-input {
  width: 240px;
}

.header-right {
  display: flex;
  gap: var(--spacing-sm);
}

.header-right .btn svg {
  width: 16px;
  height: 16px;
}

.table-card {
  flex: 1;
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.table-wrapper {
  flex: 1;
  overflow-x: auto;
}

.data-table {
  width: 100%;
  border-collapse: collapse;
}

.data-table th,
.data-table td {
  padding: var(--spacing-sm) var(--spacing-md);
  text-align: left;
  border-bottom: 1px solid var(--color-border);
}

.data-table th {
  background: var(--color-secondary);
  font-size: var(--text-sm);
  font-weight: 600;
  color: var(--color-text-secondary);
  white-space: nowrap;
}

.cell-ip {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
}

.cell-reason {
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cell-time {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

.toggle-badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.toggle-badge.active {
  background: rgba(34, 197, 94, 0.2);
  color: var(--color-success);
}

.toggle-badge:not(.active) {
  background: rgba(239, 68, 68, 0.1);
  color: var(--color-text-muted);
}

.toggle-badge.expired {
  background: rgba(139, 92, 246, 0.1);
  color: #8B5CF6;
}

.cell-actions {
  white-space: nowrap;
}

.action-btn {
  padding: 4px 12px;
  font-size: var(--text-xs);
  color: var(--color-text-secondary);
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.action-btn:hover {
  border-color: var(--color-danger);
  color: var(--color-danger);
}

.action-btn.success {
  color: var(--color-success);
  border-color: var(--color-success);
}

.action-btn.success:hover {
  background: var(--color-success);
  color: var(--color-on-primary);
}

.action-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  color: var(--color-text-muted) !important;
  border-color: var(--color-border) !important;
  background: transparent !important;
}

.empty-cell {
  text-align: center;
  padding: var(--spacing-xl) !important;
}

.empty-state {
  color: var(--color-text-muted);
}

/* Pagination */
.pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md);
  border-top: 1px solid var(--color-border);
}

.pagination-info {
  font-size: var(--text-sm);
  color: var(--color-text-muted);
}

.pagination-controls {
  display: flex;
  gap: var(--spacing-xs);
}

.page-btn {
  padding: var(--spacing-xs) var(--spacing-md);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  background: var(--color-secondary);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.page-btn:hover:not(:disabled) {
  border-color: var(--color-accent);
  color: var(--color-accent);
}

.page-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* Config Card */
.config-card {
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
}

.config-card h3 {
  font-size: var(--text-lg);
  font-weight: 600;
  margin-bottom: var(--spacing-lg);
}

.config-form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
  max-width: 600px;
}

.config-item {
  padding: var(--spacing-md);
  background: var(--color-secondary);
  border-radius: var(--radius-md);
}

.toggle-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.config-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.config-title {
  font-size: var(--text-sm);
  font-weight: 500;
}

.config-desc {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

.toggle-switch {
  position: relative;
  width: 44px;
  height: 24px;
  cursor: pointer;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-slider {
  position: absolute;
  inset: 0;
  background: var(--color-border);
  border-radius: 12px;
  transition: all var(--transition-fast);
}

.toggle-slider::before {
  content: '';
  position: absolute;
  width: 18px;
  height: 18px;
  left: 3px;
  top: 3px;
  background: white;
  border-radius: 50%;
  transition: all var(--transition-fast);
}

.toggle-switch input:checked + .toggle-slider {
  background: var(--color-accent);
}

.toggle-switch input:checked + .toggle-slider::before {
  transform: translateX(20px);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.label {
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  font-weight: 500;
}

.select-input {
  width: 100%;
}

.hint {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

.form-actions {
  margin-top: var(--spacing-md);
}

/* Modal */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: var(--z-modal);
}

.modal-content {
  width: 440px;
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md) var(--spacing-lg);
  border-bottom: 1px solid var(--color-border);
}

.modal-header h3 {
  font-size: var(--text-lg);
  font-weight: 600;
}

.close-btn {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--color-text-muted);
  border-radius: var(--radius-sm);
  transition: all var(--transition-fast);
}

.close-btn:hover {
  background: var(--color-secondary);
  color: var(--color-foreground);
}

.close-btn svg {
  width: 18px;
  height: 18px;
}

.modal-body {
  padding: var(--spacing-lg);
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  padding: var(--spacing-md) var(--spacing-lg);
  border-top: 1px solid var(--color-border);
}
</style>
