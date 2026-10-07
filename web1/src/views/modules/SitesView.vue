<template>
  <div class="sites-page">
    <!-- Stats Cards -->
    <div class="stats-row">
      <div class="stat-item">
        <span class="stat-value">{{ total }}</span>
        <span class="stat-label">站点总数</span>
      </div>
      <div class="stat-item success">
        <span class="stat-value">{{ enabledCount }}</span>
        <span class="stat-label">已启用</span>
      </div>
      <div class="stat-item danger">
        <span class="stat-value">{{ disabledCount }}</span>
        <span class="stat-label">已停用</span>
      </div>
    </div>

    <!-- Header -->
    <div class="page-header">
      <div class="header-left">
        <input
          v-model="filters.keyword"
          type="text"
          class="input search-input"
          placeholder="搜索站点名称 / 域名"
          @keyup.enter="fetchSites"
        />
        <button class="btn btn-secondary" @click="fetchSites">搜索</button>
      </div>
      <div class="header-right">
        <button class="btn btn-primary" @click="openCreate">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          新建站点
        </button>
      </div>
    </div>

    <!-- Sites Table -->
    <div class="table-card">
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>站点名称</th>
              <th>监听端口</th>
              <th>域名</th>
              <th>后端服务器</th>
              <th>启用状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="site in sites" :key="site.id">
              <td class="cell-name">{{ site.name }}</td>
              <td class="cell-port">{{ site.tls_enabled ? 'HTTPS' : 'HTTP' }} · {{ site.listen_port }}</td>
              <td class="cell-domains">{{ formatDomains(site.domains) }}</td>
              <td class="cell-upstream">{{ formatUpstream(site.upstream_targets) }}</td>
              <td>
                <span
                  class="toggle-badge"
                  :class="{ active: site.enabled, loading: togglingId === site.id && togglingType === 'site' }"
                  @click="toggleSite(site)"
                >
                  {{ togglingId === site.id && togglingType === 'site' ? '...' : (site.enabled ? '在线' : '离线') }}
                </span>
              </td>
              <td class="cell-actions">
                <button class="action-btn" @click="openEdit(site)">编辑</button>
                <button
                  class="action-btn"
                  :class="site.enabled ? 'danger' : 'success'"
                  :disabled="togglingId === site.id && togglingType === 'site'"
                  @click="toggleSite(site)"
                >
                  {{ site.enabled ? '停用' : '启用' }}
                </button>
                <button class="action-btn danger" @click="deleteSite(site)">删除</button>
              </td>
            </tr>
            <tr v-if="sites.length === 0">
              <td colspan="6" class="empty-cell">
                <div class="empty-state">
                  <span>暂无站点数据</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div class="pagination">
        <div class="pagination-info">
          共 {{ total }} 条
        </div>
        <div class="pagination-controls">
          <button class="page-btn" :disabled="currentPage <= 1" @click="goToPage(1)">首页</button>
          <button class="page-btn" :disabled="currentPage <= 1" @click="goToPage(currentPage - 1)">上一页</button>
          <button class="page-btn" :disabled="currentPage >= totalPages" @click="goToPage(currentPage + 1)">下一页</button>
        </div>
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <div class="modal-overlay" v-if="showModal" @click="closeModal">
      <div class="modal-content large" @click.stop>
        <div class="modal-header">
          <h3>{{ isEditing ? '编辑站点' : '新建站点' }}</h3>
          <button class="close-btn" @click="closeModal">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <div class="modal-body">
          <form @submit.prevent="handleSubmit" class="site-form">
            <div class="form-row">
              <div class="form-group">
                <label class="label">站点名称 *</label>
                <input
                  v-model="form.name"
                  type="text"
                  class="input"
                  placeholder="输入站点名称"
                  required
                />
              </div>
              <div class="form-group">
                <label class="label">监听端口 *</label>
                <input
                  v-model.number="form.listen_port"
                  type="number"
                  class="input"
                  placeholder="9000"
                  required
                />
              </div>
            </div>

            <div class="form-group">
              <label class="label">域名</label>
              <input
                v-model="form.domains"
                type="text"
                class="input"
                placeholder="example.com（多个用逗号分隔）"
              />
              <span class="hint">多个域名用逗号分隔。同端口按域名区分站点；HTTP 留空作为默认站点。</span>
            </div>

            <div class="form-group">
              <label class="label">接入协议</label>
              <select v-model="form.tls_enabled" class="input">
                <option :value="false">HTTP</option>
                <option :value="true">HTTPS</option>
              </select>
              <span class="hint">同端口站点需使用相同协议。HTTPS 证书必须覆盖全部配置域名。</span>
            </div>
            <template v-if="form.tls_enabled">
              <div class="form-group">
                <label class="label">证书链（PEM）</label>
                <input type="file" accept=".pem,.crt,.cer" @change="loadPEM($event, 'certificate')" />
                <textarea v-model="form.tls_certificate" class="input textarea" rows="4" placeholder="粘贴证书链，叶证书放在最前面" spellcheck="false"></textarea>
              </div>
              <div class="form-group">
                <label class="label">私钥（PEM）{{ isEditing ? '，留空保留已有私钥' : '' }}</label>
                <input type="file" accept=".pem,.key" @change="loadPEM($event, 'key')" />
                <textarea v-model="form.tls_private_key" class="input textarea" rows="3" placeholder="导入或粘贴未加密 PEM 私钥" spellcheck="false" autocomplete="off"></textarea>
                <span class="hint">私钥加密保存，后台不会回显。保存证书后立即用于新 TLS 连接。</span>
              </div>
            </template>

            <div class="form-group">
              <label class="label">后端服务器 *</label>
              <textarea
                v-model="form.targets"
                class="input textarea"
                placeholder="127.0.0.1:9000:1（每行一个）"
                rows="3"
                required
              ></textarea>
              <span class="hint">每行一个，格式：host:port:weight</span>
            </div>

          </form>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="closeModal">取消</button>
          <button class="btn btn-primary" @click="handleSubmit" :disabled="submitting">
            {{ submitting ? '提交中...' : (isEditing ? '保存' : '创建') }}
          </button>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'
import type { Site } from '@/types/api'

const auth = useAuthStore()
const sites = ref<Site[]>([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)
const totalPages = computed(() => Math.ceil(total.value / pageSize.value) || 1)
const enabledCount = computed(() => sites.value.filter(s => s.enabled).length)
const disabledCount = computed(() => sites.value.filter(s => !s.enabled).length)

const filters = reactive({
  keyword: ''
})

const showModal = ref(false)
const isEditing = ref(false)
const submitting = ref(false)
const togglingId = ref<number | null>(null)
const togglingType = ref<'site' | null>(null)

const form = reactive({
  id: 0,
  name: '',
  listen_port: 9000,
  domains: '',
  targets: '',
  tls_enabled: false,
  tls_certificate: '',
  tls_private_key: '',
})

const fetchSites = async () => {
  try {
    const result = await api.sites({
      page: currentPage.value,
      page_size: pageSize.value,
      keyword: filters.keyword || undefined
    })
    sites.value = result.list || []
    total.value = result.total || 0
  } catch (error) {
    console.error('Failed to fetch sites:', error)
  }
}

const resetForm = () => {
  form.id = 0
  form.name = ''
  form.listen_port = 9000
  form.domains = ''
  form.targets = ''
  form.tls_enabled = false
  form.tls_certificate = ''
  form.tls_private_key = ''
}

const openCreate = () => {
  resetForm()
  isEditing.value = false
  showModal.value = true
}

const openEdit = (site: Site) => {
  form.id = site.id
  form.name = site.name
  form.listen_port = site.listen_port
  form.tls_enabled = !!site.tls_enabled
  form.tls_certificate = site.tls_certificate || ''
  form.tls_private_key = ''
  form.domains = Array.isArray(site.domains) ? site.domains.join(',') : site.domains

  // 解析后端服务器为 host:port:weight 格式
  let upstreamArr: Array<{ host: string; port: number; weight: number }> = []
  if (Array.isArray(site.upstream_targets)) {
    upstreamArr = site.upstream_targets
  } else if (typeof site.upstream_targets === 'string' && site.upstream_targets.trim()) {
    try { upstreamArr = JSON.parse(site.upstream_targets) } catch {}
  }
  form.targets = upstreamArr.map(t => `${t.host}:${t.port}:${t.weight}`).join('\n')

  isEditing.value = true
  showModal.value = true
}

const closeModal = () => {
  showModal.value = false
  form.tls_private_key = ''
}
const loadPEM = async (event: Event, kind: 'certificate' | 'key') => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    if (file.size > (kind === 'key' ? 32768 : 131072)) throw new Error('文件超过大小上限')
    const content = await file.text()
    if (kind === 'key') form.tls_private_key = content
    else form.tls_certificate = content
  } catch (error) { alert(error instanceof Error ? error.message : '文件读取失败') }
  finally { input.value = '' }
}

const handleSubmit = async () => {
  submitting.value = true
  try {
    const upstream_targets = form.targets
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean)
      .map(line => {
        const [host, port, weight] = line.split(':')
        return { host, port: Number(port || 80), weight: Number(weight || 1) }
      })

    const payload = {
      name: form.name,
      listen_port: form.listen_port,
      domains: form.domains.split(',').map(d => d.trim()).filter(Boolean),
      tls_enabled: form.tls_enabled,
      tls_certificate: form.tls_certificate,
      tls_private_key: form.tls_private_key || undefined,
      upstream_targets,
    }

    if (isEditing.value) {
      await api.updateSite(form.id, payload)
    } else {
      await api.createSite(payload)
    }

    closeModal()
    fetchSites()
  } catch (error) {
    console.error('Failed to save site:', error)
    alert(error instanceof Error ? error.message : '保存失败')
  } finally {
    submitting.value = false
  }
}

const toggleSite = async (site: Site) => {
  if (togglingId.value) return
  togglingId.value = site.id
  togglingType.value = 'site'
  try {
    await api.toggleSite(site.id, !site.enabled)
    auth.setStatus(`站点 "${site.name}" 已${site.enabled ? '停用' : '启用'}`)
    await fetchSites()
  } catch (error) {
    auth.setStatus(`切换站点状态失败: ${error instanceof Error ? error.message : error}`)
  } finally {
    togglingId.value = null
    togglingType.value = null
  }
}

const deleteSite = async (site: Site) => {
  if (!confirm(`确定要删除站点 "${site.name}" 吗？`)) return
  try {
    await api.deleteSite(site.id)
    fetchSites()
  } catch (error) {
    console.error('Failed to delete site:', error)
    alert(error instanceof Error ? error.message : '删除失败')
  }
}

const goToPage = (page: number) => {
  currentPage.value = page
  fetchSites()
}

const formatDomains = (domains: string | string[]): string => {
  if (Array.isArray(domains)) return domains.slice(0, 2).join(', ')
  try {
    const parsed = JSON.parse(domains)
    return Array.isArray(parsed) ? parsed.slice(0, 2).join(', ') : domains
  } catch {
    return domains
  }
}

const formatUpstream = (targets: string | unknown[]): string => {
  if (Array.isArray(targets) && targets.length > 0) {
    const first = targets[0] as { host?: string; port?: number }
    return first?.host ? `${first.host}:${first.port}` : JSON.stringify(targets).slice(0, 30)
  }
  if (typeof targets === 'string') {
    try {
      const parsed = JSON.parse(targets)
      if (Array.isArray(parsed) && parsed.length > 0) {
        const first = parsed[0] as { host?: string; port?: number }
        return first?.host ? `${first.host}:${first.port}` : parsed.slice(0, 2).map((t: { host?: string; port?: number }) => `${t.host}:${t.port}`).join(', ')
      }
    } catch {
      return targets
    }
  }
  return '-'
}

onMounted(() => {
  fetchSites()
})
</script>

<style scoped>
.sites-page {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  height: 100%;
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
  width: 260px;
}

.header-right .btn svg {
  width: 16px;
  height: 16px;
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

.cell-name {
  font-weight: 500;
}

.cell-port {
  font-family: var(--font-mono);
  color: var(--color-info);
}

.cell-domains {
  font-size: var(--text-sm);
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cell-upstream {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--color-text-muted);
  max-width: 150px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
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

.toggle-badge.loading {
  opacity: 0.7;
  cursor: wait;
}

.cell-actions {
  white-space: nowrap;
  display: flex;
  gap: var(--spacing-xs);
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
  border-color: var(--color-accent);
  color: var(--color-accent);
}

.action-btn.danger:hover {
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
  width: 500px;
  max-height: 80vh;
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.modal-content.large {
  width: 640px;
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
  overflow-y: auto;
  flex: 1;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  padding: var(--spacing-md) var(--spacing-lg);
  border-top: 1px solid var(--color-border);
}

/* Form */
.site-form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
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

.input.textarea {
  resize: vertical;
  min-height: 80px;
}

.select-input {
  width: 100%;
}

.hint {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
}

/* Config Grid */
</style>
