<template>
  <div class="rules-page">
    <p class="catalog-hint">内置规则来自当前规则文件，只能查看内容和分类；目录状态不代表全局策略下实际启用状态；需要调整防护范围时，请前往全局防护。自定义规则可由管理员或操作员维护。</p>
    <nav class="category-nav" aria-label="规则分类">
      <button type="button" :class="{ active: !filters.category }" :aria-pressed="!filters.category" @click="selectCategory('')">全部分类 <span>{{ statistics.total || 0 }}</span></button>
      <button v-for="cat in categories" :key="cat.category" type="button" :class="{ active: filters.category === cat.category }" :aria-pressed="filters.category === cat.category" @click="selectCategory(cat.category)">{{ cat.category }} <span>{{ cat.count }}</span></button>
    </nav>
    <!-- Header -->
    <div class="page-header">
      <div class="header-left">
        <input
          v-model="filters.keyword"
          type="text"
          class="input search-input"
          placeholder="在当前分类中搜索规则ID / 描述"
          @keyup.enter="goToPage(1)"
        />
        <button class="btn btn-secondary" @click="resetFilters">重置</button>
      </div>
      <div class="header-right">
        <button v-if="auth.canWrite" class="btn btn-secondary" @click="reloadRules">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="23,4 23,10 17,10"/>
            <polyline points="1,20 1,14 7,14"/>
            <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
          </svg>
          重载规则
        </button>
        <button v-if="auth.canWrite" class="btn btn-primary" @click="openCreate">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          新建规则
        </button>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="stats-row">
      <div class="stat-item">
        <span class="stat-value">{{ statistics.total || 0 }}</span>
        <span class="stat-label">总规则数</span>
      </div>
      <div class="stat-item success">
        <span class="stat-value">{{ statistics.enabled || 0 }}</span>
        <span class="stat-label">已启用</span>
      </div>
      <div class="stat-item danger">
        <span class="stat-value">{{ statistics.disabled || 0 }}</span>
        <span class="stat-label">已禁用</span>
      </div>
    </div>

    <!-- Rules Table -->
    <div class="table-card">
      <div class="table-wrapper">
        <table class="data-table">
          <colgroup><col style="width:110px" /><col style="width:160px" /><col style="width:110px" /><col /><col style="width:120px" /><col style="width:110px" /><col style="width:250px" /></colgroup>
          <thead>
            <tr>
              <th>规则ID</th>
              <th>分类</th>
              <th>严重程度</th>
              <th>描述</th>
              <th>评分</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="rule in rules" :key="rule.id">
              <td class="cell-rule-id">{{ rule.rule_id }}<small class="rule-source">{{ rule.is_custom ? '自定义' : '内置只读' }}</small></td>
              <td>
                <span class="category-badge">{{ rule.category || '-' }}</span>
              </td>
              <td>
                <span class="severity-badge" :class="rule.severity?.toLowerCase()">
                  {{ rule.severity || '-' }}
                </span>
              </td>
              <td class="cell-desc" :title="rule.description">{{ rule.description || '-' }}</td>
              <td>
                <span class="score-value" :class="getScoreClass(rule.score)">
                  {{ rule.is_custom ? (rule.score || 0) : '见规则正文' }}
                </span>
              </td>
              <td>
                <span
                  class="toggle-badge"
                  :class="{ active: rule.enabled }"
                  @click="rule.is_custom && auth.canWrite && toggleRule(rule)"
                >
                  {{ rule.is_custom ? (rule.enabled ? '已启用' : '已禁用') : '内置只读' }}
                </span>
              </td>
              <td class="cell-actions"><div class="action-group">
                <button class="action-btn" @click="viewDetail(rule)">详情</button>
                <button v-if="rule.is_custom && auth.canWrite" class="action-btn" @click="openEdit(rule)">编辑</button>
                <button
                  class="action-btn"
                  :class="rule.enabled ? 'danger' : 'success'"
                  v-if="rule.is_custom && auth.canWrite" :disabled="togglingId === rule.id"
                  @click="toggleRule(rule)"
                >
                  {{ rule.enabled ? '停用' : '启用' }}
                </button>
                <button v-if="rule.is_custom && auth.canWrite" class="action-btn danger" @click="deleteRule(rule)">删除</button>
              </div></td>
            </tr>
            <tr v-if="rules.length === 0">
              <td colspan="7" class="empty-cell">
                <div class="empty-state">
                  <span>暂无规则数据</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div class="pagination">
        <div class="pagination-info">
          共 {{ total }} 条，第 {{ currentPage }} / {{ totalPages }} 页
        </div>
        <div class="pagination-controls">
          <button class="page-btn" :disabled="currentPage <= 1" @click="goToPage(1)">首页</button>
          <button class="page-btn" :disabled="currentPage <= 1" @click="goToPage(currentPage - 1)">上一页</button>
          <button class="page-btn" :disabled="currentPage >= totalPages" @click="goToPage(currentPage + 1)">下一页</button>
          <button class="page-btn" :disabled="currentPage >= totalPages" @click="goToPage(totalPages)">末页</button>
        </div>
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <div class="modal-overlay" v-if="showModal" @click="showModal = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>{{ isEditing ? '编辑规则' : '新建规则' }}</h3>
          <button class="close-btn" @click="showModal = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <div class="modal-body">
          <form @submit.prevent="handleSubmit" class="rule-form">
            <div class="form-group">
              <label class="label">规则ID *</label>
              <input
                v-model="form.rule_id"
                type="text"
                class="input"
                placeholder="如: SQL-001"
                required
                :disabled="isEditing"
              />
            </div>

            <div class="form-row">
              <div class="form-group">
                <label class="label">分类 *</label>
                <select v-model="form.category" class="input select-input" required>
                  <option value="">选择分类</option>
                  <option value="SQL Injection">SQL注入</option>
                  <option value="XSS">XSS</option>
                  <option value="CSRF">CSRF</option>
                  <option value="LFI">本地文件包含</option>
                  <option value="RFI">远程文件包含</option>
                  <option value="Command Injection">命令注入</option>
                  <option value="Protocol Attack">协议攻击</option>
                  <option value="Other">其他</option>
                  <option v-for="cat in extraCategoryOptions" :key="cat" :value="cat">{{ cat }}</option>
                </select>
              </div>
              <div class="form-group">
                <label class="label">严重程度 *</label>
                <select v-model="form.severity" class="input select-input" required>
                  <option value="">选择严重程度</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                  <option v-for="sev in extraSeverityOptions" :key="sev" :value="sev">{{ sev }}</option>
                </select>
              </div>
            </div>

            <div class="form-group">
              <label class="label">描述 *</label>
              <input
                v-model="form.description"
                type="text"
                class="input"
                placeholder="规则描述"
                required
              />
            </div>

            <div class="form-row">
              <div class="form-group">
                <label class="label">评分 (0-100)</label>
                <input
                  v-model.number="form.score"
                  type="number"
                  class="input"
                  placeholder="50"
                  min="0"
                  max="100"
                />
              </div>
              <div class="form-group">
                <label class="label">状态</label>
                <select v-model="form.enabled" class="input select-input">
                  <option :value="true">启用</option>
                  <option :value="false">禁用</option>
                </select>
              </div>
            </div>

            <div class="form-group">
              <label class="label">规则内容 *</label>
              <textarea
                v-model="form.rule_content"
                class="input textarea"
                placeholder="SecRule ..."
                rows="6"
                required
              ></textarea>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="showModal = false">取消</button>
          <button class="btn btn-primary" @click="handleSubmit" :disabled="submitting">
            {{ submitting ? '提交中...' : (isEditing ? '保存' : '创建') }}
          </button>
        </div>
      </div>
    </div>

    <!-- Detail Modal -->
    <div class="modal-overlay" v-if="showDetail" @click="showDetail = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>规则详情</h3>
          <button class="close-btn" @click="showDetail = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <div class="modal-body" v-if="selectedRule">
          <div class="detail-grid">
            <div class="detail-item">
              <span class="detail-label">规则ID</span>
              <span class="detail-value mono">{{ selectedRule.rule_id }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">分类</span>
              <span class="detail-value">{{ selectedRule.category }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">严重程度</span>
              <span class="detail-value" :class="'severity-' + selectedRule.severity?.toLowerCase()">
                {{ selectedRule.severity }}
              </span>
            </div>
            <div class="detail-item">
              <span class="detail-label">评分</span>
              <span class="detail-value">{{ selectedRule.is_custom ? selectedRule.score : '由规则正文与运行时变量决定' }}</span>
            </div>
            <div class="detail-item full">
              <span class="detail-label">描述</span>
              <span class="detail-value">{{ selectedRule.description }}</span>
            </div>
            <div class="detail-item full">
              <span class="detail-label">规则文件</span>
              <span class="detail-value mono">{{ selectedRule.rule_file || '-' }}</span>
            </div>
            <div class="detail-item full">
              <span class="detail-label">规则内容</span>
              <pre class="detail-code">{{ selectedRule.rule_content }}</pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'
import type { Rule } from '@/types/api'

const auth = useAuthStore()
const rules = ref<Rule[]>([])
const categories = ref<Array<{ category: string; count: number }>>([])
const statistics = ref<{ total: number; enabled: number; disabled: number; by_category: Array<{ category: string; count: number }> }>({
  total: 0,
  enabled: 0,
  disabled: 0,
  by_category: []
})
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)
const totalPages = computed(() => Math.ceil(total.value / pageSize.value) || 1)

const filters = reactive({
  keyword: '',
  category: ''
})

const showModal = ref(false)
const showDetail = ref(false)
const isEditing = ref(false)
const submitting = ref(false)
const togglingId = ref<number | null>(null)
const selectedRule = ref<Rule | null>(null)

// 编辑时动态补充的下拉选项（当数据库值不在预定义列表中时）
const extraCategoryOptions = ref<string[]>([])
const extraSeverityOptions = ref<string[]>([])

const PREDEFINED_CATEGORIES = ['SQL Injection', 'XSS', 'CSRF', 'LFI', 'RFI', 'Command Injection', 'Protocol Attack', 'Other']
const PREDEFINED_SEVERITIES = ['Critical', 'High', 'Medium', 'Low']

const form = reactive({
  id: 0,
  rule_id: '',
  category: '',
  severity: '',
  description: '',
  score: 50,
  rule_content: '',
  enabled: true
})

const fetchRules = async () => {
  try {
    const result = await api.rules({
      page: currentPage.value,
      page_size: pageSize.value,
      keyword: filters.keyword || undefined,
      category: filters.category || undefined
    })
    rules.value = result.list || []
    total.value = result.total || 0
  } catch (error) {
    console.error('Failed to fetch rules:', error)
  }
}

const fetchCategories = async () => {
  try {
    const cats = await api.getRuleCategories()
    categories.value = cats || []
  } catch (error) {
    console.error('Failed to fetch categories:', error)
  }
}

const fetchStatistics = async () => {
  try {
    const stats = await api.getRuleStatistics()
    statistics.value = {
      ...stats,
      disabled: (stats.total || 0) - (stats.enabled || 0)
    }
  } catch (error) {
    console.error('Failed to fetch statistics:', error)
  }
}

const selectCategory = (category: string) => { filters.category = category; filters.keyword = ''; goToPage(1) }

const resetFilters = () => {
  filters.keyword = ''
  filters.category = ''
  currentPage.value = 1
  fetchRules()
}

const goToPage = (page: number) => {
  currentPage.value = page
  fetchRules()
}

const openCreate = () => {
  form.id = 0
  form.rule_id = ''
  form.category = ''
  form.severity = ''
  form.description = ''
  form.score = 50
  form.rule_content = ''
  form.enabled = true
  isEditing.value = false
  showModal.value = true
  extraCategoryOptions.value = []
  extraSeverityOptions.value = []
}

const openEdit = (rule: Rule) => {
  if (!rule.is_custom || !auth.canWrite) return
  form.id = rule.id
  form.rule_id = rule.rule_id
  form.category = rule.category || ''
  form.severity = rule.severity || ''
  form.description = rule.description || ''
  form.score = rule.score || 0
  form.rule_content = rule.rule_content || ''
  form.enabled = rule.enabled
  isEditing.value = true
  showModal.value = true

  // 确保下拉框能显示当前值（即使它不在预定义列表中）
  extraCategoryOptions.value = rule.category && !PREDEFINED_CATEGORIES.includes(rule.category) ? [rule.category] : []
  extraSeverityOptions.value = rule.severity && !PREDEFINED_SEVERITIES.includes(rule.severity) ? [rule.severity] : []
}

const viewDetail = (rule: Rule) => {
  selectedRule.value = rule
  showDetail.value = true
}

const handleSubmit = async () => {
  submitting.value = true
  try {
    const payload = {
      rule_id: form.rule_id,
      category: form.category,
      severity: form.severity,
      description: form.description,
      score: form.score,
      rule_content: form.rule_content,
      enabled: form.enabled
    }

    if (isEditing.value) {
      await api.updateRule(form.id, payload)
    } else {
      await api.createRule(payload)
    }

    showModal.value = false
    fetchRules()
    fetchStatistics()
    fetchCategories()
  } catch (error) {
    console.error('Failed to save rule:', error)
    alert(error instanceof Error ? error.message : '保存失败')
  } finally {
    submitting.value = false
  }
}

const toggleRule = async (rule: Rule) => {
  if (togglingId.value) return
  togglingId.value = rule.id
  try {
    await api.toggleRule(rule.id, !rule.enabled)
    auth.setStatus(`规则 "${rule.rule_id}" 已${rule.enabled ? '停用' : '启用'}`)
    await fetchRules()
    await fetchStatistics()
  } catch (error) {
    auth.setStatus(`切换规则状态失败: ${error instanceof Error ? error.message : error}`)
  } finally {
    togglingId.value = null
  }
}

const deleteRule = async (rule: Rule) => {
  if (!confirm(`确定要删除规则 "${rule.rule_id}" 吗？`)) return
  try {
    await api.deleteRule(rule.id)
    fetchRules()
    fetchStatistics()
  } catch (error) {
    console.error('Failed to delete rule:', error)
    alert(error instanceof Error ? error.message : '删除失败')
  }
}

const reloadRules = async () => {
  if (!confirm('确定要重载所有规则吗？')) return
  try {
    await api.reloadRules()
    alert('规则重载成功')
    fetchRules()
    fetchStatistics()
  } catch (error) {
    console.error('Failed to reload rules:', error)
    alert(error instanceof Error ? error.message : '重载失败')
  }
}

const getScoreClass = (score?: number): string => {
  if (!score) return ''
  if (score >= 80) return 'high'
  if (score >= 50) return 'medium'
  return 'low'
}

onMounted(() => {
  fetchRules()
  fetchCategories()
  fetchStatistics()
})
</script>

<style scoped>
.rules-page {
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
  flex-wrap: wrap;
}

.header-left {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
}

.search-input {
  width: 240px;
}

.select-input {
  width: 160px;
}

.header-right {
  display: flex;
  gap: var(--spacing-sm);
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
  table-layout: fixed;
  min-width: 1100px;
}

.data-table th,
.data-table td {
  padding: var(--spacing-sm) var(--spacing-md);
  text-align: left;
  vertical-align: middle;
  height: 64px;
  box-sizing: border-box;
  border-bottom: 1px solid var(--color-border);
}

.data-table th {
  background: var(--color-secondary);
  font-size: var(--text-sm);
  font-weight: 600;
  color: var(--color-text-secondary);
  white-space: nowrap;
}

.cell-rule-id {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--color-accent);
}

.category-badge {
  display: inline-block;
  padding: 2px 8px;
  background: rgba(59, 130, 246, 0.2);
  color: var(--color-info);
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
}

.severity-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
  font-weight: 500;
}

.severity-badge.critical {
  background: rgba(239, 68, 68, 0.2);
  color: var(--color-danger);
}

.severity-badge.high {
  background: rgba(245, 158, 11, 0.2);
  color: var(--color-warning);
}

.severity-badge.medium {
  background: rgba(59, 130, 246, 0.2);
  color: var(--color-info);
}

.severity-badge.low {
  background: rgba(34, 197, 94, 0.2);
  color: var(--color-success);
}

.cell-desc {
  max-width: 250px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: var(--text-sm);
}

.score-value {
  font-family: var(--font-mono);
  font-weight: 600;
}

.score-value.high { color: var(--color-danger); }
.score-value.medium { color: var(--color-warning); }
.score-value.low { color: var(--color-text-muted); }

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

.cell-actions { white-space: nowrap; }
.action-group { display: flex; align-items: center; gap: var(--spacing-xs); }
.category-nav { display:flex; flex-wrap:wrap; gap:8px; }
.category-nav button { display:flex; align-items:center; gap:8px; padding:8px 12px; border:1px solid var(--color-border); border-radius:6px; color:var(--color-text-secondary); background:var(--color-primary); cursor:pointer; }
.category-nav button.active { color:var(--color-accent); border-color:var(--color-accent); background:var(--color-secondary); }
.category-nav span { font-size:12px; font-variant-numeric:tabular-nums; color:var(--color-text-muted); }

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
  width: 560px;
  max-height: 80vh;
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  overflow: hidden;
  display: flex;
  flex-direction: column;
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
.rule-form {
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

.select-input {
  width: 100%;
}

.textarea {
  resize: vertical;
  min-height: 120px;
  font-family: var(--font-mono);
  font-size: var(--text-sm);
}

/* Detail */
.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md);
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.detail-item.full {
  grid-column: span 2;
}

.detail-label {
  font-size: var(--text-xs);
  color: var(--color-text-muted);
  text-transform: uppercase;
}

.detail-value {
  font-size: var(--text-sm);
  color: var(--color-foreground);
}

.detail-value.mono {
  font-family: var(--font-mono);
}

.detail-code {
  background: var(--color-secondary);
  padding: var(--spacing-md);
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
}
.catalog-hint{color:var(--color-text-secondary);font-size:14px;line-height:1.7}.rule-source{display:block;color:var(--color-text-muted);font-size:12px;font-weight:400;margin-top:5px}
</style>
