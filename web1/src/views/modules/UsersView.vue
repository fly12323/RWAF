<template>
  <div class="users-page">
    <!-- Header -->
    <div class="page-header">
      <div class="header-left">
        <input
          v-model="filters.keyword"
          type="text"
          class="input search-input"
          placeholder="搜索用户名"
          @keyup.enter="fetchUsers"
        />
        <button class="btn btn-secondary" @click="resetFilters">重置</button>
      </div>
      <div class="header-right">
        <button class="btn btn-primary" @click="openCreate">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          新建用户
        </button>
      </div>
    </div>

    <!-- Users Table -->
    <div class="table-card">
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>用户名</th>
              <th>角色</th>
              <th>状态</th>
              <th>最后登录</th>
              <th>创建时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in users" :key="user.id">
              <td class="cell-id">{{ user.id }}</td>
              <td class="cell-username">{{ user.username }}</td>
              <td>
                <span class="role-badge" :class="user.role">
                  {{ RoleNames[user.role] || user.role }}
                </span>
              </td>
              <td>
                <span
                  class="status-badge"
                  :class="user.status === 1 ? 'active' : 'inactive'"
                  @click="toggleStatus(user)"
                >
                  {{ user.status === 1 ? '启用' : '禁用' }}
                </span>
              </td>
              <td class="cell-time">{{ user.last_login || '-' }}</td>
              <td class="cell-time">{{ user.created_at || '-' }}</td>
              <td class="cell-actions">
                <button class="action-btn" @click="openEdit(user)">编辑</button>
                <button class="action-btn" @click="resetPassword(user)">重置密码</button>
                <button class="action-btn danger" @click="deleteUser(user)">删除</button>
              </td>
            </tr>
            <tr v-if="users.length === 0">
              <td colspan="7" class="empty-cell">
                <div class="empty-state">暂无用户数据</div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="pagination">
        <div class="pagination-info">共 {{ total }} 条</div>
        <div class="pagination-controls">
          <button class="page-btn" :disabled="currentPage <= 1" @click="currentPage = 1; fetchUsers()">首页</button>
          <button class="page-btn" :disabled="currentPage <= 1" @click="currentPage--; fetchUsers()">上一页</button>
          <button class="page-btn" :disabled="currentPage >= totalPages" @click="currentPage++; fetchUsers()">下一页</button>
        </div>
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <div class="modal-overlay" v-if="showModal" @click="showModal = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>{{ isEditing ? '编辑用户' : '新建用户' }}</h3>
          <button class="close-btn" @click="showModal = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <div class="modal-body">
          <form @submit.prevent="handleSubmit" class="user-form">
            <div class="form-group">
              <label class="label">用户名 *</label>
              <input
                v-model="form.username"
                type="text"
                class="input"
                placeholder="输入用户名"
                required
                :disabled="isEditing"
              />
            </div>

            <div class="form-group" v-if="!isEditing">
              <label class="label">密码 *</label>
              <input
                v-model="form.password"
                type="password"
                class="input"
                placeholder="至少 12 个字符，不能使用弱口令"
                :required="!isEditing"
              />
            </div>

            <div class="form-group">
              <label class="label">角色 *</label>
              <select v-model="form.role" class="input select-input" required>
                <option value="admin">管理员</option>
                <option value="operator">操作员</option>
                <option value="auditor">审计员</option>
              </select>
            </div>

            <div class="form-group">
              <label class="label">状态</label>
              <select v-model="form.status" class="input select-input">
                <option :value="1">启用</option>
                <option :value="0">禁用</option>
              </select>
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

    <!-- Reset Password Modal -->
    <div class="modal-overlay" v-if="showResetModal" @click="showResetModal = false">
      <div class="modal-content small" @click.stop>
        <div class="modal-header">
          <h3>重置密码 - {{ selectedUser?.username }}</h3>
          <button class="close-btn" @click="showResetModal = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <label class="label">新密码 *</label>
            <input
              v-model="newPassword"
              type="password"
              class="input"
              placeholder="至少 12 个字符，不能使用弱口令"
              required
            />
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="showResetModal = false">取消</button>
          <button class="btn btn-primary" @click="confirmResetPassword" :disabled="submitting">
            {{ submitting ? '重置中...' : '重置密码' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { api } from '@/api'
import { RoleNames } from '@/stores/auth'
import type { UserInfo } from '@/types/api'

const users = ref<UserInfo[]>([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)
const totalPages = computed(() => Math.ceil(total.value / pageSize.value) || 1)

const filters = reactive({ keyword: '' })
const showModal = ref(false)
const showResetModal = ref(false)
const isEditing = ref(false)
const submitting = ref(false)
const selectedUser = ref<UserInfo | null>(null)
const newPassword = ref('')

const form = reactive({
  id: 0,
  username: '',
  password: '',
  role: 'operator',
  status: 1
})

const fetchUsers = async () => {
  try {
    const result = await api.users({
      page: currentPage.value,
      page_size: pageSize.value,
      keyword: filters.keyword || undefined
    })
    users.value = result.list || []
    total.value = result.total || 0
  } catch (error) {
    console.error('Failed to fetch users:', error)
  }
}

const resetFilters = () => {
  filters.keyword = ''
  currentPage.value = 1
  fetchUsers()
}

const openCreate = () => {
  form.id = 0
  form.username = ''
  form.password = ''
  form.role = 'operator'
  form.status = 1
  isEditing.value = false
  showModal.value = true
}

const openEdit = (user: UserInfo) => {
  form.id = user.id
  form.username = user.username
  form.password = ''
  form.role = user.role
  form.status = user.status
  isEditing.value = true
  showModal.value = true
}

const handleSubmit = async () => {
  submitting.value = true
  try {
    const payload: Record<string, unknown> = {
      username: form.username,
      role: form.role,
      status: form.status
    }
    if (!isEditing.value) {
      payload.password = form.password
    }

    if (isEditing.value) {
      // Update user - need to check API
      console.log('Update user:', form.id, payload)
    } else {
      await api.createUser(payload)
    }

    showModal.value = false
    fetchUsers()
  } catch (error) {
    console.error('Failed to save user:', error)
    alert(error instanceof Error ? error.message : '保存失败')
  } finally {
    submitting.value = false
  }
}

const resetPassword = (user: UserInfo) => {
  selectedUser.value = user
  newPassword.value = ''
  showResetModal.value = true
}

const confirmResetPassword = async () => {
  if (!selectedUser.value || !newPassword.value) return
  submitting.value = true
  try {
    await api.resetUser(selectedUser.value.id, newPassword.value)
    showResetModal.value = false
    alert('密码重置成功')
  } catch (error) {
    console.error('Failed to reset password:', error)
    alert(error instanceof Error ? error.message : '重置失败')
  } finally {
    submitting.value = false
  }
}

const deleteUser = async (user: UserInfo) => {
  if (!confirm(`确定要删除用户 "${user.username}" 吗？`)) return
  try {
    await api.deleteUser(user.id)
    fetchUsers()
  } catch (error) {
    console.error('Failed to delete user:', error)
    alert(error instanceof Error ? error.message : '删除失败')
  }
}

const toggleStatus = async (user: UserInfo) => {
  try {
    await api.toggleUser(user.id, user.status === 1 ? 0 : 1)
    fetchUsers()
  } catch (error) {
    console.error('Failed to toggle user status:', error)
    alert(error instanceof Error ? error.message : '状态切换失败')
  }
}

onMounted(() => {
  fetchUsers()
})
</script>

<style scoped>
.users-page {
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

.search-input { width: 240px; }
.header-right .btn svg { width: 16px; height: 16px; }

.table-card {
  flex: 1;
  background: var(--color-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.table-wrapper { flex: 1; overflow-x: auto; }

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
}

.cell-id { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--color-text-muted); }
.cell-username { font-weight: 500; }
.cell-time { font-size: var(--text-xs); color: var(--color-text-muted); }

.role-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
}

.role-badge.admin { background: rgba(239, 68, 68, 0.2); color: var(--color-danger); }
.role-badge.operator { background: rgba(59, 130, 246, 0.2); color: var(--color-info); }
.role-badge.auditor { background: rgba(34, 197, 94, 0.2); color: var(--color-success); }

.status-badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: var(--radius-sm);
  font-size: var(--text-xs);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.status-badge.active { background: rgba(34, 197, 94, 0.2); color: var(--color-success); }
.status-badge.inactive { background: rgba(239, 68, 68, 0.1); color: var(--color-text-muted); }

.cell-actions { white-space: nowrap; display: flex; gap: var(--spacing-xs); }

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

.action-btn:hover { border-color: var(--color-accent); color: var(--color-accent); }
.action-btn.danger:hover { border-color: var(--color-danger); color: var(--color-danger); }

.empty-cell { text-align: center; padding: var(--spacing-xl) !important; }
.empty-state { color: var(--color-text-muted); }

.pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md);
  border-top: 1px solid var(--color-border);
}

.pagination-info { font-size: var(--text-sm); color: var(--color-text-muted); }
.pagination-controls { display: flex; gap: var(--spacing-xs); }

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

.page-btn:hover:not(:disabled) { border-color: var(--color-accent); color: var(--color-accent); }
.page-btn:disabled { opacity: 0.5; cursor: not-allowed; }

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

.modal-content.small { width: 360px; }

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md) var(--spacing-lg);
  border-bottom: 1px solid var(--color-border);
}

.modal-header h3 { font-size: var(--text-lg); font-weight: 600; }

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

.close-btn:hover { background: var(--color-secondary); color: var(--color-foreground); }
.close-btn svg { width: 18px; height: 18px; }

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

.user-form {
  display: flex;
  flex-direction: column;
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

.select-input { width: 100%; }
</style>
