<template>
  <main class="password-page"><form class="password-card" @submit.prevent="save">
    <h2>修改管理账号密码</h2>
    <p v-if="auth.user?.must_change_password">旧密码不符合当前安全要求。修改完成后重新登录，才能继续使用系统。</p><p v-else>修改密码后会退出当前会话，请重新登录。</p>
    <label>当前密码<input class="input" type="password" autocomplete="current-password" v-model="oldPassword" required /></label>
    <label>新密码<input class="input" type="password" autocomplete="new-password" v-model="newPassword" minlength="12" required /></label>
    <label>确认新密码<input class="input" type="password" autocomplete="new-password" v-model="confirmation" required /></label>
    <p>至少 12 个字符，不超过 72 字节；不能使用常见弱口令、连续或重复字符，不能以账号名开头。</p>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <button class="btn btn-primary" :disabled="busy">{{ busy ? '保存中…' : '保存并重新登录' }}</button>
    <button class="btn btn-secondary" type="button" @click="logout">退出登录</button>
  </form></main>
</template>
<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'
const oldPassword = ref(''), newPassword = ref(''), confirmation = ref(''), error = ref(''), busy = ref(false)
const auth = useAuthStore(), router = useRouter()
const logout = async () => { await auth.logout(); router.replace('/login') }
const save = async () => {
  error.value = ''; if (newPassword.value !== confirmation.value) { error.value = '两次输入的新密码不一致'; return }
  busy.value = true
  try { await api.changePassword(oldPassword.value, newPassword.value); auth.clear(); oldPassword.value = ''; newPassword.value = ''; confirmation.value = ''; router.replace('/login') }
  catch (e) { error.value = e instanceof Error ? e.message : '修改失败' } finally { busy.value = false }
}
</script>
<style scoped>
.password-page { min-height:100vh; display:grid; place-items:center; padding:24px; }
.password-card { width:min(100%,480px); display:flex; flex-direction:column; gap:20px; padding:32px; border:1px solid var(--color-border); border-radius:var(--radius-lg); background:var(--color-muted); }
label { display:flex; flex-direction:column; gap:8px; } p { color:var(--color-text-muted); font-size:var(--text-sm); line-height:1.7; } .error { color:var(--color-danger); }
</style>
