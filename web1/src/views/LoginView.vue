<template>
 <main class="login-container">
  <div class="login-theme"><ThemeToggle /></div>
  <section class="login-card">
   <div class="brand"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg><span>RWAF</span></div>
   <h1>登录管理后台</h1><p class="subtitle">管理站点防护，查看安全事件与运行状态。</p>
   <form @submit.prevent="handleLogin">
    <label for="login-username">用户名</label><input id="login-username" v-model="form.username" class="input" placeholder="请输入用户名" autocomplete="username" required />
    <label for="login-password">密码</label><input id="login-password" v-model="form.password" type="password" class="input" placeholder="请输入密码" autocomplete="current-password" required />
    <p v-if="errorMessage" class="form-error" role="alert">{{ errorMessage }}</p>
    <button class="btn btn-primary login-submit" :disabled="loading">{{ loading ? '登录中…' : '登录' }}</button>
   </form>
  </section>
 </main>
</template>
<script setup lang="ts">
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import ThemeToggle from '@/components/ThemeToggle.vue'

const router = useRouter()
const authStore = useAuthStore()

const form = reactive({
  username: '',
  password: ''
})

const loading = ref(false)
const errorMessage = ref('')

const handleLogin = async () => {
  if (!form.username || !form.password) {
    errorMessage.value = '请输入用户名和密码'
    return
  }

  loading.value = true
  errorMessage.value = ''

  try {
    await authStore.login(form.username, form.password)
    router.push('/overview')
  } catch (error: unknown) {
    errorMessage.value = error instanceof Error ? error.message : '登录失败，请稍后重试'
  } finally {
    loading.value = false
  }
}
</script>
<style scoped>
.login-container{min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:64px 20px;background:var(--color-background);overflow:auto;height:100dvh}
.login-card{width:410px;max-width:100%;padding:40px;background:var(--color-primary);border:1px solid var(--color-border);border-radius:10px}
.brand{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:600}.brand svg{width:34px;height:34px;color:var(--color-accent)}
h1{font-size:24px;margin:28px 0 12px}.subtitle{color:var(--color-text-secondary);line-height:1.8;font-size:14px}label{display:block;margin:24px 0 8px;font-size:14px}.input{padding:12px}.login-submit{width:100%;margin-top:28px;padding:12px}.form-error{color:var(--color-danger);font-size:14px;margin-top:16px}.login-theme{position:fixed;right:24px;top:22px}
@media(max-width:600px){.login-card{padding:28px}.login-theme{right:16px;top:16px}}
</style>
