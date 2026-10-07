import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import App from './App.vue'
import { useAuthStore } from './stores/auth'
import './styles/global.css'
import { initializeTheme } from './stores/theme'

initializeTheme()

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(router)

// Initialize auth store and load from localStorage
const authStore = useAuthStore()
authStore.loadLocal()

app.mount('#app')
