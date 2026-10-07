import axios from 'axios'

let tokenGetter: (() => string) | null = null
let onAuthFailed: (() => void) | null = null

export function bindHttpHooks(getToken: () => string, authFailed: () => void) {
  tokenGetter = getToken
  onAuthFailed = authFailed
}

export const http = axios.create({
  baseURL: '',
  timeout: 15000
})

http.interceptors.request.use((config) => {
  const token = tokenGetter?.()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

http.interceptors.response.use(
  (response) => {
    const payload = response.data
    if (payload?.code !== 0) {
      const raw = String(payload?.message || '请求失败')
      const message = /[\uFFFD]/.test(raw) ? '请求失败（返回内容编码异常）' : raw
      if (raw.toLowerCase().includes('token') || raw.includes('未登录') || raw.includes('令牌') || raw.includes('过期')) {
        console.log('auth failed detected, calling onAuthFailed')
        onAuthFailed?.()
      }
      return Promise.reject(new Error(message))
    }
    return payload.data
  },
  (error) => Promise.reject(new Error(error?.message || '网络错误'))
)
