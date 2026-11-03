import { defineStore } from 'pinia'
import { authApi } from '@/api'

export const useUserStore = defineStore('user', {
  state: () => ({
    token: localStorage.getItem('malscope_token') || '',
    user: null
  }),
  getters: {
    isLoggedIn: (state) => !!state.token,
    permissions: (state) => {
      if (!state.user) return []
      if (state.user.is_superuser) return ['*']
      const set = new Set()
      for (const role of state.user.roles || []) {
        for (const p of role.permissions || []) set.add(p.code)
      }
      return [...set]
    }
  },
  actions: {
    has(code) {
      const perms = this.permissions
      return perms.includes('*') || perms.includes(code)
    },
    async login(username, password) {
      const data = await authApi.login({ username, password })
      this.token = data.access_token
      this.user = data.user
      localStorage.setItem('malscope_token', data.access_token)
      return data
    },
    async fetchMe() {
      this.user = await authApi.me()
      return this.user
    },
    async logout() {
      try {
        await authApi.logout()
      } catch (e) { /* ignore */ }
      this.token = ''
      this.user = null
      localStorage.removeItem('malscope_token')
    }
  }
})
