import axios from 'axios'
import { ElMessage } from 'element-plus'

const http = axios.create({
  baseURL: '/api/v1',
  timeout: 600000
})

http.interceptors.request.use((config) => {
  const token = localStorage.getItem('malscope_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

http.interceptors.response.use(
  (res) => res.data,
  (error) => {
    const detail = error?.response?.data?.detail
    const status = error?.response?.status
    if (status === 401) {
      localStorage.removeItem('malscope_token')
      if (location.hash !== '#/login') location.hash = '#/login'
      ElMessage.error(detail || '登录已过期，请重新登录')
    } else if (detail) {
      ElMessage.error(typeof detail === 'string' ? detail : JSON.stringify(detail))
    } else {
      ElMessage.error(error.message || '请求失败')
    }
    return Promise.reject(error)
  }
)

export const authApi = {
  login: (data) => http.post('/auth/login', data),
  me: () => http.get('/auth/me'),
  logout: () => http.post('/auth/logout')
}

export const dashboardApi = {
  stats: () => http.get('/dashboard/stats')
}

export const sampleApi = {
  list: (params) => http.get('/samples', { params }),
  upload: (formData, onProgress) =>
    http.post('/samples/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: onProgress
    }),
  detail: (id) => http.get(`/samples/${id}`),
  update: (id, data) => http.put(`/samples/${id}`, data),
  remove: (id) => http.delete(`/samples/${id}`),
  download: (id, confirm = true) =>
    http.get(`/samples/${id}/download`, { params: { confirm }, responseType: 'blob' }),
  similar: (id) => http.get(`/samples/${id}/similar`)
}

export const analysisApi = {
  run: (sampleId, taskType) => http.post(`/analysis/${sampleId}/run`, { task_type: taskType }),
  tasks: (params) => http.get('/analysis/tasks', { params }),
  task: (id) => http.get(`/analysis/tasks/${id}`),
  staticResult: (sampleId) => http.get(`/analysis/${sampleId}/static`),
  dynamicResult: (sampleId) => http.get(`/analysis/${sampleId}/dynamic`)
}

export const iocApi = {
  list: (params) => http.get('/iocs', { params }),
  export: (data) =>
    http.post('/iocs/export', data, { responseType: 'blob' }),
  mispPush: (data) => http.post('/iocs/misp-push', data)
}

export const reportApi = {
  generate: (sampleId, format) =>
    http.post('/reports/generate', null, { params: { sample_id: sampleId, format } }),
  list: (params) => http.get('/reports', { params }),
  download: (id) => http.get(`/reports/${id}/download`, { responseType: 'blob' }),
  previewUrl: (id) => `/api/v1/reports/${id}/preview`
}

export const ruleApi = {
  yaraList: () => http.get('/rules/yara'),
  yaraCreate: (data) => http.post('/rules/yara', data),
  yaraToggle: (id) => http.put(`/rules/yara/${id}/toggle`),
  yaraDelete: (id) => http.delete(`/rules/yara/${id}`),
  packers: () => http.get('/rules/packers')
}

export const userApi = {
  list: () => http.get('/users'),
  create: (data) => http.post('/users', data),
  update: (id, data) => http.put(`/users/${id}`, data),
  roles: () => http.get('/roles'),
  permissions: () => http.get('/permissions')
}

export const auditApi = {
  list: (params) => http.get('/audit', { params })
}

export default http
