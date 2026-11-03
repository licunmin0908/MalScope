import { createRouter, createWebHashHistory } from 'vue-router'
import { useUserStore } from '@/store/user'

const routes = [
  { path: '/login', name: 'login', component: () => import('@/views/Login.vue'), meta: { public: true } },
  {
    path: '/',
    component: () => import('@/layouts/MainLayout.vue'),
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', name: 'dashboard', component: () => import('@/views/Dashboard.vue'), meta: { title: '总览' } },
      { path: 'samples', name: 'samples', component: () => import('@/views/SampleList.vue'), meta: { title: '样本库' } },
      { path: 'samples/:id', name: 'sample-detail', component: () => import('@/views/SampleDetail.vue'), meta: { title: '样本详情' } },
      { path: 'iocs', name: 'iocs', component: () => import('@/views/IOCList.vue'), meta: { title: '威胁情报' } },
      { path: 'reports', name: 'reports', component: () => import('@/views/Reports.vue'), meta: { title: '分析报告' } },
      { path: 'rules', name: 'rules', component: () => import('@/views/Rules.vue'), meta: { title: '检测规则' } },
      { path: 'users', name: 'users', component: () => import('@/views/Users.vue'), meta: { title: '用户权限' } },
      { path: 'audit', name: 'audit', component: () => import('@/views/Audit.vue'), meta: { title: '审计日志' } }
    ]
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' }
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

router.beforeEach(async (to) => {
  const store = useUserStore()
  if (to.meta.public) return true
  if (!store.isLoggedIn) return { name: 'login', query: { redirect: to.fullPath } }
  if (!store.user) {
    try {
      await store.fetchMe()
    } catch (e) {
      return { name: 'login' }
    }
  }
  return true
})

export default router
