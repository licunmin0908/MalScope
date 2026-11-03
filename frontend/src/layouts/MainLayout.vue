<template>
  <el-container style="height: 100%">
    <el-aside width="216px" style="background:#12263a">
      <div class="brand">
        <span class="logo">🛡️</span>
        <div>
          <div class="name">MalScope</div>
          <div class="desc">恶意样本智能分析平台</div>
        </div>
      </div>
      <el-menu
        :default-active="activeMenu"
        router
        background-color="#12263a"
        text-color="#c8d2dc"
        active-text-color="#ffffff"
        style="border-right:none"
      >
        <el-menu-item index="/dashboard"><el-icon><DataLine /></el-icon><span>总览</span></el-menu-item>
        <el-menu-item index="/samples"><el-icon><Folder /></el-icon><span>样本库</span></el-menu-item>
        <el-menu-item index="/iocs"><el-icon><Aim /></el-icon><span>威胁情报</span></el-menu-item>
        <el-menu-item index="/reports"><el-icon><Document /></el-icon><span>分析报告</span></el-menu-item>
        <el-menu-item index="/rules"><el-icon><SetUp /></el-icon><span>检测规则</span></el-menu-item>
        <el-menu-item v-if="store.has('user:manage')" index="/users"><el-icon><User /></el-icon><span>用户权限</span></el-menu-item>
        <el-menu-item v-if="store.has('audit:read')" index="/audit"><el-icon><List /></el-icon><span>审计日志</span></el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="topbar">
        <div class="crumb">{{ route.meta.title || '' }}</div>
        <div class="right">
          <el-tag size="small" type="info" effect="dark">沙箱: {{ sandboxDriver }}</el-tag>
          <el-dropdown @command="onCommand">
            <span class="user">
              <el-icon><UserFilled /></el-icon>
              {{ store.user?.display_name || store.user?.username }}
              <el-icon><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="logout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>
      <el-main style="background:#f5f7fa">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessageBox } from 'element-plus'
import { useUserStore } from '@/store/user'
import http from '@/api'

const route = useRoute()
const router = useRouter()
const store = useUserStore()
const sandboxDriver = ref('...')

const activeMenu = computed(() => '/' + (route.path.split('/')[1] || 'dashboard'))

onMounted(async () => {
  try {
    const health = await fetch('/health').then((r) => r.json())
    sandboxDriver.value = health.sandbox_driver
  } catch (e) {
    sandboxDriver.value = 'unknown'
  }
})

async function onCommand(cmd) {
  if (cmd === 'logout') {
    await ElMessageBox.confirm('确认退出登录？', '提示', { type: 'warning' })
    await store.logout()
    router.push('/login')
  }
}
</script>

<style scoped>
.brand { display: flex; gap: 10px; align-items: center; padding: 18px 16px; color: #fff; }
.brand .logo { font-size: 26px; }
.brand .name { font-weight: 700; font-size: 16px; }
.brand .desc { font-size: 11px; color: #8ba0b4; }
.topbar {
  background: #fff; border-bottom: 1px solid #e3e6ea;
  display: flex; align-items: center; justify-content: space-between;
}
.crumb { font-weight: 600; }
.right { display: flex; align-items: center; gap: 16px; }
.user { display: flex; align-items: center; gap: 4px; cursor: pointer; color: #2c5f8a; }
</style>
