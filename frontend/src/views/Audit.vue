<template>
  <div>
    <div class="page-header">
      <div>
        <h2>审计日志</h2>
        <div class="sub">记录样本上传、下载、分析、删除、登录等敏感操作，满足可追溯要求</div>
      </div>
    </div>

    <div class="ms-card">
      <el-form :inline="true" @submit.prevent>
        <el-form-item label="操作类型">
          <el-select v-model="query.action" clearable style="width:180px">
            <el-option v-for="a in actions" :key="a" :label="a" :value="a" />
          </el-select>
        </el-form-item>
        <el-form-item label="用户名">
          <el-input v-model="query.username" clearable style="width:160px" />
        </el-form-item>
        <el-button type="primary" @click="load">查询</el-button>
      </el-form>

      <el-table :data="items" v-loading="loading" size="small">
        <el-table-column label="时间" width="170"><template #default="{ row }">{{ fmt(row.created_at) }}</template></el-table-column>
        <el-table-column prop="username" label="用户" width="120" />
        <el-table-column prop="action" label="操作" width="150" />
        <el-table-column prop="resource_type" label="资源类型" width="110" />
        <el-table-column prop="resource_id" label="资源 ID" width="220" show-overflow-tooltip />
        <el-table-column label="结果" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="row.result === 'success' ? 'success' : 'danger'">{{ row.result }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="ip" label="来源 IP" width="140" />
        <el-table-column label="详情" min-width="180">
          <template #default="{ row }"><span class="mono">{{ row.detail ? JSON.stringify(row.detail) : '' }}</span></template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { auditApi } from '@/api'

const items = ref([])
const loading = ref(false)
const query = reactive({ action: '', username: '' })
const actions = ['login', 'logout', 'sample_upload', 'sample_download', 'sample_delete', 'analysis_run', 'ioc_export', 'report_generate', 'rule_create', 'user_create', 'user_update', 'misp_push']
const fmt = (t) => (t ? new Date(t).toLocaleString('zh-CN') : '-')

async function load() {
  loading.value = true
  try {
    items.value = await auditApi.list({ action: query.action || undefined, username: query.username || undefined, limit: 200 })
  } finally {
    loading.value = false
  }
}
onMounted(load)
</script>
