<template>
  <div>
    <div class="page-header">
      <div>
        <h2>分析报告</h2>
        <div class="sub">一键生成涵盖样本信息、静态分析、动态行为、IOC 与 ATT&CK 矩阵的安全研判报告</div>
      </div>
    </div>

    <div class="ms-card">
      <el-form :inline="true" @submit.prevent>
        <el-form-item label="按样本筛选">
          <el-input v-model="sampleFilter" placeholder="样本 ID" clearable style="width:280px" />
        </el-form-item>
        <el-button type="primary" @click="load">查询</el-button>
      </el-form>

      <el-table :data="items" v-loading="loading" size="small">
        <el-table-column prop="title" label="报告标题" min-width="280" show-overflow-tooltip />
        <el-table-column prop="format" label="格式" width="90" />
        <el-table-column label="大小" width="100"><template #default="{ row }">{{ (row.file_size / 1024).toFixed(1) }} KB</template></el-table-column>
        <el-table-column label="危害等级" width="100">
          <template #default="{ row }">
            <el-tag size="small" :class="`tag-${row.summary?.risk_level}`" effect="dark">{{ levelCn(row.summary?.risk_level) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="生成时间" width="170"><template #default="{ row }">{{ fmt(row.created_at) }}</template></el-table-column>
        <el-table-column label="操作" width="160" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="preview(row)">预览</el-button>
            <el-button link type="primary" size="small" @click="download(row)">下载</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { reportApi } from '@/api'

const items = ref([])
const loading = ref(false)
const sampleFilter = ref('')
const levelCn = (l) => ({ malicious: '恶意', suspicious: '可疑', clean: '无害', unknown: '未知' }[l] || '-')
const fmt = (t) => (t ? new Date(t).toLocaleString('zh-CN') : '-')

async function load() {
  loading.value = true
  try {
    const res = await reportApi.list({ sample_id: sampleFilter.value || undefined, limit: 100 })
    items.value = res.items
  } finally {
    loading.value = false
  }
}
function preview(row) { window.open(reportApi.previewUrl(row.id), '_blank') }
async function download(row) {
  const blob = await reportApi.download(row.id)
  const url = URL.createObjectURL(new Blob([blob]))
  const a = document.createElement('a')
  a.href = url
  a.download = `${row.title}.${row.format}`
  a.click()
  URL.revokeObjectURL(url)
}
onMounted(load)
</script>
