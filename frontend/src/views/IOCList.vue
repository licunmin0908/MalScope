<template>
  <div>
    <div class="page-header">
      <div>
        <h2>威胁情报 / IOC</h2>
        <div class="sub">从静态与动态分析结果自动提取的威胁指标，支持 STIX / OpenIOC 导出与 MISP 对接</div>
      </div>
      <div>
        <el-dropdown @command="exportIocs">
          <el-button v-if="store.has('ioc:export')" type="primary">导出<el-icon><ArrowDown /></el-icon></el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="csv">CSV</el-dropdown-item>
              <el-dropdown-item command="json">JSON</el-dropdown-item>
              <el-dropdown-item command="stix">STIX 2.1</el-dropdown-item>
              <el-dropdown-item command="openioc">OpenIOC</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </div>

    <div class="ms-card">
      <el-form :inline="true" @submit.prevent>
        <el-form-item label="类型">
          <el-select v-model="query.ioc_type" clearable style="width:150px">
            <el-option v-for="t in types" :key="t" :label="t" :value="t" />
          </el-select>
        </el-form-item>
        <el-form-item label="最低威胁分">
          <el-input-number v-model="query.min_score" :min="0" :max="100" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="load">查询</el-button>
        </el-form-item>
      </el-form>

      <el-table :data="items" v-loading="loading" size="small">
        <el-table-column prop="ioc_type" label="类型" width="110" />
        <el-table-column label="值" min-width="340"><template #default="{ row }"><span class="mono">{{ row.value }}</span></template></el-table-column>
        <el-table-column prop="source" label="来源" width="100" />
        <el-table-column prop="confidence" label="置信度" width="90" />
        <el-table-column label="威胁分" width="150">
          <template #default="{ row }">
            <el-progress :percentage="row.threat_score" :stroke-width="10"
                         :color="row.threat_score >= 70 ? '#c0392b' : (row.threat_score >= 40 ? '#e67e22' : '#27ae60')" />
          </template>
        </el-table-column>
        <el-table-column prop="context" label="上下文" min-width="200" show-overflow-tooltip />
        <el-table-column label="关联样本" width="120">
          <template #default="{ row }">
            <el-link v-if="row.sample_id" type="primary" @click="$router.push(`/samples/${row.sample_id}`)">查看</el-link>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination style="margin-top:12px; justify-content:flex-end" layout="total, prev, pager, next"
                     :total="total" :page-size="query.limit" :current-page="page" @current-change="onPage" />
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ArrowDown } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { iocApi } from '@/api'
import { useUserStore } from '@/store/user'

const store = useUserStore()
const types = ['md5', 'sha1', 'sha256', 'ssdeep', 'ip', 'domain', 'url', 'c2', 'email', 'registry', 'filepath', 'mutex', 'useragent', 'certificate', 'yara']
const items = ref([])
const total = ref(0)
const page = ref(1)
const loading = ref(false)
const query = reactive({ ioc_type: '', min_score: 0, limit: 50 })

async function load() {
  loading.value = true
  try {
    const res = await iocApi.list({ ...query, offset: (page.value - 1) * query.limit })
    items.value = res.items
    total.value = res.total
  } finally {
    loading.value = false
  }
}
function onPage(p) { page.value = p; load() }
async function exportIocs(format) {
  const blob = await iocApi.export({ format, ioc_type: query.ioc_type || null, min_score: query.min_score })
  const url = URL.createObjectURL(new Blob([blob]))
  const a = document.createElement('a')
  a.href = url
  a.download = `malscope_iocs.${format}`
  a.click()
  URL.revokeObjectURL(url)
  ElMessage.success('已导出')
}
onMounted(load)
</script>
