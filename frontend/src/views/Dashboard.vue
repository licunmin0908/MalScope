<template>
  <div>
    <div class="page-header">
      <div>
        <h2>安全态势总览</h2>
        <div class="sub">样本规模、危害分布、ATT&CK 技术与最新威胁指标</div>
      </div>
      <el-button :icon="Refresh" @click="load">刷新</el-button>
    </div>

    <div class="stat-grid">
      <div class="stat-card"><div class="num">{{ stats.total_samples }}</div><div class="lbl">样本总数</div></div>
      <div class="stat-card"><div class="num" style="color:var(--ms-mal)">{{ stats.malicious_samples }}</div><div class="lbl">恶意样本</div></div>
      <div class="stat-card"><div class="num" style="color:var(--ms-sus)">{{ stats.suspicious_samples }}</div><div class="lbl">可疑样本</div></div>
      <div class="stat-card"><div class="num">{{ stats.total_tasks }}</div><div class="lbl">分析任务</div></div>
      <div class="stat-card"><div class="num">{{ stats.total_iocs }}</div><div class="lbl">威胁指标</div></div>
      <div class="stat-card"><div class="num" style="color:var(--ms-mal)">{{ stats.c2_iocs }}</div><div class="lbl">C2 地址</div></div>
    </div>

    <el-row :gutter="16">
      <el-col :span="8">
        <div class="ms-card">
          <div class="chart-title">危害等级分布</div>
          <v-chart :option="levelOption" style="height:260px" autoresize />
        </div>
      </el-col>
      <el-col :span="8">
        <div class="ms-card">
          <div class="chart-title">文件类型分布</div>
          <v-chart :option="kindOption" style="height:260px" autoresize />
        </div>
      </el-col>
      <el-col :span="8">
        <div class="ms-card">
          <div class="chart-title">ATT&CK 技术 TOP</div>
          <v-chart :option="attckOption" style="height:260px" autoresize />
        </div>
      </el-col>
    </el-row>

    <el-row :gutter="16">
      <el-col :span="14">
        <div class="ms-card">
          <div class="chart-title">最新样本</div>
          <el-table :data="stats.recent_samples" size="small" @row-click="openSample" style="cursor:pointer">
            <el-table-column prop="original_filename" label="文件名" show-overflow-tooltip />
            <el-table-column prop="file_kind" label="类型" width="80" />
            <el-table-column label="等级" width="90">
              <template #default="{ row }">
                <el-tag size="small" :class="`tag-${row.threat_level}`" effect="dark">{{ levelCn(row.threat_level) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="risk_score" label="评分" width="70" />
          </el-table>
        </div>
      </el-col>
      <el-col :span="10">
        <div class="ms-card">
          <div class="chart-title">高危威胁指标</div>
          <el-table :data="stats.top_iocs" size="small">
            <el-table-column prop="ioc_type" label="类型" width="90" />
            <el-table-column prop="value" label="值" show-overflow-tooltip />
            <el-table-column prop="threat_score" label="威胁分" width="80" />
          </el-table>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Refresh } from '@element-plus/icons-vue'
import VChart from 'vue-echarts'
import { dashboardApi } from '@/api'

const router = useRouter()
const stats = ref({
  total_samples: 0, malicious_samples: 0, suspicious_samples: 0, clean_samples: 0,
  total_tasks: 0, running_tasks: 0, total_iocs: 0, c2_iocs: 0,
  by_file_kind: {}, by_threat_level: {}, recent_samples: [], top_iocs: [], attck_distribution: []
})

const levelCn = (l) => ({ malicious: '恶意', suspicious: '可疑', clean: '无害', unknown: '未知' }[l] || l)

const levelOption = computed(() => {
  const colors = { malicious: '#c0392b', suspicious: '#e67e22', clean: '#27ae60', unknown: '#7f8c8d' }
  const data = Object.entries(stats.value.by_threat_level || {}).map(([k, v]) => ({
    name: levelCn(k), value: v, itemStyle: { color: colors[k] }
  }))
  return {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, textStyle: { fontSize: 11 } },
    series: [{ type: 'pie', radius: ['42%', '68%'], data, label: { fontSize: 11 } }]
  }
})

const kindOption = computed(() => {
  const data = Object.entries(stats.value.by_file_kind || {}).map(([k, v]) => ({ name: k.toUpperCase(), value: v }))
  return {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie', roseType: 'radius', radius: ['25%', '68%'], data,
      label: { fontSize: 11 }
    }]
  }
})

const attckOption = computed(() => {
  const items = [...(stats.value.attck_distribution || [])].reverse()
  return {
    grid: { left: 140, right: 24, top: 10, bottom: 20 },
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'value', splitLine: { lineStyle: { color: '#eef1f4' } } },
    yAxis: {
      type: 'category',
      data: items.map((i) => (i.name.length > 18 ? i.name.slice(0, 18) + '…' : i.name)),
      axisLabel: { fontSize: 10, width: 132, overflow: 'truncate' }
    },
    series: [{ type: 'bar', data: items.map((i) => i.count), itemStyle: { color: '#2c5f8a' }, barWidth: 12 }]
  }
})

async function load() {
  stats.value = await dashboardApi.stats()
}
function openSample(row) {
  router.push(`/samples/${row.id}`)
}
onMounted(load)
</script>

<style scoped>
.chart-title { font-size: 13px; font-weight: 600; margin-bottom: 10px; }
</style>
