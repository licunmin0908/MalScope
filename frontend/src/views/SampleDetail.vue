<template>
  <div v-loading="loading">
    <div class="page-header">
      <div>
        <h2>{{ sample.original_filename || '样本详情' }}</h2>
        <div class="sub">
          样本 ID：<span class="mono">{{ sample.id }}</span>
        </div>
      </div>
      <div>
        <el-button :icon="Back" @click="$router.push('/samples')">返回</el-button>
        <el-button v-if="store.has('analysis:run')" :icon="Cpu" :loading="running" @click="runAnalysis('static')">静态分析</el-button>
        <el-button v-if="store.has('sandbox:run')" :icon="VideoPlay" :loading="running" @click="runAnalysis('dynamic')">动态沙箱分析</el-button>
        <el-button v-if="store.has('analysis:run')" type="primary" :icon="MagicStick" :loading="running" @click="runAnalysis('full')">完整分析</el-button>
        <el-dropdown @command="genReport" style="margin-left:8px">
          <el-button :icon="Document" :disabled="!store.has('report:generate')">生成报告<el-icon><ArrowDown /></el-icon></el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="html">HTML 报告</el-dropdown-item>
              <el-dropdown-item command="pdf">PDF 报告</el-dropdown-item>
              <el-dropdown-item command="json">JSON 报告</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <el-button v-if="store.has('sample:download')" :icon="Download" @click="download">下载样本</el-button>
      </div>
    </div>

    <el-alert v-if="currentTask" :title="`分析任务：${currentTask.stage || ''}（${currentTask.status}）`"
              :type="taskType(currentTask.status)" :closable="false" style="margin-bottom:14px">
      <el-progress :percentage="currentTask.progress" :status="currentTask.status === 'failed' ? 'exception' : undefined" />
    </el-alert>

    <div class="stat-grid">
      <div class="stat-card">
        <div class="num"><el-tag :class="`tag-${sample.threat_level}`" effect="dark" size="large">{{ levelCn(sample.threat_level) }}</el-tag></div>
        <div class="lbl">危害等级</div>
      </div>
      <div class="stat-card"><div class="num">{{ sample.risk_score }}</div><div class="lbl">综合风险评分</div></div>
      <div class="stat-card"><div class="num">{{ (sample.file_size / 1024).toFixed(1) }} KB</div><div class="lbl">文件大小</div></div>
      <div class="stat-card"><div class="num">{{ (sample.file_kind || '').toUpperCase() }}</div><div class="lbl">文件类型</div></div>
      <div class="stat-card"><div class="num">{{ sample.entropy?.toFixed?.(2) ?? sample.entropy }}</div><div class="lbl">文件熵</div></div>
      <div class="stat-card"><div class="num">{{ sample.packer || '未加壳' }}</div><div class="lbl">加壳检测</div></div>
    </div>

    <el-tabs v-model="tab">
      <el-tab-pane label="概览" name="overview">
        <div class="ms-card">
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="MD5"><span class="mono">{{ sample.md5 }}</span></el-descriptions-item>
            <el-descriptions-item label="CRC32"><span class="mono">{{ sample.crc32 || '-' }}</span></el-descriptions-item>
            <el-descriptions-item label="SHA1"><span class="mono">{{ sample.sha1 }}</span></el-descriptions-item>
            <el-descriptions-item label="SHA256"><span class="mono">{{ sample.sha256 }}</span></el-descriptions-item>
            <el-descriptions-item label="SSDEEP"><span class="mono">{{ sample.ssdeep || '-' }}</span></el-descriptions-item>
            <el-descriptions-item label="imphash"><span class="mono">{{ sample.imphash || '-' }}</span></el-descriptions-item>
            <el-descriptions-item label="数字签名">
              <el-tag size="small" :type="sample.is_signed ? 'success' : 'info'">{{ sample.is_signed ? '已签名' : '未签名' }}</el-tag>
              <span class="text-muted" style="margin-left:6px">{{ sample.signature_subject || '' }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="家族标注">{{ sample.family || '未标注' }}</el-descriptions-item>
            <el-descriptions-item label="上传时间">{{ fmt(sample.created_at) }}</el-descriptions-item>
            <el-descriptions-item label="威胁等级判定">
              <el-tag size="small" :class="`tag-${sample.threat_level}`" effect="dark">{{ levelCn(sample.threat_level) }}</el-tag>
            </el-descriptions-item>
          </el-descriptions>
          <el-form inline style="margin-top:14px" v-if="store.has('sample:upload')">
            <el-form-item label="家族">
              <el-input v-model="editForm.family" size="small" style="width:180px" />
            </el-form-item>
            <el-form-item label="说明">
              <el-input v-model="editForm.description" size="small" style="width:320px" />
            </el-form-item>
            <el-button size="small" type="primary" @click="saveMeta">保存标注</el-button>
          </el-form>
        </div>
      </el-tab-pane>

      <el-tab-pane label="静态分析" name="static">
        <el-empty v-if="!staticResult" description="暂无静态分析结果，请点击上方「静态分析」" />
        <template v-else>
          <div class="ms-card">
            <div class="chart-title">PE 头部与元数据</div>
            <el-descriptions :column="3" border size="small">
              <el-descriptions-item label="入口点"><span class="mono">{{ staticResult.entry_point || '-' }}</span></el-descriptions-item>
              <el-descriptions-item label="镜像基址"><span class="mono">{{ staticResult.image_base || '-' }}</span></el-descriptions-item>
              <el-descriptions-item label="编译时间">{{ staticResult.compile_timestamp || '未知' }}</el-descriptions-item>
              <el-descriptions-item label="加壳" :span="2">
                <span v-if="staticResult.packer_detected" class="sev-high">{{ staticResult.packer_name }}（置信度 {{ staticResult.packer_confidence }}）</span>
                <span v-else>未检出</span>
              </el-descriptions-item>
              <el-descriptions-item label="PDB 路径"><span class="mono">{{ staticResult.pdb_path || '无' }}</span></el-descriptions-item>
            </el-descriptions>
          </div>

          <div class="ms-card">
            <div class="chart-title">区段分析与熵值</div>
            <v-chart :option="entropyOption" style="height:240px" autoresize />
            <el-table :data="staticResult.sections" size="small" style="margin-top:10px">
              <el-table-column prop="name" label="名称" width="100" />
              <el-table-column label="虚拟地址" width="110"><template #default="{ row }"><span class="mono">{{ hex(row.virtual_address) }}</span></template></el-table-column>
              <el-table-column prop="virtual_size" label="虚拟大小" width="100" />
              <el-table-column prop="raw_size" label="原始大小" width="100" />
              <el-table-column prop="entropy" label="熵" width="80" />
              <el-table-column label="属性" width="120">
                <template #default="{ row }">
                  <span class="section-flags">
                    <span v-for="f in row.flags" :key="f" :class="{ rwx: f === 'X' && row.flags.includes('W') }">{{ f }} </span>
                  </span>
                </template>
              </el-table-column>
              <el-table-column label="可疑" min-width="220">
                <template #default="{ row }">
                  <span v-if="row.is_suspicious" class="sev-high">{{ row.suspicion_reason }}</span>
                </template>
              </el-table-column>
            </el-table>
          </div>

          <div class="ms-card">
            <div class="chart-title">可疑特征（{{ (staticResult.suspicious_features || []).length }}）</div>
            <el-table :data="staticResult.suspicious_features || []" size="small">
              <el-table-column prop="name" label="特征" width="220" />
              <el-table-column label="级别" width="90">
                <template #default="{ row }"><span :class="`sev-${row.severity}`">{{ sevCn(row.severity) }}</span></template>
              </el-table-column>
              <el-table-column prop="description" label="说明" min-width="320" />
              <el-table-column prop="attack" label="ATT&CK" width="110" />
            </el-table>
          </div>

          <div class="ms-card">
            <div class="chart-title">导入表风险分类</div>
            <el-row :gutter="12">
              <el-col v-for="(v, k) in (staticResult.api_risk_summary || {})" :key="k" :span="8" style="margin-bottom:10px">
                <el-card shadow="never" body-style="padding:10px 12px">
                  <div :class="`sev-${v.level}`" style="font-weight:600">{{ k }}</div>
                  <div class="text-muted" style="margin:4px 0">{{ v.description }}</div>
                  <div class="mono" style="max-height:70px; overflow:auto">{{ (v.apis || []).join(', ') }}</div>
                </el-card>
              </el-col>
            </el-row>
            <el-table :data="staticResult.imports.filter(i => i.risk_level)" size="small" max-height="320" style="margin-top:10px">
              <el-table-column prop="dll" label="DLL" width="180" />
              <el-table-column prop="function" label="函数" width="220" />
              <el-table-column prop="risk_category" label="风险类别" width="180" />
              <el-table-column label="级别" width="90">
                <template #default="{ row }"><span :class="`sev-${row.risk_level}`">{{ sevCn(row.risk_level) }}</span></template>
              </el-table-column>
              <el-table-column prop="description" label="说明" min-width="260" />
            </el-table>
          </div>

          <div class="ms-card">
            <div class="chart-title">YARA 命中（{{ (staticResult.yara_matches || []).length }}）</div>
            <el-table :data="staticResult.yara_matches || []" size="small">
              <el-table-column prop="rule_name" label="规则" width="240" />
              <el-table-column prop="namespace" label="命名空间" width="140" />
              <el-table-column prop="description" label="描述" min-width="280" />
              <el-table-column prop="severity" label="级别" width="90" />
            </el-table>
          </div>

          <div class="ms-card">
            <div class="chart-title">提取字符串（{{ (staticResult.strings || []).length }}）</div>
            <el-radio-group v-model="stringFilter" size="small" style="margin-bottom:10px">
              <el-radio-button value="">全部</el-radio-button>
              <el-radio-button value="url">URL</el-radio-button>
              <el-radio-button value="ipv4">IP</el-radio-button>
              <el-radio-button value="domain">域名</el-radio-button>
              <el-radio-button value="registry_key">注册表</el-radio-button>
              <el-radio-button value="cmdline">命令行</el-radio-button>
              <el-radio-button value="mutex">互斥体</el-radio-button>
            </el-radio-group>
            <el-table :data="filteredStrings" size="small" max-height="360">
              <el-table-column label="值" min-width="420">
                <template #default="{ row }"><span class="mono">{{ row.value }}</span></template>
              </el-table-column>
              <el-table-column prop="category" label="类别" width="130" />
              <el-table-column prop="encoding" label="编码" width="100" />
              <el-table-column label="级别" width="90">
                <template #default="{ row }"><span :class="`sev-${row.risk_level}`">{{ sevCn(row.risk_level) }}</span></template>
              </el-table-column>
            </el-table>
          </div>
        </template>
      </el-tab-pane>

      <el-tab-pane label="动态分析" name="dynamic">
        <el-empty v-if="!dynamicResult" description="暂无动态沙箱结果，请点击「动态沙箱分析」" />
        <template v-else>
          <div class="ms-card">
            <el-descriptions :column="4" border size="small">
              <el-descriptions-item label="沙箱驱动">{{ dynamicResult.sandbox_driver }}</el-descriptions-item>
              <el-descriptions-item label="虚拟机">{{ dynamicResult.vm_name || '-' }}</el-descriptions-item>
              <el-descriptions-item label="客户机">{{ dynamicResult.guest_os || '-' }}</el-descriptions-item>
              <el-descriptions-item label="运行时长">{{ dynamicResult.duration_sec }} s</el-descriptions-item>
              <el-descriptions-item label="行为判定">
                <el-tag size="small" :class="`tag-${dynamicResult.verdict}`" effect="dark">{{ levelCn(dynamicResult.verdict) }}</el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="动态风险分">{{ dynamicResult.risk_score }}/100</el-descriptions-item>
              <el-descriptions-item label="反分析检测">
                <el-tag size="small" :type="dynamicResult.anti_analysis_detected ? 'danger' : 'info'">
                  {{ dynamicResult.anti_analysis_detected ? '已检测到' : '未检测到' }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="快照">{{ dynamicResult.snapshot || '-' }}</el-descriptions-item>
            </el-descriptions>
          </div>

          <div class="stat-grid" v-if="dynamicResult.behavior_summary">
            <div class="stat-card"><div class="num">{{ dynamicResult.behavior_summary.process_count }}</div><div class="lbl">进程</div></div>
            <div class="stat-card"><div class="num">{{ dynamicResult.behavior_summary.file_event_count }}</div><div class="lbl">文件操作</div></div>
            <div class="stat-card"><div class="num">{{ dynamicResult.behavior_summary.registry_event_count }}</div><div class="lbl">注册表操作</div></div>
            <div class="stat-card"><div class="num" style="color:var(--ms-mal)">{{ dynamicResult.behavior_summary.c2_count }}</div><div class="lbl">C2 外联</div></div>
            <div class="stat-card"><div class="num" style="color:var(--ms-mal)">{{ dynamicResult.behavior_summary.ransomware_files }}</div><div class="lbl">勒索文件</div></div>
            <div class="stat-card"><div class="num">{{ dynamicResult.behavior_summary.dropped_file_count }}</div><div class="lbl">释放文件</div></div>
          </div>

          <div class="ms-card">
            <div class="chart-title">MITRE ATT&CK 技术映射</div>
            <el-tag v-for="t in dynamicResult.attck_techniques || []" :key="t.id" type="danger" effect="plain" style="margin:0 8px 8px 0">
              {{ t.id }} · {{ t.name }}
            </el-tag>
            <el-empty v-if="!(dynamicResult.attck_techniques || []).length" description="未映射到 ATT&CK 技术" :image-size="60" />
          </div>

          <div class="ms-card">
            <div class="chart-title">反逃逸 / 反分析事件</div>
            <el-alert v-for="(e, i) in dynamicResult.evasion_events || []" :key="i" :title="`${e.type}：${e.detail}`"
                      type="warning" :closable="false" style="margin-bottom:6px" />
            <el-empty v-if="!(dynamicResult.evasion_events || []).length" description="未检测到反分析行为" :image-size="50" />
          </div>

          <div class="ms-card">
            <div class="chart-title">网络行为与 C2 外联</div>
            <el-table :data="dynamicResult.network_flows || []" size="small" max-height="340">
              <el-table-column label="时间" width="170"><template #default="{ row }">{{ fmt(row.timestamp) }}</template></el-table-column>
              <el-table-column prop="protocol" label="协议" width="80" />
              <el-table-column label="目的" width="180"><template #default="{ row }">{{ row.dst_ip }}{{ row.dst_port ? ':' + row.dst_port : '' }}</template></el-table-column>
              <el-table-column label="域名/SNI/DNS" min-width="180"><template #default="{ row }">{{ row.domain || row.tls_sni || row.dns_query }}</template></el-table-column>
              <el-table-column prop="url" label="URL" min-width="200" show-overflow-tooltip />
              <el-table-column label="C2" width="140">
                <template #default="{ row }">
                  <el-tag v-if="row.is_c2" size="small" type="danger">{{ row.c2_confidence }}%</el-tag>
                  <span v-else class="text-muted">-</span>
                </template>
              </el-table-column>
            </el-table>
          </div>

          <div class="ms-card">
            <div class="chart-title">进程树</div>
            <el-table :data="dynamicResult.processes || []" size="small" max-height="300">
              <el-table-column prop="pid" label="PID" width="80" />
              <el-table-column prop="ppid" label="PPID" width="80" />
              <el-table-column prop="name" label="进程名" width="160" />
              <el-table-column prop="cmdline" label="命令行" min-width="320" show-overflow-tooltip />
              <el-table-column prop="user" label="用户" width="140" />
              <el-table-column label="注入" width="70"><template #default="{ row }"><el-tag v-if="row.is_injected" size="small" type="danger">是</el-tag></template></el-table-column>
            </el-table>
          </div>

          <div class="ms-card">
            <div class="chart-title">文件行为</div>
            <el-table :data="dynamicResult.file_events || []" size="small" max-height="280">
              <el-table-column label="时间" width="170"><template #default="{ row }">{{ fmt(row.timestamp) }}</template></el-table-column>
              <el-table-column prop="action" label="动作" width="90" />
              <el-table-column prop="path" label="路径" min-width="320" show-overflow-tooltip />
              <el-table-column prop="new_path" label="新路径" min-width="160" show-overflow-tooltip />
              <el-table-column label="标记" width="150">
                <template #default="{ row }">
                  <el-tag v-if="row.is_ransomware" size="small" type="danger">勒索</el-tag>
                  <el-tag v-if="row.is_autorun" size="small" type="warning" style="margin-left:4px">自启动</el-tag>
                </template>
              </el-table-column>
            </el-table>
          </div>

          <div class="ms-card">
            <div class="chart-title">注册表行为</div>
            <el-table :data="dynamicResult.registry_events || []" size="small" max-height="280">
              <el-table-column label="时间" width="170"><template #default="{ row }">{{ fmt(row.timestamp) }}</template></el-table-column>
              <el-table-column prop="action" label="动作" width="80" />
              <el-table-column prop="key_path" label="键路径" min-width="320" show-overflow-tooltip />
              <el-table-column label="值" min-width="200"><template #default="{ row }">{{ row.value_name }} = {{ row.value_data }}</template></el-table-column>
              <el-table-column label="持久化" width="90"><template #default="{ row }"><el-tag v-if="row.is_persistence" size="small" type="danger">是</el-tag></template></el-table-column>
            </el-table>
          </div>

          <div class="ms-card">
            <div class="chart-title">行为时间线</div>
            <el-timeline>
              <el-timeline-item v-for="(e, i) in (dynamicResult.events || []).slice(0, 120)" :key="i"
                                :timestamp="fmt(e.timestamp)" :type="tlType(e.severity)" placement="top">
                <span :class="`sev-${e.severity}`">[{{ e.category }}] {{ e.action }}</span>
                <span class="mono" style="margin-left:8px">{{ e.object }}</span>
                <el-tag v-if="e.attck_technique_id" size="small" type="danger" effect="plain" style="margin-left:8px">{{ e.attck_technique_id }}</el-tag>
              </el-timeline-item>
            </el-timeline>
          </div>
        </template>
      </el-tab-pane>

      <el-tab-pane label="威胁指标 (IOC)" name="ioc">
        <div class="ms-card">
          <div style="margin-bottom:10px">
            <el-button v-if="store.has('ioc:export')" size="small" @click="exportIocs('csv')">导出 CSV</el-button>
            <el-button v-if="store.has('ioc:export')" size="small" @click="exportIocs('json')">导出 JSON</el-button>
            <el-button v-if="store.has('ioc:export')" size="small" @click="exportIocs('stix')">导出 STIX</el-button>
            <el-button v-if="store.has('ioc:export')" size="small" @click="exportIocs('openioc')">导出 OpenIOC</el-button>
          </div>
          <el-table :data="iocs" size="small">
            <el-table-column prop="ioc_type" label="类型" width="110" />
            <el-table-column label="值" min-width="360"><template #default="{ row }"><span class="mono">{{ row.value }}</span></template></el-table-column>
            <el-table-column prop="source" label="来源" width="90" />
            <el-table-column prop="confidence" label="置信度" width="90" />
            <el-table-column label="威胁分" width="140">
              <template #default="{ row }">
                <el-progress :percentage="row.threat_score" :stroke-width="10"
                             :color="row.threat_score >= 70 ? '#c0392b' : (row.threat_score >= 40 ? '#e67e22' : '#27ae60')" />
              </template>
            </el-table-column>
            <el-table-column prop="context" label="上下文" min-width="200" show-overflow-tooltip />
          </el-table>
        </div>
      </el-tab-pane>

      <el-tab-pane label="同源关联" name="similar">
        <div class="ms-card">
          <el-table :data="similar" size="small" v-loading="similarLoading">
            <el-table-column label="样本" min-width="240">
              <template #default="{ row }">
                <el-link type="primary" @click="$router.push(`/samples/${row.sample.id}`)">{{ row.sample.original_filename }}</el-link>
              </template>
            </el-table-column>
            <el-table-column prop="sample.md5" label="MD5" width="150" />
            <el-table-column label="相似度" width="110">
              <template #default="{ row }"><el-tag :type="row.similarity >= 80 ? 'danger' : 'warning'">{{ row.similarity }}%</el-tag></template>
            </el-table-column>
            <el-table-column prop="reason" label="依据" min-width="260" />
          </el-table>
        </div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { Back, Download, Document, ArrowDown, Cpu, VideoPlay, MagicStick } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import VChart from 'vue-echarts'
import { analysisApi, iocApi, reportApi, sampleApi } from '@/api'
import { useUserStore } from '@/store/user'

const route = useRoute()
const store = useUserStore()
const sampleId = route.params.id

const loading = ref(false)
const sample = ref({})
const staticResult = ref(null)
const dynamicResult = ref(null)
const iocs = ref([])
const similar = ref([])
const similarLoading = ref(false)
const tab = ref('overview')
const running = ref(false)
const currentTask = ref(null)
const stringFilter = ref('')
const editForm = reactive({ family: '', description: '' })
let pollTimer = null

const levelCn = (l) => ({ malicious: '恶意', suspicious: '可疑', clean: '无害', unknown: '未知' }[l] || l)
const sevCn = (s) => ({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }[s] || s)
const fmt = (t) => (t ? new Date(t).toLocaleString('zh-CN') : '-')
const hex = (n) => '0x' + (n >>> 0).toString(16)
const tlType = (s) => ({ critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[s] || 'primary')
const taskType = (s) => ({ success: 'success', failed: 'error', running: 'info', pending: 'info' }[s] || 'info')

const filteredStrings = computed(() => {
  const list = staticResult.value?.strings || []
  return stringFilter.value ? list.filter((s) => s.category === stringFilter.value) : list.slice(0, 300)
})

const entropyOption = computed(() => {
  const secs = staticResult.value?.sections || []
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: 50, right: 20, top: 20, bottom: 30 },
    xAxis: { type: 'category', data: secs.map((s) => s.name || '(空)'), axisLabel: { fontSize: 11 } },
    yAxis: { type: 'value', max: 8, name: '熵' },
    series: [{
      type: 'bar', data: secs.map((s) => ({
        value: s.entropy,
        itemStyle: { color: s.entropy >= 7.2 ? '#c0392b' : (s.is_rwx ? '#e67e22' : '#2c5f8a') }
      })),
      markLine: {
        data: [{ yAxis: 7.2, name: '高熵阈值' }],
        lineStyle: { color: '#c0392b' },
        label: { formatter: '高熵阈值 7.2', position: 'insideEndTop', fontSize: 10 }
      }
    }]
  }
})

async function load() {
  loading.value = true
  try {
    sample.value = await sampleApi.detail(sampleId)
    editForm.family = sample.value.family || ''
    editForm.description = sample.value.description || ''
    await Promise.allSettled([loadStatic(), loadDynamic(), loadIocs(), loadSimilar()])
  } finally {
    loading.value = false
  }
}
async function loadStatic() {
  try { staticResult.value = await analysisApi.staticResult(sampleId) } catch (e) { staticResult.value = null }
}
async function loadDynamic() {
  try { dynamicResult.value = await analysisApi.dynamicResult(sampleId) } catch (e) { dynamicResult.value = null }
}
async function loadIocs() {
  const res = await iocApi.list({ sample_id: sampleId, limit: 500 })
  iocs.value = res.items
}
async function loadSimilar() {
  similarLoading.value = true
  try { similar.value = (await sampleApi.similar(sampleId)).items } finally { similarLoading.value = false }
}

async function runAnalysis(type) {
  running.value = true
  try {
    currentTask.value = await analysisApi.run(sampleId, type)
    ElMessage.info('分析任务已提交，正在后台执行…')
    pollTask(currentTask.value.id)
  } catch (e) {
    running.value = false
  }
}

function pollTask(taskId) {
  clearInterval(pollTimer)
  pollTimer = setInterval(async () => {
    try {
      const t = await analysisApi.task(taskId)
      currentTask.value = t
      if (['success', 'failed', 'timeout', 'cancelled'].includes(t.status)) {
        clearInterval(pollTimer)
        running.value = false
        if (t.status === 'success') {
          ElMessage.success('分析完成')
          await load()
        } else {
          ElMessage.error('分析失败：' + (t.error_message || t.status))
        }
      }
    } catch (e) {
      clearInterval(pollTimer)
      running.value = false
    }
  }, 1500)
}

async function genReport(format) {
  const report = await reportApi.generate(sampleId, format)
  ElMessage.success('报告已生成')
  window.open(reportApi.previewUrl(report.id), '_blank')
}
async function download() {
  await ElMessageBox.confirm('样本下载属敏感操作，需二次授权确认。请确认你处于隔离环境并遵守样本处置规范。', '二次授权', { type: 'warning' })
  const blob = await sampleApi.download(sampleId, true)
  saveBlob(blob, sample.value.original_filename)
}
async function exportIocs(format) {
  const blob = await iocApi.export({ format, sample_id: sampleId, min_score: 0 })
  saveBlob(blob, `iocs_${sampleId}.${format}`)
}
function saveBlob(blob, filename) {
  const url = URL.createObjectURL(new Blob([blob]))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
async function saveMeta() {
  await sampleApi.update(sampleId, { family: editForm.family, description: editForm.description })
  ElMessage.success('已保存')
}

watch(tab, (v) => {
  if (v === 'similar' && !similar.value.length) loadSimilar()
})

onMounted(load)
onUnmounted(() => clearInterval(pollTimer))
</script>
