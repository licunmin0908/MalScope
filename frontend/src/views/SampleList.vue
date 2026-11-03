<template>
  <div>
    <div class="page-header">
      <div>
        <h2>样本库</h2>
        <div class="sub">样本加密存储（AES-256）· 哈希去重 · 全流程隔离分析</div>
      </div>
      <div>
        <el-button v-if="store.has('sample:upload')" type="primary" :icon="Upload" @click="uploadVisible = true">
          上传样本
        </el-button>
        <el-button :icon="Refresh" @click="load">刷新</el-button>
      </div>
    </div>

    <div class="ms-card">
      <el-form :inline="true" @submit.prevent>
        <el-form-item label="关键字">
          <el-input v-model="query.keyword" placeholder="文件名 / MD5 / SHA256 / 家族" clearable style="width:280px" @keyup.enter="load" />
        </el-form-item>
        <el-form-item label="类型">
          <el-select v-model="query.file_kind" clearable style="width:130px">
            <el-option v-for="k in kinds" :key="k" :label="k.toUpperCase()" :value="k" />
          </el-select>
        </el-form-item>
        <el-form-item label="等级">
          <el-select v-model="query.threat_level" clearable style="width:130px">
            <el-option label="恶意" value="malicious" />
            <el-option label="可疑" value="suspicious" />
            <el-option label="无害" value="clean" />
            <el-option label="未知" value="unknown" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="load">查询</el-button>
          <el-button @click="reset">重置</el-button>
        </el-form-item>
      </el-form>

      <el-table :data="items" v-loading="loading" size="small" @row-click="(r) => $router.push(`/samples/${r.id}`)" style="cursor:pointer">
        <el-table-column prop="original_filename" label="文件名" min-width="200" show-overflow-tooltip />
        <el-table-column prop="file_kind" label="类型" width="80" />
        <el-table-column label="大小" width="100">
          <template #default="{ row }">{{ humanSize(row.file_size) }}</template>
        </el-table-column>
        <el-table-column label="MD5" width="140">
          <template #default="{ row }"><span class="mono">{{ row.md5.slice(0, 12) }}…</span></template>
        </el-table-column>
        <el-table-column label="等级" width="90">
          <template #default="{ row }">
            <el-tag size="small" :class="`tag-${row.threat_level}`" effect="dark">{{ levelCn(row.threat_level) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="risk_score" label="评分" width="70" />
        <el-table-column label="加壳" width="110">
          <template #default="{ row }"><span v-if="row.packer" class="sev-high">{{ row.packer }}</span><span v-else class="text-muted">-</span></template>
        </el-table-column>
        <el-table-column label="上传时间" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click.stop="$router.push(`/samples/${row.id}`)">详情</el-button>
            <el-button v-if="store.has('sample:delete')" link type="danger" size="small" @click.stop="remove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        style="margin-top:12px; justify-content:flex-end"
        layout="total, prev, pager, next"
        :total="total"
        :page-size="query.limit"
        :current-page="page"
        @current-change="onPage"
      />
    </div>

    <el-dialog v-model="uploadVisible" title="上传样本" width="520px">
      <el-upload drag :auto-upload="false" :limit="1" :on-change="onFileChange" :file-list="fileList">
        <el-icon class="el-icon--upload"><UploadFilled /></el-icon>
        <div class="el-upload__text">拖拽样本到此处，或<em>点击选择文件</em></div>
        <template #tip>
          <div class="text-muted" style="margin-top:8px">
            仅用于安全研究；平台会对压缩包做压缩炸弹校验，样本加密后隔离存储，平台自身不执行样本。
          </div>
        </template>
      </el-upload>
      <el-input v-model="description" type="textarea" :rows="2" placeholder="样本说明（可选）" style="margin-top:12px" />
      <template #footer>
        <el-button @click="uploadVisible = false">取消</el-button>
        <el-button type="primary" :loading="uploading" @click="doUpload">上传</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { Upload, UploadFilled, Refresh } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { sampleApi } from '@/api'
import { useUserStore } from '@/store/user'

const store = useUserStore()
const kinds = ['pe', 'elf', 'office', 'pdf', 'script', 'archive', 'unknown']
const items = ref([])
const total = ref(0)
const page = ref(1)
const loading = ref(false)
const query = reactive({ keyword: '', file_kind: '', threat_level: '', limit: 20 })
const uploadVisible = ref(false)
const uploading = ref(false)
const fileList = ref([])
const selectedFile = ref(null)
const description = ref('')

const levelCn = (l) => ({ malicious: '恶意', suspicious: '可疑', clean: '无害', unknown: '未知' }[l] || l)
const fmt = (t) => (t ? new Date(t).toLocaleString('zh-CN') : '-')
const humanSize = (n) => {
  if (!n) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB']
  let i = 0
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ }
  return n.toFixed(1) + ' ' + u[i]
}

async function load() {
  loading.value = true
  try {
    const res = await sampleApi.list({ ...query, offset: (page.value - 1) * query.limit })
    items.value = res.items
    total.value = res.total
  } finally {
    loading.value = false
  }
}
function reset() {
  query.keyword = ''; query.file_kind = ''; query.threat_level = ''
  page.value = 1
  load()
}
function onPage(p) { page.value = p; load() }

function onFileChange(file) {
  selectedFile.value = file.raw
  fileList.value = [file]
}
async function doUpload() {
  if (!selectedFile.value) { ElMessage.warning('请选择文件'); return }
  const fd = new FormData()
  fd.append('file', selectedFile.value)
  if (description.value) fd.append('description', description.value)
  uploading.value = true
  try {
    const sample = await sampleApi.upload(fd)
    ElMessage.success('上传成功（如哈希已存在则自动去重）')
    uploadVisible.value = false
    fileList.value = []; selectedFile.value = null; description.value = ''
    await load()
  } finally {
    uploading.value = false
  }
}
async function remove(row) {
  await ElMessageBox.confirm(`确认删除样本「${row.original_filename}」？该操作为不可逆的敏感操作。`, '警告', { type: 'warning' })
  await sampleApi.remove(row.id)
  ElMessage.success('已删除')
  load()
}
onMounted(load)
</script>
