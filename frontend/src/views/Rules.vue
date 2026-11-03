<template>
  <div>
    <div class="page-header">
      <div>
        <h2>检测规则库</h2>
        <div class="sub">YARA 恶意特征规则与加壳器特征签名库</div>
      </div>
      <el-button v-if="store.has('rule:manage')" type="primary" :icon="Plus" @click="dialog = true">新增 YARA 规则</el-button>
    </div>

    <el-tabs v-model="tab">
      <el-tab-pane label="YARA 规则" name="yara">
        <div class="ms-card">
          <el-table :data="rules" v-loading="loading" size="small">
            <el-table-column prop="name" label="规则名" width="260" />
            <el-table-column prop="description" label="描述" min-width="260" show-overflow-tooltip />
            <el-table-column prop="severity" label="级别" width="90" />
            <el-table-column label="来源" width="100">
              <template #default="{ row }"><el-tag size="small" :type="row.is_builtin ? 'info' : 'success'">{{ row.is_builtin ? '内置' : '自定义' }}</el-tag></template>
            </el-table-column>
            <el-table-column label="状态" width="100">
              <template #default="{ row }"><el-tag size="small" :type="row.is_enabled ? 'success' : 'info'">{{ row.is_enabled ? '启用' : '停用' }}</el-tag></template>
            </el-table-column>
            <el-table-column label="操作" width="150" fixed="right">
              <template #default="{ row }">
                <el-button v-if="store.has('rule:manage')" link type="primary" size="small" @click="toggle(row)">切换</el-button>
                <el-button v-if="store.has('rule:manage') && !row.is_builtin" link type="danger" size="small" @click="remove(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <el-tab-pane label="加壳器特征库" name="packer">
        <div class="ms-card">
          <el-table :data="packers" size="small">
            <el-table-column prop="name" label="名称" width="160" />
            <el-table-column prop="category" label="类别" width="120" />
            <el-table-column label="节区特征" min-width="240"><template #default="{ row }"><span class="mono">{{ (row.section_names || []).join(', ') }}</span></template></el-table-column>
            <el-table-column prop="description" label="描述" min-width="280" />
            <el-table-column prop="severity" label="级别" width="90" />
          </el-table>
        </div>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="dialog" title="新增 YARA 规则" width="640px">
      <el-form :model="form" label-width="90px">
        <el-form-item label="规则名"><el-input v-model="form.name" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="form.description" /></el-form-item>
        <el-form-item label="级别">
          <el-select v-model="form.severity" style="width:160px">
            <el-option v-for="s in ['info','low','medium','high','critical']" :key="s" :label="s" :value="s" />
          </el-select>
        </el-form-item>
        <el-form-item label="规则内容">
          <el-input v-model="form.rules_text" type="textarea" :rows="12" placeholder="rule Example { strings: $a = &quot;malware&quot; condition: $a }" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { Plus } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { ruleApi } from '@/api'
import { useUserStore } from '@/store/user'

const store = useUserStore()
const tab = ref('yara')
const rules = ref([])
const packers = ref([])
const loading = ref(false)
const dialog = ref(false)
const saving = ref(false)
const form = reactive({ name: '', description: '', severity: 'medium', rules_text: '' })

async function load() {
  loading.value = true
  try {
    ;[rules.value, packers.value] = await Promise.all([ruleApi.yaraList(), ruleApi.packers()])
  } finally {
    loading.value = false
  }
}
async function save() {
  saving.value = true
  try {
    await ruleApi.yaraCreate({ ...form, tags: [] })
    ElMessage.success('规则已创建')
    dialog.value = false
    form.name = ''; form.description = ''; form.rules_text = ''
    load()
  } finally {
    saving.value = false
  }
}
async function toggle(row) {
  await ruleApi.yaraToggle(row.id)
  load()
}
async function remove(row) {
  await ruleApi.yaraDelete(row.id)
  ElMessage.success('已删除')
  load()
}
onMounted(load)
</script>
