<template>
  <div>
    <div class="page-header">
      <div>
        <h2>用户与权限</h2>
        <div class="sub">基于 RBAC 的角色权限管理</div>
      </div>
      <el-button type="primary" :icon="Plus" @click="dialog = true">新增用户</el-button>
    </div>

    <div class="ms-card">
      <el-table :data="users" v-loading="loading" size="small">
        <el-table-column prop="username" label="用户名" width="140" />
        <el-table-column prop="display_name" label="姓名" width="140" />
        <el-table-column prop="email" label="邮箱" min-width="200" />
        <el-table-column label="角色" min-width="220">
          <template #default="{ row }">
            <el-tag v-for="r in row.roles" :key="r.id" size="small" style="margin-right:6px">{{ r.name }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }"><el-tag size="small" :type="row.is_active ? 'success' : 'info'">{{ row.is_active ? '启用' : '禁用' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="上次登录" width="170"><template #default="{ row }">{{ fmt(row.last_login_at) }}</template></el-table-column>
        <el-table-column label="操作" width="110" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="edit(row)">编辑</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="ms-card">
      <div class="chart-title">角色与权限矩阵</div>
      <el-table :data="roles" size="small">
        <el-table-column prop="name" label="角色" width="160" />
        <el-table-column prop="description" label="说明" min-width="240" />
        <el-table-column label="权限" min-width="420">
          <template #default="{ row }">
            <el-tag v-for="p in row.permissions" :key="p.id" size="small" effect="plain" style="margin:0 6px 6px 0">{{ p.name }}</el-tag>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="dialog" :title="form.id ? '编辑用户' : '新增用户'" width="520px">
      <el-form :model="form" label-width="80px">
        <el-form-item label="用户名"><el-input v-model="form.username" :disabled="!!form.id" /></el-form-item>
        <el-form-item label="姓名"><el-input v-model="form.display_name" /></el-form-item>
        <el-form-item label="邮箱"><el-input v-model="form.email" /></el-form-item>
        <el-form-item label="密码"><el-input v-model="form.password" type="password" show-password :placeholder="form.id ? '留空则不修改' : ''" /></el-form-item>
        <el-form-item label="角色">
          <el-select v-model="form.role_names" multiple style="width:100%">
            <el-option v-for="r in roles" :key="r.id" :label="r.name" :value="r.name" />
          </el-select>
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
import { userApi } from '@/api'

const users = ref([])
const roles = ref([])
const loading = ref(false)
const dialog = ref(false)
const saving = ref(false)
const form = reactive({ id: null, username: '', display_name: '', email: '', password: '', role_names: [] })

const fmt = (t) => (t ? new Date(t).toLocaleString('zh-CN') : '-')

async function load() {
  loading.value = true
  try {
    ;[users.value, roles.value] = await Promise.all([userApi.list(), userApi.roles()])
  } finally {
    loading.value = false
  }
}
function edit(row) {
  form.id = row.id
  form.username = row.username
  form.display_name = row.display_name
  form.email = row.email
  form.password = ''
  form.role_names = (row.roles || []).map((r) => r.name)
  dialog.value = true
}
async function save() {
  saving.value = true
  try {
    if (form.id) {
      const payload = { display_name: form.display_name, email: form.email, role_names: form.role_names }
      if (form.password) payload.password = form.password
      await userApi.update(form.id, payload)
    } else {
      await userApi.create({
        username: form.username, password: form.password, email: form.email,
        display_name: form.display_name, role_names: form.role_names
      })
    }
    ElMessage.success('已保存')
    dialog.value = false
    Object.assign(form, { id: null, username: '', display_name: '', email: '', password: '', role_names: [] })
    load()
  } finally {
    saving.value = false
  }
}
onMounted(load)
</script>
