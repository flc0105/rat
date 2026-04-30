<template>
  <el-dialog
    v-model="visible"
    title="External Tool Manager"
    width="1180px"
    top="5vh"
    class="fixed-dialog external-tool-dialog"
    @closed="handleClosed"
  >
    <div class="external-tool-body" v-loading="loading">
      <div class="external-tool-toolbar">
        <div class="external-tool-toolbar-left">
          <el-button size="small" type="primary" plain :loading="loading" @click="loadCatalog">
            Refresh Catalog
          </el-button>
          <el-select v-model="sideFilter" size="small" class="external-tool-filter" placeholder="Side">
            <el-option label="All sides" value="" />
            <el-option label="Server" value="server" />
            <el-option label="Client" value="client" />
          </el-select>
          <el-select v-model="platformFilter" size="small" class="external-tool-filter" placeholder="Platform">
            <el-option label="All platforms" value="" />
            <el-option label="Current client" value="current" />
            <el-option label="Linux" value="linux" />
            <el-option label="macOS" value="mac" />
            <el-option label="Windows" value="win" />
            <el-option label="iOS" value="ios" />
          </el-select>
        </div>

        <div class="external-tool-toolbar-right">
          <el-input
            v-model="searchText"
            size="small"
            clearable
            class="external-tool-search"
            placeholder="Search external tools"
          />
        </div>
      </div>

      <div v-if="filteredItems.length" class="external-tool-list">
        <div
          v-for="item in filteredItems"
          :key="item.id"
          class="external-tool-card"
        >
          <div class="external-tool-card-header">
            <div class="external-tool-card-main">
              <div class="external-tool-title-row">
                <div class="external-tool-title" :title="item.display_name || item.id">
                  {{ item.display_name || item.id }}
                </div>
                <el-tag size="small" :type="item.side === 'server' ? 'success' : 'warning'">
                  {{ item.side || '-' }}
                </el-tag>
                <el-tag size="small" type="info">
                  {{ formatPlatforms(item.platforms) }}
                </el-tag>
                <el-tag v-if="item.version" size="small" type="info">
                  v{{ item.version }}
                </el-tag>
                <el-tag v-if="item.arch" size="small" type="info">
                  {{ item.arch }}
                </el-tag>
              </div>

              <div class="external-tool-desc" :title="item.description || ''">
                {{ item.description || 'No description' }}
              </div>

              <div class="external-tool-meta mono">
                <span>ID: {{ item.id }}</span>
                <span v-if="item.package?.filename">Package: {{ item.package.filename }}</span>
                <span v-if="item.package?.executable_rel_path">Exec: {{ item.package.executable_rel_path }}</span>
              </div>
            </div>

            <div class="external-tool-actions">
              <el-button size="small" plain @click="downloadTool(item)">
                Download Zip
              </el-button>

              <el-button
                v-if="item.side === 'server'"
                size="small"
                type="primary"
                plain
                :disabled="!isServerPlatformSupported(item)"
                @click="openStartDialog(item, 'server')"
              >
                Start Instance
              </el-button>

              <el-button
                v-if="item.side === 'server'"
                size="small"
                plain
                @click="loadServerInstances(item.id)"
              >
                Refresh Instances
              </el-button>

              <el-button
                v-if="item.side === 'client'"
                size="small"
                type="primary"
                plain
                :disabled="!selectedId || !isClientPlatformSupported(item)"
                @click="openStartDialog(item, 'client')"
              >
                Start Client Instance
              </el-button>

              <el-button
                v-if="item.side === 'client'"
                size="small"
                plain
                :disabled="!selectedId"
                @click="submitClientListInstances(item)"
              >
                List Client Instances
              </el-button>

              <el-dropdown
                v-if="item.side === 'client'"
                trigger="click"
                @command="command => openClientInstanceAction(item, command)"
              >
                <el-button size="small" plain :disabled="!selectedId">
                  Client Instance Action
                </el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="status">Status</el-dropdown-item>
                    <el-dropdown-item command="logs">Logs</el-dropdown-item>
                    <el-dropdown-item divided command="stop">Stop</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </div>
          </div>

          <div v-if="item.side === 'server'" class="external-tool-instances">
            <div class="external-tool-section-title">
              Server instances
            </div>
            <div v-if="serverInstances[item.id]?.length" class="external-tool-instance-list">
              <div
                v-for="instance in serverInstances[item.id]"
                :key="instance.instance_id"
                class="external-tool-instance-row"
              >
                <div class="external-tool-instance-main">
                  <el-tag size="small" :type="instance.running ? 'success' : (instance.status === 'stale' ? 'danger' : 'info')">
                    {{ instance.status || '-' }}
                  </el-tag>
                  <span class="mono instance-id">{{ instance.instance_id }}</span>
                  <span class="mono">pid={{ instance.pid || '-' }}</span>
                  <span v-if="instance.params?.bind_port" class="mono">bind={{ instance.params.bind_port }}</span>
                  <span v-if="instance.params?.remote_port" class="mono">remote={{ instance.params.remote_port }}</span>
                  <span class="mono muted">{{ instance.stdout || '' }}</span>
                </div>
                <div class="external-tool-instance-actions">
                  <el-button size="small" plain @click="loadServerInstanceStatus(item.id, instance.instance_id)">
                    Status
                  </el-button>
                  <el-button size="small" plain @click="openServerLogs(item.id, instance.instance_id)">
                    Logs
                  </el-button>
                  <el-button
                    size="small"
                    type="danger"
                    plain
                    :disabled="!instance.running && instance.status !== 'stale'"
                    @click="stopServerInstance(item.id, instance.instance_id)"
                  >
                    Stop
                  </el-button>
                </div>
              </div>
            </div>
            <div v-else class="external-tool-empty-inline">
              No server instances. Click Start Instance to create one.
            </div>
          </div>
        </div>
      </div>

      <div v-else class="external-tool-empty">
        {{ searchText ? 'No matching external tools' : 'No external tool meta files found' }}
      </div>
    </div>
  </el-dialog>

  <el-dialog
    v-model="startDialogVisible"
    :title="startDialogTitle"
    width="650px"
    append-to-body
    @closed="resetStartDialog"
  >
    <div v-if="pendingItem" class="external-tool-run-body">
      <div class="external-tool-run-summary">
        <div><strong>{{ pendingItem.display_name || pendingItem.id }}</strong></div>
        <div class="mono">{{ pendingItem.id }} / {{ pendingTargetSide }}</div>
        <div class="external-tool-param-help">
          The instance name isolates config, pid, state and logs. Multiple frpc instances should use different names.
        </div>
      </div>

      <el-form label-position="top" class="external-tool-param-form">
        <el-form-item
          v-for="param in pendingParams"
          :key="param.name"
          :label="formatParamLabel(param)"
        >
          <el-switch
            v-if="normalizeParamType(param.type) === 'boolean'"
            v-model="paramForm[param.name]"
          />

          <el-input-number
            v-else-if="normalizeParamType(param.type) === 'integer'"
            v-model="paramForm[param.name]"
            :min="param.min"
            :max="param.max"
            controls-position="right"
            class="external-tool-number"
          />

          <el-input
            v-else
            v-model="paramForm[param.name]"
            :placeholder="param.description || param.name"
            clearable
          />

          <div v-if="param.description" class="external-tool-param-help">
            {{ param.description }}
          </div>
        </el-form-item>

        <div v-if="!pendingParams.length" class="external-tool-empty small">
          This tool has no runtime params.
        </div>
      </el-form>
    </div>

    <template #footer>
      <el-button size="small" @click="startDialogVisible = false">Cancel</el-button>
      <el-button size="small" type="primary" :loading="submitting" @click="confirmStart">
        Start Instance
      </el-button>
    </template>
  </el-dialog>

  <el-dialog
    v-model="clientActionDialogVisible"
    :title="clientActionDialogTitle"
    width="520px"
    append-to-body
    @closed="resetClientActionDialog"
  >
    <div v-if="pendingClientActionItem" class="external-tool-run-body">
      <div class="external-tool-run-summary">
        <div><strong>{{ pendingClientActionItem.display_name || pendingClientActionItem.id }}</strong></div>
        <div class="mono">action={{ pendingClientAction }}</div>
      </div>
      <el-form label-position="top">
        <el-form-item label="Instance ID">
          <el-input v-model="clientActionInstanceId" placeholder="vite-8087" clearable />
          <div class="external-tool-param-help">
            Use the same value as Instance Name when you started this frpc/frps instance.
          </div>
        </el-form-item>
      </el-form>
    </div>
    <template #footer>
      <el-button size="small" @click="clientActionDialogVisible = false">Cancel</el-button>
      <el-button size="small" type="primary" :loading="submitting" @click="confirmClientInstanceAction">
        Submit
      </el-button>
    </template>
  </el-dialog>

  <el-dialog
    v-model="logDialogVisible"
    :title="logDialogTitle"
    width="900px"
    append-to-body
  >
    <pre class="external-tool-log-content">{{ logContent || 'No log content.' }}</pre>
    <template #footer>
      <el-button size="small" @click="logDialogVisible = false">Close</el-button>
    </template>
  </el-dialog>
</template>

<script>
import { ElMessage, ElMessageBox } from 'element-plus'

export default {
  name: 'ExternalToolManagerDialog',

  props: {
    selectedId: {
      type: [String, Number],
      default: '',
    },
    currentConnection: {
      type: Object,
      default: null,
    },
    getTabScopedHeaders: {
      type: Function,
      default: null,
    },
  },

  emits: [
    'append-output',
    'set-active-task',
  ],

  data() {
    return {
      visible: false,
      loading: false,
      submitting: false,
      items: [],
      serverInstances: {},
      searchText: '',
      sideFilter: '',
      platformFilter: '',
      startDialogVisible: false,
      pendingToolId: '',
      pendingTargetSide: '',
      paramForm: {},
      clientActionDialogVisible: false,
      pendingClientActionToolId: '',
      pendingClientAction: '',
      clientActionInstanceId: '',
      logDialogVisible: false,
      logDialogTitle: 'External Tool Logs',
      logContent: '',
    }
  },

  computed: {
    currentClientPlatform() {
      return this.normalizePlatform(
        this.currentConnection?.os_alias ||
        this.currentConnection?.os_type ||
        this.currentConnection?.platform ||
        this.currentConnection?.system ||
        '',
      )
    },

    filteredItems() {
      const keyword = String(this.searchText || '').trim().toLowerCase()
      const side = String(this.sideFilter || '').trim().toLowerCase()
      const platform = String(this.platformFilter || '').trim().toLowerCase()
      return (this.items || []).filter((item) => {
        if (side && item.side !== side) return false
        if (platform) {
          const target = platform === 'current' ? this.currentClientPlatform : platform
          if (target && !this.doesPlatformMatch(item, target)) return false
        }
        if (!keyword) return true
        const values = [
          item.id,
          item.name,
          item.display_name,
          item.description,
          item.package?.filename,
          item.package?.executable_rel_path,
          (item.tags || []).join(' '),
        ].map(value => String(value || '').toLowerCase())
        return values.some(value => value.includes(keyword))
      })
    },

    pendingItem() {
      const target = String(this.pendingToolId || '').trim()
      return (this.items || []).find(item => String(item.id || '').trim() === target) || null
    },

    pendingParams() {
      return Array.isArray(this.pendingItem?.params) ? this.pendingItem.params : []
    },

    startDialogTitle() {
      const item = this.pendingItem
      const name = item ? (item.display_name || item.id) : 'External Tool'
      const side = this.pendingTargetSide === 'server' ? 'Server' : 'Client'
      return `Start ${name} on ${side}`
    },

    pendingClientActionItem() {
      const target = String(this.pendingClientActionToolId || '').trim()
      return (this.items || []).find(item => String(item.id || '').trim() === target) || null
    },

    clientActionDialogTitle() {
      const item = this.pendingClientActionItem
      const name = item ? (item.display_name || item.id) : 'External Tool'
      return `${this.pendingClientAction || 'Action'} ${name} client instance`
    },
  },

  methods: {
    async open() {
      this.visible = true
      await this.loadCatalog()
    },

    isOpen() {
      return this.visible
    },

    async refreshIfOpen() {
      if (!this.visible) return
      await this.loadCatalog()
    },

    handleClosed() {
      this.resetStartDialog()
      this.resetClientActionDialog()
    },

    buildJsonHeaders(extra = {}) {
      if (typeof this.getTabScopedHeaders === 'function') {
        return this.getTabScopedHeaders(extra)
      }
      return extra
    },

    async loadCatalog() {
      this.loading = true
      try {
        const res = await fetch('/api/external-tools/catalog')
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load external tools')
        const catalog = json.data || {}
        this.items = Array.isArray(catalog.items) ? catalog.items : []
        await this.refreshVisibleServerInstances()
      } catch (e) {
        ElMessage.error(e.message || 'Failed to load external tools')
      } finally {
        this.loading = false
      }
    },

    async refreshVisibleServerInstances() {
      const serverItems = (this.items || []).filter(item => item.side === 'server')
      await Promise.all(serverItems.map(item => this.loadServerInstances(item.id, false)))
    },

    normalizePlatform(value) {
      const text = String(value || '').trim().toLowerCase()
      const aliases = {
        windows: 'win',
        win32: 'win',
        darwin: 'mac',
        macos: 'mac',
        osx: 'mac',
        linux: 'linux',
        ios: 'ios',
        common: '*',
        all: '*',
        '*': '*',
      }
      return aliases[text] || text
    },

    normalizePlatforms(platforms) {
      const source = Array.isArray(platforms)
        ? platforms
        : (typeof platforms === 'string' && platforms.trim() ? [platforms] : [])
      const result = []
      const seen = new Set()
      source.forEach((platform) => {
        const normalized = this.normalizePlatform(platform)
        if (!normalized || seen.has(normalized)) return
        seen.add(normalized)
        result.push(normalized)
      })
      return result.length ? result : ['*']
    },

    doesPlatformMatch(item, platform) {
      const target = this.normalizePlatform(platform)
      const platforms = this.normalizePlatforms(item?.platforms || item?.platform)
      if (!target || platforms.includes('*')) return true
      return platforms.includes(target)
    },

    isServerPlatformSupported(item) {
      return !!item
    },

    isClientPlatformSupported(item) {
      return this.doesPlatformMatch(item, this.currentClientPlatform)
    },

    formatPlatforms(platforms) {
      const normalized = this.normalizePlatforms(platforms)
      if (!normalized.length || normalized.includes('*')) return 'All platforms'
      return normalized.map((platform) => {
        if (platform === 'mac') return 'macOS'
        if (platform === 'win') return 'Windows'
        if (platform === 'linux') return 'Linux'
        if (platform === 'ios') return 'iOS'
        return platform
      }).join(', ')
    },

    normalizeParamType(type) {
      const value = String(type || 'string').trim().toLowerCase()
      if (value === 'int' || value === 'number') return 'integer'
      if (value === 'bool') return 'boolean'
      return value || 'string'
    },

    formatParamLabel(param) {
      const label = param.label || param.name
      const required = param.required ? ' *' : ''
      return `${label}${required}`
    },

    buildParamDefaults(item) {
      const form = {}
      for (const param of item?.params || []) {
        const name = String(param?.name || '').trim()
        if (!name) continue
        if (param.default !== undefined && param.default !== null) {
          form[name] = param.default
        } else if (this.normalizeParamType(param.type) === 'boolean') {
          form[name] = false
        } else {
          form[name] = ''
        }
      }
      return form
    },

    buildStartParams() {
      const params = {}
      for (const param of this.pendingParams || []) {
        const name = String(param?.name || '').trim()
        if (!name) continue
        const value = this.paramForm[name]
        if (param.required && (value === '' || value === undefined || value === null)) {
          throw new Error(`Param ${name} is required`)
        }
        params[name] = value
      }
      return params
    },

    deriveInstanceId(params) {
      const raw = params.instance_name || params.instance_id || (
        params.proxy_name && params.remote_port ? `${params.proxy_name}-${params.remote_port}` : ''
      ) || (params.bind_port ? `instance-${params.bind_port}` : 'default')
      return String(raw || 'default').trim().replace(/[^A-Za-z0-9_.-]+/g, '-').replace(/^[._-]+|[._-]+$/g, '') || 'default'
    },

    openStartDialog(item, side) {
      this.pendingToolId = String(item?.id || '').trim()
      this.pendingTargetSide = side
      this.paramForm = this.buildParamDefaults(item)
      this.startDialogVisible = true
    },

    resetStartDialog() {
      this.startDialogVisible = false
      this.submitting = false
      this.pendingToolId = ''
      this.pendingTargetSide = ''
      this.paramForm = {}
    },

    downloadTool(item) {
      const id = String(item?.id || '').trim()
      if (!id) return
      window.open(`/api/external-tools/${encodeURIComponent(id)}/download`, '_blank')
    },

    async confirmStart() {
      const item = this.pendingItem
      if (!item) {
        this.resetStartDialog()
        return
      }

      try {
        this.submitting = true
        const params = this.buildStartParams()
        const instanceId = this.deriveInstanceId(params)
        if (this.pendingTargetSide === 'server') {
          await this.startServerInstance(item, params, instanceId)
        } else {
          await this.startClientInstance(item, params, instanceId)
        }
        this.resetStartDialog()
      } catch (e) {
        ElMessage.error(e.message || 'Failed to start external tool')
      } finally {
        this.submitting = false
      }
    },

    async startServerInstance(item, params, instanceId) {
      this.$emit('append-output', this.selectedId, `> [External Tool: Server Start] ${item.display_name || item.id} instance=${instanceId}`, 'command')
      const res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/instances/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ params, instance_id: instanceId }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to start server tool')
      const data = json.data || {}
      this.$emit('append-output', this.selectedId, `[External Tool Started] instance=${data.instance_id || instanceId} pid=${data.pid || '-'} log=${data.runtime?.stdout || data.stdout || '-'}`, 'info')
      ElMessage.success(data.message || 'External tool instance started on server')
      await this.loadServerInstances(item.id, false)
    },

    async startClientInstance(item, params, instanceId) {
      if (!this.selectedId) throw new Error('Please select a device')
      this.$emit('append-output', this.selectedId, `> [External Tool: Client Start] ${item.display_name || item.id} instance=${instanceId}`, 'command')
      const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/external-tools/${encodeURIComponent(item.id)}/instances/start`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ params, instance_id: instanceId }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to start client tool')
      const taskId = json.data && json.data.task_id
      this.$emit('set-active-task', this.selectedId, taskId || '')
      ElMessage.success(`Client start submitted: ${item.display_name || item.id} / ${instanceId}`)
    },

    async loadServerInstances(toolId, showToast = true) {
      if (!toolId) return
      try {
        const res = await fetch(`/api/external-tools/${encodeURIComponent(toolId)}/server/instances`)
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load server instances')
        const data = json.data || {}
        this.serverInstances = {
          ...this.serverInstances,
          [toolId]: Array.isArray(data.items) ? data.items : [],
        }
        if (showToast) ElMessage.success('Server instances refreshed')
      } catch (e) {
        if (showToast) ElMessage.error(e.message || 'Failed to load server instances')
      }
    },

    async loadServerInstanceStatus(toolId, instanceId) {
      try {
        const res = await fetch(`/api/external-tools/${encodeURIComponent(toolId)}/server/instances/${encodeURIComponent(instanceId)}/status`)
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load status')
        const data = json.data || {}
        this.$emit('append-output', this.selectedId, `[External Tool Status] ${toolId}/${instanceId}: ${data.status} pid=${data.pid || '-'}`, 'info')
        await this.loadServerInstances(toolId, false)
        ElMessage.success(`Status: ${data.status || '-'}`)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to load status')
      }
    },

    async stopServerInstance(toolId, instanceId) {
      try {
        await ElMessageBox.confirm(
          `Stop external tool instance ${toolId}/${instanceId}?`,
          'Stop External Tool',
          { type: 'warning' },
        )
      } catch (_) {
        return
      }
      try {
        const res = await fetch(`/api/external-tools/${encodeURIComponent(toolId)}/server/instances/${encodeURIComponent(instanceId)}/stop`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ params: {} }),
        })
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to stop server instance')
        const data = json.data || {}
        this.$emit('append-output', this.selectedId, `[External Tool Stop] ${toolId}/${instanceId}: ${data.status} pid=${data.pid || '-'}`, 'info')
        ElMessage.success(data.message || 'Stop requested')
        await this.loadServerInstances(toolId, false)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to stop server instance')
      }
    },

    async openServerLogs(toolId, instanceId) {
      try {
        const res = await fetch(`/api/external-tools/${encodeURIComponent(toolId)}/server/instances/${encodeURIComponent(instanceId)}/logs?bytes=65536`)
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to read logs')
        const data = json.data || {}
        this.logDialogTitle = `${toolId}/${instanceId} logs`
        this.logContent = data.content || ''
        this.logDialogVisible = true
      } catch (e) {
        ElMessage.error(e.message || 'Failed to read logs')
      }
    },

    async submitClientListInstances(item) {
      if (!this.selectedId) {
        ElMessage.error('Please select a device')
        return
      }
      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/external-tools/${encodeURIComponent(item.id)}/instances`, {
          method: 'POST',
          headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({}),
        })
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to list client instances')
        const taskId = json.data && json.data.task_id
        this.$emit('set-active-task', this.selectedId, taskId || '')
        ElMessage.success(`Client list request submitted: ${item.display_name || item.id}`)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to list client instances')
      }
    },

    openClientInstanceAction(item, action) {
      this.pendingClientActionToolId = String(item?.id || '').trim()
      this.pendingClientAction = String(action || '').trim()
      this.clientActionInstanceId = ''
      this.clientActionDialogVisible = true
    },

    resetClientActionDialog() {
      this.clientActionDialogVisible = false
      this.pendingClientActionToolId = ''
      this.pendingClientAction = ''
      this.clientActionInstanceId = ''
      this.submitting = false
    },

    async confirmClientInstanceAction() {
      const item = this.pendingClientActionItem
      const action = this.pendingClientAction
      const instanceId = this.deriveInstanceId({ instance_name: this.clientActionInstanceId })
      if (!item || !action) return
      if (!this.selectedId) {
        ElMessage.error('Please select a device')
        return
      }
      if (!instanceId) {
        ElMessage.error('Instance ID is required')
        return
      }
      try {
        this.submitting = true
        let url = `/api/connections/${encodeURIComponent(this.selectedId)}/external-tools/${encodeURIComponent(item.id)}/instances/${encodeURIComponent(instanceId)}/${action}`
        const res = await fetch(url, {
          method: 'POST',
          headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ max_bytes: 65536 }),
        })
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || `Failed to submit client ${action}`)
        const taskId = json.data && json.data.task_id
        this.$emit('set-active-task', this.selectedId, taskId || '')
        ElMessage.success(`Client ${action} submitted: ${item.id}/${instanceId}`)
        this.resetClientActionDialog()
      } catch (e) {
        ElMessage.error(e.message || `Failed to submit client ${action}`)
      } finally {
        this.submitting = false
      }
    },
  },
}
</script>

<style scoped>
.external-tool-body {
  min-height: 520px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.external-tool-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.external-tool-toolbar-left,
.external-tool-toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.external-tool-filter {
  width: 150px;
}

.external-tool-search {
  width: 260px;
}

.external-tool-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  max-height: 600px;
  overflow: auto;
  padding-right: 4px;
}

.external-tool-card {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 14px;
  border: 1px solid var(--terminal-line, rgba(255,255,255,.12));
  border-radius: 12px;
  background: rgba(255,255,255,.035);
}

.external-tool-card-header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
}

.external-tool-card-main {
  min-width: 0;
  flex: 1;
}

.external-tool-title-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.external-tool-title {
  font-size: 15px;
  font-weight: 700;
  max-width: 360px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.external-tool-desc {
  margin-top: 8px;
  color: var(--terminal-muted, #8f9bb3);
  line-height: 1.45;
}

.external-tool-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 9px;
  color: var(--terminal-muted, #8f9bb3);
  font-size: 12px;
}

.external-tool-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 8px;
  min-width: 340px;
}

.external-tool-instances {
  border-top: 1px solid var(--terminal-line, rgba(255,255,255,.10));
  padding-top: 10px;
}

.external-tool-section-title {
  font-size: 12px;
  font-weight: 700;
  color: var(--terminal-muted, #8f9bb3);
  margin-bottom: 8px;
  text-transform: uppercase;
  letter-spacing: .04em;
}

.external-tool-instance-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.external-tool-instance-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 10px;
  border-radius: 10px;
  background: rgba(255,255,255,.035);
}

.external-tool-instance-main {
  display: flex;
  align-items: center;
  gap: 9px;
  min-width: 0;
  flex: 1;
}

.external-tool-instance-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}

.instance-id {
  font-weight: 700;
}

.muted {
  color: var(--terminal-muted, #8f9bb3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.external-tool-empty {
  padding: 48px 16px;
  text-align: center;
  color: var(--terminal-muted, #8f9bb3);
}

.external-tool-empty.small {
  padding: 20px 8px;
}

.external-tool-empty-inline {
  padding: 12px;
  color: var(--terminal-muted, #8f9bb3);
  font-size: 12px;
}

.external-tool-run-body {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.external-tool-run-summary {
  padding: 12px;
  border-radius: 10px;
  background: rgba(255,255,255,.045);
  line-height: 1.6;
}

.external-tool-param-form {
  max-height: 460px;
  overflow: auto;
  padding-right: 4px;
}

.external-tool-number {
  width: 100%;
}

.external-tool-param-help {
  margin-top: 4px;
  color: var(--terminal-muted, #8f9bb3);
  font-size: 12px;
  line-height: 1.45;
}

.external-tool-log-content {
  max-height: 560px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 12px;
  border-radius: 10px;
  background: rgba(0,0,0,.24);
  color: var(--terminal-fg, #d9e2ff);
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}
</style>
