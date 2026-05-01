<template>
  <el-dialog
    v-model="visible"
    title="External Tool Manager"
    width="1240px"
    top="5vh"
    class="fixed-dialog external-tool-dialog"
    @closed="handleClosed"
  >
    <div class="external-tool-body" v-loading="loading">
      <div class="external-tool-toolbar">
        <div class="external-tool-toolbar-left">
          <el-button size="small" type="primary" plain :loading="loading" @click="refreshAll">
            Refresh
          </el-button>

          <el-select v-model="sideFilter" size="small" class="external-tool-filter" placeholder="Side">
            <el-option label="All sides" value="" />
            <el-option label="Server" value="server" />
            <el-option label="Client" value="client" />
          </el-select>

          <el-select
            v-if="activeTab === 'instances'"
            v-model="deviceFilter"
            size="small"
            filterable
            class="external-tool-device-filter"
            placeholder="Filter by device"
            @change="handleDeviceFilterChange"
          >
            <el-option
              v-for="item in deviceFilterOptions"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>

          <el-select
            v-if="activeTab === 'modules'"
            v-model="platformFilter"
            size="small"
            class="external-tool-filter"
            placeholder="Platform"
          >
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
            :placeholder="activeTab === 'modules' ? 'Search modules/packages' : 'Search instances'"
          />
        </div>
      </div>

      <el-tabs v-model="activeTab" class="external-tool-tabs">
        <el-tab-pane label="Packages" name="modules">
          <div v-if="filteredModules.length" class="external-tool-module-list">
            <div
              v-for="item in filteredModules"
              :key="item.id"
              class="external-tool-card"
            >
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
  {{ formatVersionLabel(item.version) }}
</el-tag>
                  <el-tag v-if="item.arch" size="small" type="info">
                    {{ item.arch }}
                  </el-tag>
                  <el-tag
                    v-if="getModuleInstallStatus(item).label"
                    size="small"
                    :type="getModuleInstallStatus(item).type"
                    effect="plain"
                  >
                    {{ getModuleInstallStatus(item).label }}
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
                <div class="external-tool-action-row">
                  <el-button size="small" plain @click="downloadTool(item)">
                    Download
                  </el-button>
                  <el-button size="small" plain @click="$emit('open-tool-meta-editor', item.id)">
                    Edit
                  </el-button>
                </div>

                <div class="external-tool-action-row">
                  <el-button
                    v-if="item.side === 'server'"
                    size="small"
                    type="primary"
                    plain
                    :disabled="!isServerPlatformSupported(item)"
                    @click="openStartDialog(item, 'server', 'start')"
                  >
                    Run on Server
                  </el-button>

                  <el-button
                    v-if="item.side === 'client'"
                    size="small"
                    type="primary"
                    plain
                    :disabled="!selectedId || !isClientPlatformSupported(item)"
                    @click="openStartDialog(item, 'client', 'start')"
                  >
                    Run on Client
                  </el-button>

                  <el-dropdown
                    trigger="click"
                    size="small"
                    @command="handlePackageMoreCommand($event, item)"
                  >
                    <el-button size="small" plain>
                      More
                    </el-button>
                    <template #dropdown>
                      <el-dropdown-menu>
                        <el-dropdown-item command="install" :disabled="!canUsePackageAction(item)">
                          Install (Only)
                        </el-dropdown-item>
                        <el-dropdown-item command="run_only" :disabled="!canUsePackageAction(item)">
                          Run (Only)
                        </el-dropdown-item>
                        <el-dropdown-item command="status" :disabled="!canUsePackageAction(item)">
                          Install Status / Path
                        </el-dropdown-item>
                        <el-dropdown-item command="copy" :disabled="!canUsePackageAction(item)">
                          Copy Command
                        </el-dropdown-item>
                      </el-dropdown-menu>
                    </template>
                  </el-dropdown>
                </div>
              </div>
            </div>
          </div>

          <div v-else class="external-tool-empty">
            {{ searchText ? 'No matching external tool modules' : 'No external tool meta files found' }}
          </div>
        </el-tab-pane>

        <el-tab-pane label="Instances" name="instances">
          <div class="external-tool-instance-toolbar">
            <div class="external-tool-hint">
              Showing {{ activeDeviceFilterLabel }}. Use the device filter to switch between current device, server host, or all loaded devices.
            </div>
          </div>

          <el-table
            v-if="filteredInstances.length"
            :data="filteredInstances"
            size="small"
            class="external-tool-instance-table"
            height="560"
            row-key="row_key"
          >
            <el-table-column label="Side" width="86">
              <template #default="{ row }">
                <el-tag size="small" :type="row.side === 'server' ? 'success' : 'warning'">
                  {{ row.side }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column label="Device" min-width="170">
              <template #default="{ row }">
                <div class="mono strong" :title="row.device_id">{{ row.device_label || '-' }}</div>
                <div class="muted mono" :title="row.device_id">{{ shortenDeviceId(row.device_id) }}</div>
              </template>
            </el-table-column>

            <el-table-column label="Status" width="110">
              <template #default="{ row }">
                <el-tag size="small" :type="statusTagType(row.status)">
                  {{ row.status || '-' }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column label="Instance" min-width="170">
              <template #default="{ row }">
                <div class="mono strong" :title="row.instance_id">{{ row.instance_id }}</div>
                <div class="muted mono" :title="row.tool_id">{{ row.tool_id }}</div>
              </template>
            </el-table-column>

            <el-table-column label="PID" width="95">
              <template #default="{ row }">
                <span class="mono">{{ row.pid || '-' }}</span>
              </template>
            </el-table-column>

            <el-table-column label="Port" min-width="210">
              <template #default="{ row }">
                <span class="mono" :title="formatPortInfo(row)">{{ formatPortInfo(row) }}</span>
              </template>
            </el-table-column>

            <el-table-column label="Exec" min-width="210">
              <template #default="{ row }">
                <span class="mono muted" :title="row.exec_path">{{ row.exec_path || '-' }}</span>
              </template>
            </el-table-column>

            <el-table-column label="Path" min-width="300">
              <template #default="{ row }">
                <div class="mono path-line" :title="row.config_path">cfg: {{ row.config_path || '-' }}</div>
                <div class="mono path-line" :title="row.stdout">log: {{ row.stdout || '-' }}</div>
              </template>
            </el-table-column>

            <el-table-column label="Started" width="160">
              <template #default="{ row }">
                <span class="mono muted">{{ shortTime(row.started_at) }}</span>
              </template>
            </el-table-column>

            <el-table-column label="Actions" width="168" fixed="right">
              <template #default="{ row }">
                <div class="external-tool-table-actions">
                  <el-button size="small" plain @click="openInstanceLogs(row)">
                    Logs
                  </el-button>
                  <el-button
                    size="small"
                    type="danger"
                    plain
                    :disabled="!row.running && row.status !== 'stale'"
                    @click="stopInstance(row)"
                  >
                    Stop
                  </el-button>
                </div>
              </template>
            </el-table-column>
          </el-table>

          <div v-else class="external-tool-empty">
            {{ searchText || sideFilter || deviceFilter ? 'No matching instances' : 'No instances yet. Start one from Package / Module.' }}
          </div>
        </el-tab-pane>
      </el-tabs>
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
          Instance Name isolates config, pid, state and logs. Example: vite-8087 or ssh-6000.
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
        {{ pendingStartMode === 'run_only' ? 'Run Only' : 'Start Instance' }}
      </el-button>
    </template>
  </el-dialog>

  <el-dialog
    v-model="logDialogVisible"
    :title="logDialogTitle"
    width="940px"
    append-to-body
  >
    <div v-if="logFilePath" class="external-tool-log-path mono" :title="logFilePath">
      Log file: {{ logFilePath }}
    </div>
    <pre class="external-tool-log-content">{{ logContent || 'No log content.' }}</pre>
    <template #footer>
      <el-button size="small" :loading="logLoading" @click="refreshCurrentLogs">Refresh Logs</el-button>
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
    connections: {
      type: Array,
      default: () => [],
    },
    getTabScopedHeaders: {
      type: Function,
      default: null,
    },
  },

  emits: [
    'append-output',
    'set-active-task',
    'open-tool-meta-editor',
  ],

  data() {
    return {
      visible: false,
      loading: false,
      submitting: false,
      logLoading: false,
      installLoading: false,
      activeTab: 'modules',
      items: [],
      serverInstances: {},
      clientInstances: {},
      installStatuses: {},
      searchText: '',
      sideFilter: '',
      deviceFilter: '',
      platformFilter: '',
      startDialogVisible: false,
      pendingToolId: '',
      pendingTargetSide: '',
      pendingStartMode: 'start',
      paramForm: {},
      logDialogVisible: false,
      logDialogTitle: 'External Tool Logs',
      logFilePath: '',
      logContent: '',
      currentLogRow: null,
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

    currentDeviceId() {
      return this.normalizeDeviceId(this.selectedId || this.currentConnection?.client_id || '')
    },

    deviceFilterOptions() {
      const options = [
        { value: '__all__', label: 'All loaded devices' },
        { value: '__server__', label: 'Server host' },
      ]
      const seen = new Set(options.map(item => item.value))
      for (const conn of this.connections || []) {
        const id = this.normalizeDeviceId(conn?.client_id)
        if (!id || seen.has(id)) continue
        seen.add(id)
        options.push({ value: id, label: this.formatDeviceOptionLabel(conn) })
      }
      if (this.currentDeviceId && !seen.has(this.currentDeviceId)) {
        options.push({ value: this.currentDeviceId, label: this.formatCurrentDeviceLabel() })
      }
      return options
    },

    activeDeviceFilterLabel() {
      const value = this.normalizeDeviceId(this.deviceFilter)
      const option = this.deviceFilterOptions.find(item => item.value === value)
      if (option) return option.label
      if (!value) return 'current device'
      return this.shortenDeviceId(value)
    },

    serverModules() {
      return (this.items || []).filter(item => item.side === 'server')
    },

    clientModules() {
      return (this.items || []).filter(item => item.side === 'client')
    },

    filteredModules() {
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
        return this.moduleSearchText(item).includes(keyword)
      })
    },

    allInstances() {
      const rows = []
      for (const item of this.serverModules) {
        const list = this.serverInstances[item.id] || []
        for (const instance of list) rows.push(this.normalizeInstanceRow(item, instance, 'server', '__server__'))
      }
      for (const item of this.clientModules) {
        const byDevice = this.clientInstances || {}
        for (const [deviceId, toolMap] of Object.entries(byDevice)) {
          const list = toolMap?.[item.id] || []
          for (const instance of list) rows.push(this.normalizeInstanceRow(item, instance, 'client', deviceId))
        }
      }
      return rows.sort((a, b) => {
        if (a.running !== b.running) return a.running ? -1 : 1
        return String(b.started_at || '').localeCompare(String(a.started_at || ''))
      })
    },

    filteredInstances() {
      const keyword = String(this.searchText || '').trim().toLowerCase()
      const side = String(this.sideFilter || '').trim().toLowerCase()
      const device = this.normalizeDeviceId(this.deviceFilter || this.currentDeviceId || '__all__')
      return this.allInstances.filter((row) => {
        if (side && row.side !== side) return false
        if (device && device !== '__all__') {
          if (device === '__server__') {
            if (row.side !== 'server') return false
          } else if (row.device_id !== device) {
            return false
          }
        }
        if (!keyword) return true
        const values = [
          row.side,
          row.status,
          row.device_id,
          row.device_label,
          row.tool_id,
          row.display_name,
          row.instance_id,
          row.pid,
          row.exec_path,
          row.config_path,
          row.stdout,
          row.pid_file,
          this.formatPortInfo(row),
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
      const action = this.pendingStartMode === 'run_only' ? 'Run Only' : 'Start'
      return `${action} ${name} on ${side}`
    },
  },

  watch: {
    async selectedId() {
      if (!this.visible) return
      this.deviceFilter = this.currentDeviceId || '__server__'
      await this.refreshInstallStatuses(false)
      await this.refreshInstances(false)
    },
  },

  methods: {
    async open() {
      this.deviceFilter = this.currentDeviceId || '__server__'
      this.visible = true
      await this.refreshAll()
    },

    isOpen() {
      return this.visible
    },

    async refreshIfOpen() {
      if (!this.visible) return
      await this.refreshAll()
    },

    handleClosed() {
      this.resetStartDialog()
      this.currentLogRow = null
      this.logFilePath = ''
    },

    buildJsonHeaders(extra = {}) {
      if (typeof this.getTabScopedHeaders === 'function') {
        return this.getTabScopedHeaders(extra)
      }
      return extra
    },

    async refreshAll() {
      this.loading = true
      try {
        await this.loadCatalog(false)
        await this.refreshInstallStatuses(false)
        await this.refreshInstances(false)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to refresh external tools')
      } finally {
        this.loading = false
      }
    },

    async loadCatalog(showError = true) {
      try {
        const res = await fetch('/api/external-tools/catalog')
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load external tools')
        const catalog = json.data || {}
        this.items = Array.isArray(catalog.items) ? catalog.items : []
        this.applyCatalogInstallStatuses(this.items, '__server__')
      } catch (e) {
        if (showError) ElMessage.error(e.message || 'Failed to load external tools')
        throw e
      }
    },

    applyCatalogInstallStatuses(items, clientDeviceId = '') {
      for (const item of items || []) {
        const status = item?.install_status
        if (!status) continue
        const side = item.side || status.side || ''
        const deviceId = side === 'server' ? '__server__' : this.normalizeDeviceId(clientDeviceId || this.currentDeviceId)
        if (side === 'client' && !deviceId) continue
        this.setInstallStatus(item, side, deviceId, { ...status, loading: false, error: status.error || '' })
      }
    },

    async loadClientCatalogStatuses(deviceId = this.currentDeviceId, showError = true) {
      const targetDeviceId = this.normalizeDeviceId(deviceId)
      if (!targetDeviceId || targetDeviceId === '__server__' || targetDeviceId === '__all__') return []
      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(targetDeviceId)}/external-tools/catalog`, {
          method: 'POST',
          headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({}),
        })
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load client install statuses')
        const catalog = json.data || {}
        const items = Array.isArray(catalog.items) ? catalog.items : []
        this.applyCatalogInstallStatuses(items, targetDeviceId)
        return Array.isArray(catalog.client_install_statuses) ? catalog.client_install_statuses : []
      } catch (e) {
        if (showError) ElMessage.error(e.message || 'Failed to load client install statuses')
        return []
      }
    },

    installStatusKey(itemOrToolId, side = '', deviceId = '') {
      const toolId = typeof itemOrToolId === 'object' ? itemOrToolId?.id : itemOrToolId
      const normalizedSide = side || (typeof itemOrToolId === 'object' ? itemOrToolId?.side : '')
      const normalizedDeviceId = normalizedSide === 'server' ? '__server__' : this.normalizeDeviceId(deviceId || this.currentDeviceId)
      return `${normalizedSide}:${normalizedDeviceId}:${toolId || ''}`
    },

    getModuleInstallStatus(item) {
      const side = item?.side || ''
      const deviceId = side === 'server' ? '__server__' : this.currentDeviceId
      if (side === 'client' && !deviceId) return { label: 'Install: no client', type: 'info' }
      const status = this.installStatuses[this.installStatusKey(item, side, deviceId)]
      if (!status) return { label: 'Install: unknown', type: 'info' }
      if (status.loading) return { label: 'Checking...', type: 'info' }
      if (status.error) return { label: 'Install: unknown', type: 'info' }
      return status.installed
        ? { label: 'Installed', type: 'success' }
        : { label: 'Not installed', type: 'warning' }
    },

    setInstallStatus(itemOrToolId, side, deviceId, status) {
      const key = this.installStatusKey(itemOrToolId, side, deviceId)
      this.installStatuses = {
        ...this.installStatuses,
        [key]: { ...(status || {}) },
      }
    },

    async refreshInstallStatuses(showToast = false) {
      this.applyCatalogInstallStatuses(this.items, '__server__')
      if (this.currentDeviceId) {
        await this.loadClientCatalogStatuses(this.currentDeviceId, showToast)
      }
      if (showToast) ElMessage.success('Install statuses refreshed')
    },

    canUsePackageAction(item) {
      if (!item) return false
      if (item.side === 'server') return this.isServerPlatformSupported(item)
      if (item.side === 'client') return !!this.selectedId && this.isClientPlatformSupported(item)
      return false
    },

    async fetchInstallStatus(item, side = item?.side, deviceId = this.currentDeviceId, options = {}) {
      if (!item?.id) return null
      const targetSide = side || item.side
      const targetDeviceId = targetSide === 'server' ? '__server__' : this.normalizeDeviceId(deviceId || this.selectedId)
      if (targetSide === 'client' && !targetDeviceId) return null
      const statusKey = this.installStatusKey(item, targetSide, targetDeviceId)
      const cachedStatus = this.installStatuses[statusKey]
      if (cachedStatus && !cachedStatus.loading && !cachedStatus.error && !options.force) return cachedStatus

      if (targetSide === 'client') {
        await this.loadClientCatalogStatuses(targetDeviceId, !options.silent)
        const refreshed = this.installStatuses[statusKey]
        if (refreshed) return refreshed
        return null
      }

      const previousStatus = this.installStatuses[statusKey] || {}
      this.setInstallStatus(item, targetSide, targetDeviceId, { ...previousStatus, loading: true, error: '' })
      try {
        const res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/install-status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ params: {} }),
        })
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to read install status')
        const data = json.data || {}
        this.setInstallStatus(item, targetSide, targetDeviceId, { ...data, loading: false, error: data.error || '' })
        return data
      } catch (e) {
        this.setInstallStatus(item, targetSide, targetDeviceId, {
          ...previousStatus,
          loading: false,
          error: e.message || 'Failed to read install status',
        })
        if (!options.silent) ElMessage.error(e.message || 'Failed to read install status')
        return null
      }
    },

    async refreshInstances(showToast = true) {
      const device = this.normalizeDeviceId(this.deviceFilter || this.currentDeviceId || '__all__')

      if (device === '__all__' || device === '__server__' || !device) {
        await Promise.allSettled(this.serverModules.map(item => this.loadServerInstances(item.id, false)))
      }

      const clientDeviceIds = this.getClientDeviceIdsForFilter(device)
      for (const deviceId of clientDeviceIds) {
        for (const item of this.clientModules) {
          await this.loadClientInstances(item.id, deviceId, false)
        }
      }

      if (showToast) ElMessage.success('Instances refreshed')
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

    async loadClientInstances(toolId, deviceId = this.currentDeviceId, showToast = true) {
      const targetDeviceId = this.normalizeDeviceId(deviceId)
      if (!toolId || !targetDeviceId || targetDeviceId === '__server__' || targetDeviceId === '__all__') return
      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(targetDeviceId)}/external-tools/${encodeURIComponent(toolId)}/instances`, {
          method: 'POST',
          headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({}),
        })
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load client instances')
        const data = json.data || {}
        this.clientInstances = {
          ...this.clientInstances,
          [targetDeviceId]: {
            ...(this.clientInstances[targetDeviceId] || {}),
            [toolId]: Array.isArray(data.items) ? data.items : [],
          },
        }
        if (showToast) ElMessage.success('Client instances refreshed')
      } catch (e) {
        if (showToast) ElMessage.error(e.message || 'Failed to load client instances')
      }
    },

    normalizeDeviceId(value) {
      return String(value || '').trim()
    },

    shortenDeviceId(deviceId) {
      const value = this.normalizeDeviceId(deviceId)
      if (!value) return '-'
      if (value === '__server__') return 'server'
      if (value === '__all__') return 'all'
      return value.length > 12 ? value.slice(0, 12) : value
    },

    findConnectionById(deviceId) {
      const id = this.normalizeDeviceId(deviceId)
      return (this.connections || []).find(conn => this.normalizeDeviceId(conn?.client_id) === id) || null
    },

    formatDeviceOptionLabel(conn) {
      const id = this.normalizeDeviceId(conn?.client_id)
      const shortId = this.shortenDeviceId(id)
      const hostname = String(conn?.hostname || '').trim()
      return hostname ? `${shortId} (${hostname})` : shortId
    },

    formatCurrentDeviceLabel() {
      const conn = this.findConnectionById(this.currentDeviceId) || this.currentConnection
      return conn ? this.formatDeviceOptionLabel(conn) : this.shortenDeviceId(this.currentDeviceId)
    },

    getDeviceLabel(deviceId, side = '') {
      const id = this.normalizeDeviceId(deviceId)
      if (side === 'server' || id === '__server__') return 'Server host'
      const conn = this.findConnectionById(id)
      if (conn) return this.formatDeviceOptionLabel(conn)
      if (id === this.currentDeviceId && this.currentConnection) return this.formatDeviceOptionLabel(this.currentConnection)
      return this.shortenDeviceId(id)
    },

    getClientDeviceIdsForFilter(filterValue) {
      const value = this.normalizeDeviceId(filterValue || this.currentDeviceId)
      if (!value || value === '__server__') return []
      if (value === '__all__') {
        const ids = []
        const seen = new Set()
        for (const conn of this.connections || []) {
          const id = this.normalizeDeviceId(conn?.client_id)
          if (!id || seen.has(id)) continue
          seen.add(id)
          ids.push(id)
        }
        if (this.currentDeviceId && !seen.has(this.currentDeviceId)) ids.push(this.currentDeviceId)
        return ids
      }
      return [value]
    },

    async handleDeviceFilterChange() {
      await this.refreshInstances(false)
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

    moduleSearchText(item) {
      return [
        item.id,
        item.name,
        item.display_name,
        item.description,
        item.package?.filename,
        item.package?.executable_rel_path,
        (item.tags || []).join(' '),
      ].map(value => String(value || '').toLowerCase()).join(' ')
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
        if (name === 'instance_name' && (param.default === undefined || param.default === null || String(param.default).trim() === '')) {
          form[name] = this.defaultInstanceName(item)
        } else if (param.default !== undefined && param.default !== null) {
          form[name] = param.default
        } else if (this.normalizeParamType(param.type) === 'boolean') {
          form[name] = false
        } else {
          form[name] = ''
        }
      }
      return form
    },

    defaultInstanceName(item) {
      if (item?.name === 'frps') return 'frps-7000'
      if (item?.name === 'frpc') return 'vite-8087'
      return 'default'
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
      ) || (params.bind_port ? `frps-${params.bind_port}` : 'default')
      return String(raw || 'default').trim().replace(/[^A-Za-z0-9_.-]+/g, '-').replace(/^[._-]+|[._-]+$/g, '') || 'default'
    },

    openStartDialog(item, side, mode = 'start') {
      this.pendingToolId = String(item?.id || '').trim()
      this.pendingTargetSide = side
      this.pendingStartMode = mode === 'run_only' ? 'run_only' : 'start'
      this.paramForm = this.buildParamDefaults(item)
      this.startDialogVisible = true
    },

    resetStartDialog() {
      this.startDialogVisible = false
      this.submitting = false
      this.pendingToolId = ''
      this.pendingTargetSide = ''
      this.pendingStartMode = 'start'
      this.paramForm = {}
    },

    downloadTool(item) {
      const id = String(item?.id || '').trim()
      if (!id) return
      window.open(`/api/external-tools/${encodeURIComponent(id)}/download`, '_blank')
    },

    handlePackageMoreCommand(command, item) {
      if (command === 'install') return this.installOnly(item)
      if (command === 'run_only') return this.openStartDialog(item, item.side, 'run_only')
      if (command === 'status') return this.showInstallStatus(item)
      if (command === 'copy') return this.copyInstallCommand(item)
      return null
    },

    async installOnly(item) {
      if (!this.canUsePackageAction(item)) {
        ElMessage.warning(item?.side === 'client' ? 'Please select a supported client first' : 'This package is not supported')
        return
      }
      try {
        this.installLoading = true
        let res
        const side = item.side
        const deviceId = side === 'server' ? '__server__' : this.normalizeDeviceId(this.selectedId)
        if (side === 'server') {
          res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/install`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ params: {} }),
          })
        } else {
          res = await fetch(`/api/connections/${encodeURIComponent(deviceId)}/external-tools/${encodeURIComponent(item.id)}/install`, {
            method: 'POST',
            headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
            body: JSON.stringify({ params: {} }),
          })
        }
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to install package')
        const data = json.data || {}
        this.setInstallStatus(item, side, deviceId, data)
        const message = data.already_installed
          ? `Already installed: ${data.executable_path || data.install_dir || item.id}`
          : `Installed successfully: ${data.executable_path || data.install_dir || item.id}`
        ElMessage.success(message)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to install package')
      } finally {
        this.installLoading = false
      }
    },

    formatInstallStatusDetails(data) {
      if (!data) return 'No install status available'
      return [
        `Status: ${data.installed ? 'installed' : 'not installed'}`,
        `Install dir: ${data.install_dir || '-'}`,
        `Executable: ${data.executable_path || '-'}`,
        `Skip path: ${data.skip_path || '-'}`,
        `Command: ${data.command || data.executable_path || '-'}`,
        data.message ? `Message: ${data.message}` : '',
      ].filter(Boolean).join('\n')
    },

    async getInstallStatusForAction(item) {
      const deviceId = item?.side === 'server' ? '__server__' : this.selectedId
      return this.fetchInstallStatus(item, item?.side, deviceId, { silent: false, force: true })
    },

    async showInstallStatus(item) {
      const data = await this.getInstallStatusForAction(item)
      if (!data) return
      await ElMessageBox.alert(
        this.formatInstallStatusDetails(data),
        `${item.display_name || item.id} install status`,
        { confirmButtonText: 'OK' },
      )
    },

    async copyInstallCommand(item) {
      const data = await this.getInstallStatusForAction(item)
      if (!data) return
      const command = data.command || data.executable_path || ''
      if (!command) {
        ElMessage.warning('No command available to copy')
        return
      }
      try {
        if (window.isSecureContext && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
          await navigator.clipboard.writeText(command)
        } else {
          this.copyTextFallback(command)
        }
        ElMessage.success(data.installed ? 'Command copied' : 'Command copied; package is not installed yet')
      } catch (e) {
        try {
          this.copyTextFallback(command)
          ElMessage.success(data.installed ? 'Command copied' : 'Command copied; package is not installed yet')
        } catch (_) {
          ElMessage.error('Failed to copy command')
        }
      }
    },

    copyTextFallback(text) {
      const textarea = document.createElement('textarea')
      textarea.value = String(text || '')
      textarea.setAttribute('readonly', '')
      textarea.style.position = 'fixed'
      textarea.style.left = '-9999px'
      textarea.style.top = '0'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.focus()
      textarea.select()
      textarea.setSelectionRange(0, textarea.value.length)
      const ok = document.execCommand('copy')
      document.body.removeChild(textarea)
      if (!ok) throw new Error('Fallback copy failed')
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
        const installIfNeeded = this.pendingStartMode !== 'run_only'
        if (this.pendingTargetSide === 'server') {
          await this.startServerInstance(item, params, instanceId, installIfNeeded)
        } else {
          await this.startClientInstance(item, params, instanceId, installIfNeeded)
        }
        this.activeTab = 'instances'
        this.resetStartDialog()
      } catch (e) {
        ElMessage.error(e.message || 'Failed to start external tool')
      } finally {
        this.submitting = false
      }
    },

    async startServerInstance(item, params, instanceId, installIfNeeded = true) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/instances/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ params, instance_id: instanceId, install_if_needed: installIfNeeded }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to start server tool')
      ElMessage.success(json.data?.message || 'Server instance started')
      if (json.data?.install) this.setInstallStatus(item, 'server', '__server__', json.data.install)
      await this.loadServerInstances(item.id, false)
    },

    async startClientInstance(item, params, instanceId, installIfNeeded = true) {
      if (!this.selectedId) throw new Error('Please select a device')
      const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/external-tools/${encodeURIComponent(item.id)}/instances/start`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ params, instance_id: instanceId, install_if_needed: installIfNeeded }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to start client tool')
      ElMessage.success(json.data?.message || 'Client instance started')
      if (json.data?.install) this.setInstallStatus(item, 'client', this.selectedId, json.data.install)
      await this.loadClientInstances(item.id, this.selectedId, false)
    },

    normalizeInstanceRow(item, instance, side, deviceId = '') {
      const runtime = instance.runtime || {}
      const config = instance.config || {}
      const params = instance.params || {}
      const configPath = config.target || instance.config_file || ''
      const normalizedDeviceId = side === 'server' ? '__server__' : this.normalizeDeviceId(deviceId || this.currentDeviceId)
      return {
        row_key: `${side}:${normalizedDeviceId}:${item.id}:${instance.instance_id}`,
        side,
        device_id: normalizedDeviceId,
        device_label: this.getDeviceLabel(normalizedDeviceId, side),
        tool_id: item.id,
        display_name: item.display_name || item.id,
        instance_id: instance.instance_id || 'default',
        status: instance.status || '-',
        running: !!instance.running,
        pid: instance.pid || '',
        pid_file: instance.pid_file || runtime.pid_file || '',
        stdout: instance.stdout || runtime.stdout || '',
        state_file: instance.state_file || runtime.state_file || '',
        config_path: configPath,
        params,
        started_at: instance.started_at || '',
        stopped_at: instance.stopped_at || '',
        exec_path: item.package?.executable_rel_path || '',
        raw: instance,
        module: item,
      }
    },

    formatPortInfo(row) {
      const params = row.params || {}
      if (params.local_port || params.remote_port) {
        const localIp = params.local_ip || '127.0.0.1'
        const localPort = params.local_port || '-'
        const remotePort = params.remote_port || '-'
        return `${localIp}:${localPort} -> server:${remotePort}`
      }
      if (params.bind_port) return `bind:${params.bind_port}`
      if (params.server_port) return `control:${params.server_port}`
      return '-'
    },

    statusTagType(status) {
      const value = String(status || '').toLowerCase()
      if (value === 'running') return 'success'
      if (value === 'stale' || value === 'error') return 'danger'
      if (value === 'stopped') return 'info'
      return 'info'
    },

    shortTime(value) {
      const text = String(value || '').trim()
      if (!text) return '-'
      return text.replace('T', ' ').slice(0, 19)
    },

    async stopInstance(row) {
      try {
        await ElMessageBox.confirm(
          `Stop ${row.side} instance ${row.tool_id}/${row.instance_id}?`,
          'Stop External Tool Instance',
          {
            type: 'warning',
            confirmButtonText: 'Stop',
            cancelButtonText: 'Cancel',
          },
        )
      } catch (_) {
        return
      }

      try {
        if (row.side === 'server') {
          await this.stopServerInstance(row)
        } else {
          await this.stopClientInstance(row)
        }
        ElMessage.success(`Stop requested: ${row.instance_id}`)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to stop instance')
      }
    },

    async stopServerInstance(row) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(row.tool_id)}/server/instances/${encodeURIComponent(row.instance_id)}/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ params: {} }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to stop server instance')
      await this.loadServerInstances(row.tool_id, false)
    },

    async stopClientInstance(row) {
      const deviceId = this.normalizeDeviceId(row.device_id || this.selectedId)
      if (!deviceId) throw new Error('Please select a device')
      const res = await fetch(`/api/connections/${encodeURIComponent(deviceId)}/external-tools/${encodeURIComponent(row.tool_id)}/instances/${encodeURIComponent(row.instance_id)}/stop`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({}),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to stop client instance')
      await this.loadClientInstances(row.tool_id, deviceId, false)
    },

    async openInstanceLogs(row) {
      this.currentLogRow = row
      await this.readLogs(row, true)
    },

    async refreshCurrentLogs() {
      if (!this.currentLogRow) return
      await this.readLogs(this.currentLogRow, true)
    },

    async readLogs(row, openDialog = false) {
      try {
        this.logLoading = true
        let data
        if (row.side === 'server') {
          data = await this.readServerLogs(row)
        } else {
          data = await this.readClientLogs(row)
        }
        this.logDialogTitle = `${row.side} ${row.tool_id}/${row.instance_id} logs`
        this.logFilePath = data.log_file || row.stdout || ''
        this.logContent = data.content || ''
        if (openDialog) this.logDialogVisible = true
      } catch (e) {
        ElMessage.error(e.message || 'Failed to read logs')
      } finally {
        this.logLoading = false
      }
    },

    async readServerLogs(row) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(row.tool_id)}/server/instances/${encodeURIComponent(row.instance_id)}/logs?bytes=65536`)
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to read server logs')
      return json.data || {}
    },

    async readClientLogs(row) {
      const deviceId = this.normalizeDeviceId(row.device_id || this.selectedId)
      if (!deviceId) throw new Error('Please select a device')
      const res = await fetch(`/api/connections/${encodeURIComponent(deviceId)}/external-tools/${encodeURIComponent(row.tool_id)}/instances/${encodeURIComponent(row.instance_id)}/logs`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ max_bytes: 65536 }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to read client logs')
      return json.data || {}
    },

formatVersionLabel(version) {
  const value = String(version || '').trim()
  if (!value) return ''

  // 已经带 v 的标准数字版本，直接返回，避免 vv1.2.3
  if (/^v\d+\.\d+(?:\.\d+)?$/i.test(value)) {
    return value
  }

  // 只有 x.x 或 x.x.x 这种纯数字版本才自动加 v
  if (/^\d+\.\d+(?:\.\d+)?$/.test(value)) {
    return `v${value}`
  }

  // snapshot、commit、custom tag 等原样显示
  return value
}

  },
}
</script>

<style scoped>
.external-tool-body {
  min-height: 620px;
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

.external-tool-device-filter {
  width: 230px;
}

.external-tool-search {
  width: 280px;
}

.external-tool-tabs {
  min-height: 560px;
}

.external-tool-module-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  max-height: 560px;
  overflow: auto;
  padding-right: 4px;
}

.external-tool-card {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 14px;
  border: 1px solid var(--terminal-line, rgba(255,255,255,.12));
  border-radius: 12px;
  background: rgba(255,255,255,.035);
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
  max-width: 420px;
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
  flex-direction: column;
  align-items: stretch;
  justify-content: flex-start;
  gap: 8px;
  min-width: 240px;
}

.external-tool-action-row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
  justify-content: stretch;
}

.external-tool-action-row :deep(.el-button),
.external-tool-action-row :deep(.el-dropdown),
.external-tool-action-row :deep(.el-dropdown .el-button) {
  width: 100%;
  margin-left: 0;
}

.external-tool-table-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
}

.external-tool-table-actions :deep(.el-button + .el-button) {
  margin-left: 0;
}

.external-tool-instance-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.external-tool-hint {
  color: var(--terminal-muted, #8f9bb3);
  font-size: 12px;
}

.external-tool-instance-table {
  width: 100%;
  border-radius: 12px;
  overflow: hidden;
}

.path-line {
  max-width: 320px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.external-tool-empty {
  padding: 64px 16px;
  text-align: center;
  color: var(--terminal-muted, #8f9bb3);
}

.external-tool-empty.small {
  padding: 20px 8px;
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

.external-tool-log-path {
  margin-bottom: 8px;
  padding: 8px 10px;
  border-radius: 8px;
  background: rgba(255,255,255,.045);
  color: var(--terminal-muted, #8f9bb3);
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.external-tool-log-content {
  max-height: 560px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 12px;
  border-radius: 10px;
  background: #050505;
  color: #d9e2ff;
  border: 1px solid rgba(255,255,255,.12);
  scrollbar-color: #303544 #050505;
  scrollbar-width: thin;
}

.external-tool-log-content::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}

.external-tool-log-content::-webkit-scrollbar-track {
  background: #050505;
  border-radius: 999px;
}

.external-tool-log-content::-webkit-scrollbar-thumb {
  background: #303544;
  border-radius: 999px;
  border: 2px solid #050505;
}

.external-tool-log-content::-webkit-scrollbar-thumb:hover {
  background: #495064;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}

.strong {
  font-weight: 700;
}

.muted {
  color: var(--terminal-muted, #8f9bb3);
}
</style>
