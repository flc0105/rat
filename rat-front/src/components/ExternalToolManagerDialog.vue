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

          <div class="external-tool-target-control">
            <el-select
              v-model="deviceFilter"
              size="small"
              filterable
              class="external-tool-target-select"
              placeholder="Select target"
              @change="handleTargetFilterChange"
            >
              <el-option
                v-for="item in deviceFilterOptions"
                :key="item.value"
                :label="item.label"
                :value="item.value"
              />
            </el-select>
          </div>

          <el-checkbox
            v-if="activeTab === 'modules'"
            v-model="packageOnlyCompatible"
            size="small"
            @change="handlePackageOnlyCompatibleChange"
          >
            Only compatible
          </el-checkbox>
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
                  <el-tag size="small" :type="getModuleTargetTagType(item)">
                    {{ getModuleTargetTagLabel(item) }}
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
                <div class="external-tool-action-row single">
                  <el-button
                    size="small"
                    type="primary"
                    plain
                    :disabled="!canUsePackageAction(item)"
                    @click="openStartDialog(item, getSelectedTargetSideForAction(), 'start')"
                  >
                    {{ getRunButtonLabel(item) }}
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
                        <el-dropdown-item command="download">
                          Browser Download
                        </el-dropdown-item>
                        <el-dropdown-item command="edit">
                          Edit Metadata
                        </el-dropdown-item>
                        <el-dropdown-item divided command="install" :disabled="!canUsePackageAction(item)">
                          {{ getInstallMenuLabel(item) }}
                        </el-dropdown-item>
                        <el-dropdown-item command="run_only" :disabled="!canUsePackageAction(item)">
                          {{ getRunOnlyMenuLabel(item) }}
                        </el-dropdown-item>
                        <el-dropdown-item command="status" :disabled="!canUsePackageAction(item)">
                          Install Status
                        </el-dropdown-item>
                        <el-dropdown-item command="copy" :disabled="!canUsePackageAction(item)">
                          Copy Command
                        </el-dropdown-item>
                        <el-dropdown-item
                          command="uninstall"
                          divided
                          :disabled="!canUninstallPackageAction(item)"
                        >
                          {{ getUninstallMenuLabel(item) }}
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
              Target: {{ activeDeviceFilterLabel }}.
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
<!--            <el-table-column label="Target" min-width="190">-->
<!--              <template #default="{ row }">-->
<!--                <div class="mono strong" :title="row.machine_id || row.device_id">{{ row.machine_label || '-' }}</div>-->
<!--&lt;!&ndash;                <div class="muted mono" :title="row.connection_id || row.device_id">&ndash;&gt;-->
<!--&lt;!&ndash;                  {{ row.connection_id ? `conn: ${shortenDeviceId(row.connection_id)}` : '-' }}&ndash;&gt;-->
<!--&lt;!&ndash;                </div>&ndash;&gt;-->
<!--              </template>-->
<!--            </el-table-column>-->


             <el-table-column label="Instance" min-width="170">
              <template #default="{ row }">
                <div class="mono strong" :title="row.instance_id">{{ row.instance_id }}</div>
                <div class="muted mono" :title="row.tool_id">{{ row.tool_id }}</div>
              </template>
            </el-table-column>

            <el-table-column label="Status" width="110">
              <template #default="{ row }">
                <el-tag size="small" :type="statusTagType(row.status)">
                  {{ row.status || '-' }}
                </el-tag>
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

            <el-table-column label="Started" width="180">
              <template #default="{ row }">
                <span class="mono muted">{{ shortTime(row.started_at) }}</span>
              </template>
            </el-table-column>

            <el-table-column label="Actions" width="240" >
              <template #default="{ row }">
                <div class="external-tool-table-actions">
                  <el-button size="small" plain @click="openInstanceLogs(row)">
                    Logs
                  </el-button>
<!--                  <el-button size="small" plain @click="openInstanceInfo(row)">-->
<!--                    Info-->
<!--                  </el-button>-->
                  <el-button
                    size="small"
                    type="danger"
                    plain
                    :disabled="!row.running && row.status !== 'stale'"
                    @click="stopInstance(row)"
                  >
                    Stop
                  </el-button>
                  <el-dropdown
                    trigger="click"
                    size="small"
                    @command="handleInstanceMoreCommand($event, row)"
                  >
                    <el-button size="small" plain>
                      More
                    </el-button>
                    <template #dropdown>
                      <el-dropdown-menu>
                       <el-dropdown-item command="info">
                          Info
                        </el-dropdown-item>
                        <el-dropdown-item command="restart" :disabled="!canRestartInstance(row)">
                          Restart
                        </el-dropdown-item>
                        <el-dropdown-item command="clear_logs" :disabled="!canModifyStoppedInstanceFiles(row)">
                          Clear Logs
                        </el-dropdown-item>
                        <el-dropdown-item command="remove" :disabled="!canModifyStoppedInstanceFiles(row)">
                          Remove
                        </el-dropdown-item>
                      </el-dropdown-menu>
                    </template>
                  </el-dropdown>
                </div>
              </template>
            </el-table-column>
          </el-table>

          <div v-else class="external-tool-empty">
            {{ searchText || deviceFilter ? 'No matching instances' : 'No instances yet. Start one from Packages.' }}
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
        <div class="mono">{{ pendingItem.id }} / {{ activeDeviceFilterLabel }}</div>
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
            :placeholder="param.description || param.name"
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
    <pre ref="logContentRef" class="external-tool-log-content">{{ logContent || 'No log content.' }}</pre>
    <template #footer>
      <el-button size="small" :loading="logLoading" @click="refreshCurrentLogs">Refresh Logs</el-button>
      <el-button size="small" @click="logDialogVisible = false">Close</el-button>
    </template>
  </el-dialog>

  <el-dialog
    v-model="detailDialogVisible"
    :title="detailDialogTitle"
    width="780px"
    append-to-body
    class="external-tool-detail-dialog"
  >
    <div class="external-tool-detail-body">
      <div v-if="detailSubtitle" class="external-tool-detail-subtitle">
        {{ detailSubtitle }}
      </div>

      <div
        v-for="section in detailSections"
        :key="section.title"
        class="external-tool-detail-section"
      >
        <div class="external-tool-detail-section-title">
          {{ section.title }}
        </div>

        <div class="external-tool-detail-grid">
          <div
            v-for="row in section.rows"
            :key="`${section.title}:${row.label}`"
            class="external-tool-detail-row"
          >
            <div class="external-tool-detail-label">
              {{ row.label }}
            </div>
            <div
              class="external-tool-detail-value"
              :class="{ mono: row.mono, multiline: row.multiline }"
              :title="row.multiline ? '' : stringifyDetailValue(row.value)"
            >
              <pre v-if="row.multiline" class="external-tool-detail-pre">{{ formatDetailValue(row.value) }}</pre>
              <span v-else>{{ formatDetailValue(row.value) }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <template #footer>
      <el-button
        v-if="detailCopyText"
        size="small"
        plain
        @click="copyDetailText"
      >
        Copy Command
      </el-button>
      <el-button size="small" @click="detailDialogVisible = false">Close</el-button>
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
      deviceFilter: '',
      packageOnlyCompatible: true,
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
      detailDialogVisible: false,
      detailDialogTitle: '',
      detailSubtitle: '',
      detailSections: [],
      detailCopyText: '',
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

    currentMachineId() {
      return this.normalizeMachineId(this.currentConnection?.machine_id || '')
    },

    deviceFilterOptions() {
      const options = [
        { value: '__server__', label: 'Server host' },
      ]
      const seen = new Set(options.map(item => item.value))
      for (const conn of this.connections || []) {
        const machineId = this.normalizeMachineId(conn?.machine_id)
        if (!machineId || seen.has(machineId)) continue
        seen.add(machineId)
        options.push({ value: machineId, label: this.formatMachineOptionLabel(conn) })
      }
      if (this.currentMachineId && !seen.has(this.currentMachineId)) {
        seen.add(this.currentMachineId)
        options.push({ value: this.currentMachineId, label: this.formatCurrentMachineLabel() })
      }
      return options
    },

    activeDeviceFilterLabel() {
      const value = this.normalizeDeviceId(this.deviceFilter)
      const option = this.deviceFilterOptions.find(item => item.value === value)
      if (option) return option.label
      if (!value) return 'current target'
      return this.shortenMachineId(value)
    },

    serverModules() {
      return (this.items || []).filter(item => this.supportsSide(item, 'server'))
    },

    clientModules() {
      return (this.items || []).filter(item => this.supportsSide(item, 'client'))
    },

    isServerTargetSelected() {
      return this.normalizeDeviceId(this.deviceFilter || this.defaultTargetValue()) === '__server__'
    },

    selectedTargetMachineId() {
      return this.normalizeMachineId(this.deviceFilter || this.defaultTargetValue())
    },

    selectedTargetSide() {
      if (this.isServerTargetSelected) return 'server'
      return 'client'
    },

    selectedTargetClientId() {
      if (this.selectedTargetSide !== 'client') return ''
      return this.getClientDeviceIdForMachine(this.selectedTargetMachineId)
    },

    selectedTargetPlatform() {
      if (this.selectedTargetSide !== 'client') return ''
      return this.getPlatformForMachineId(this.selectedTargetMachineId)
    },

    filteredModules() {
      const keyword = String(this.searchText || '').trim().toLowerCase()

      return (this.items || []).filter((item) => {
        if (this.packageOnlyCompatible && !this.isPackageAvailableForTarget(item)) return false
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
      const machine = this.normalizeMachineId(this.deviceFilter || this.defaultTargetValue())
      return this.allInstances.filter((row) => {
        if (machine === '__server__') {
          if (row.side !== 'server') return false
        } else if (machine && row.machine_id !== machine) {
          return false
        }
        if (!keyword) return true
        const values = [
          row.side,
          row.status,
          row.machine_id,
          row.machine_label,
          row.hostname,
          row.connection_id,
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
      const side = this.pendingTargetSide === 'server' ? 'Server' : 'This Client'
      const action = this.pendingStartMode === 'run_only' ? 'Run Only' : 'Start'
      return `${action} ${name} on ${side}`
    },
  },

  watch: {
    async selectedId() {
      if (!this.visible) return
      this.deviceFilter = this.defaultTargetValue()
      await this.refreshInstallStatuses(false)
      await this.refreshInstances(false)
    },
  },

  methods: {
    async open() {
      this.deviceFilter = this.defaultTargetValue()
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
        const side = status.side || this.getItemSides(item)[0] || ''
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

    getItemSides(item) {
      const raw = item?.sides !== undefined ? item.sides : item?.side
      const source = Array.isArray(raw) ? raw : [raw]
      const sides = []
      const seen = new Set()
      for (const value of source) {
        const side = String(value || '').trim().toLowerCase()
        if (!['server', 'client'].includes(side) || seen.has(side)) continue
        seen.add(side)
        sides.push(side)
      }
      return sides.length ? sides : ['client']
    },

    supportsSide(item, side) {
      return this.getItemSides(item).includes(String(side || '').trim().toLowerCase())
    },

    getActionSideForItem(item) {
      const side = this.getSelectedTargetSideForAction()
      return this.supportsSide(item, side) ? side : this.getItemSides(item)[0]
    },

    installStatusKey(itemOrToolId, side = '', deviceId = '') {
      const toolId = typeof itemOrToolId === 'object' ? itemOrToolId?.id : itemOrToolId
      const normalizedSide = side || (typeof itemOrToolId === 'object' ? this.getItemSides(itemOrToolId)[0] : '')
      const normalizedDeviceId = normalizedSide === 'server' ? '__server__' : this.normalizeDeviceId(deviceId || this.currentDeviceId)
      return `${normalizedSide}:${normalizedDeviceId}:${toolId || ''}`
    },

    getModuleTargetTagLabel(item) {
      const sides = this.getItemSides(item)
      if (sides.includes('server') && sides.includes('client')) return 'Server / Client'
      return sides.includes('server') ? 'Server' : 'Client'
    },

    getModuleTargetTagType(item) {
      const sides = this.getItemSides(item)
      if (sides.includes('server') && sides.includes('client')) return 'info'
      if (sides.includes('server')) return 'success'
      return 'warning'
    },

    getInstallStatusTargetLabel() {
      return this.getSelectedTargetSideForAction() === 'server' ? 'Server' : 'This Client'
    },

    getModuleInstallDeviceId(item) {
      return this.getSelectedTargetSideForAction() === 'server' ? '__server__' : this.getActionDeviceId(item)
    },

    getModuleInstallStatus(item) {
      if (!this.isPackageAvailableForTarget(item)) {
        return { label: 'Unavailable for target', type: 'info' }
      }
      const side = this.getSelectedTargetSideForAction()
      const targetLabel = this.getInstallStatusTargetLabel(item)
      const deviceId = this.getModuleInstallDeviceId(item)
      if (side === 'client' && !deviceId) return { label: 'Install: no client', type: 'info' }
      const status = this.installStatuses[this.installStatusKey(item, side, deviceId)]
      if (!status) return { label: `Status unknown on ${targetLabel}`, type: 'info' }
      if (status.loading) return { label: 'Checking...', type: 'info' }
      if (status.error) return { label: `Status unknown on ${targetLabel}`, type: 'info' }
      return status.installed
        ? { label: `Installed on ${targetLabel}`, type: 'success' }
        : { label: `Not installed on ${targetLabel}`, type: 'warning' }
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
      const deviceId = this.selectedTargetClientId
      if (deviceId) {
        await this.loadClientCatalogStatuses(deviceId, showToast)
      }
      if (showToast) ElMessage.success('Install statuses refreshed')
    },

    isPackageAvailableForTarget(item) {
      if (!item) return false
      const side = this.getSelectedTargetSideForAction()
      if (!this.supportsSide(item, side)) return false
      if (side === 'server') return this.isServerPlatformSupported(item)
      const deviceId = this.getActionDeviceId(item)
      const platform = this.selectedTargetPlatform || this.currentClientPlatform
      return !!deviceId && this.selectedTargetSide === 'client' && this.doesPlatformMatch(item, platform)
    },

    canUsePackageAction(item) {
      return this.isPackageAvailableForTarget(item)
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
      const device = this.normalizeMachineId(this.deviceFilter || this.defaultTargetValue())

      if (device === '__server__' || !device) {
        await Promise.allSettled(this.serverModules.map(item => this.loadServerInstances(item.id, false)))
      } else {
        const clientDeviceIds = this.getClientDeviceIdsForFilter(device)
        for (const deviceId of clientDeviceIds) {
          for (const item of this.clientModules) {
            await this.loadClientInstances(item.id, deviceId, false)
          }
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

    defaultTargetValue() {
      return this.currentMachineId || '__server__'
    },

    getClientDeviceIdForMachine(machineId) {
      const id = this.normalizeMachineId(machineId)
      if (!id || id === '__server__' || id === '__all__') return ''
      const conn = this.findConnectionByMachineId(id)
      if (conn?.client_id) return this.normalizeDeviceId(conn.client_id)
      if (id === this.currentMachineId && this.currentDeviceId) return this.currentDeviceId
      const byConnectionId = this.findConnectionById(id)
      if (byConnectionId?.client_id) return this.normalizeDeviceId(byConnectionId.client_id)
      return ''
    },

    getPlatformForMachineId(machineId) {
      const id = this.normalizeMachineId(machineId)
      if (!id || id === '__server__' || id === '__all__') return ''
      const conn = this.findConnectionByMachineId(id) || (id === this.currentMachineId ? this.currentConnection : null)
      return this.normalizePlatform(
        conn?.os_alias || conn?.os_type || conn?.platform || conn?.system || '',
      )
    },

    getActionDeviceId(item) {
      if (!item || !this.supportsSide(item, 'client')) return ''
      return this.selectedTargetClientId || this.currentDeviceId
    },

    normalizeDeviceId(value) {
      return String(value || '').trim()
    },

    normalizeMachineId(value) {
      return String(value || '').trim()
    },

    shortenDeviceId(deviceId) {
      const value = this.normalizeDeviceId(deviceId)
      if (!value) return '-'
      if (value === '__server__') return 'server'
      if (value === '__all__') return 'all'
      return value.length > 12 ? value.slice(0, 12) : value
    },

    shortenMachineId(machineId) {
      const value = this.normalizeMachineId(machineId)
      if (!value) return '-'
      if (value === '__server__') return 'server'
      if (value === '__all__') return 'all'
      return value.length > 12 ? value.slice(0, 12) : value
    },

    findConnectionById(deviceId) {
      const id = this.normalizeDeviceId(deviceId)
      return (this.connections || []).find(conn => this.normalizeDeviceId(conn?.client_id) === id) || null
    },

    findConnectionByMachineId(machineId) {
      const id = this.normalizeMachineId(machineId)
      return (this.connections || []).find(conn => this.normalizeMachineId(conn?.machine_id) === id) || null
    },

    getMachineIdForConnectionId(deviceId) {
      if (deviceId === '__server__') return '__server__'
      const conn = this.findConnectionById(deviceId)
      return this.normalizeMachineId(conn?.machine_id || (deviceId === this.currentDeviceId ? this.currentConnection?.machine_id : '') || deviceId)
    },

    getHostnameForConnectionId(deviceId) {
      const conn = this.findConnectionById(deviceId) || (deviceId === this.currentDeviceId ? this.currentConnection : null)
      return String(conn?.hostname || '').trim()
    },

    formatMachineOptionLabel(conn) {
      const machineId = this.normalizeMachineId(conn?.machine_id)
      const shortId = this.shortenMachineId(machineId)
      const hostname = String(conn?.hostname || '').trim()
      return hostname ? `${shortId} (${hostname})` : shortId
    },

    formatCurrentMachineLabel() {
      const conn = this.currentConnection || this.findConnectionById(this.currentDeviceId)
      if (conn?.machine_id) return this.formatMachineOptionLabel(conn)
      return this.shortenMachineId(this.currentMachineId)
    },

    getMachineLabel(machineId, side = '', connectionId = '') {
      const id = this.normalizeMachineId(machineId)
      if (side === 'server' || id === '__server__') return 'Server host'
      const conn = this.findConnectionByMachineId(id) || this.findConnectionById(connectionId)
      if (conn?.machine_id) return this.formatMachineOptionLabel(conn)
      if (id === this.currentMachineId && this.currentConnection) return this.formatMachineOptionLabel(this.currentConnection)
      return this.shortenMachineId(id)
    },

    getClientDeviceIdsForFilter(filterValue) {
      const value = this.normalizeMachineId(filterValue || this.currentMachineId)
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

      const ids = []
      const seen = new Set()
      for (const conn of this.connections || []) {
        const machineId = this.normalizeMachineId(conn?.machine_id)
        const clientId = this.normalizeDeviceId(conn?.client_id)
        if (!clientId || seen.has(clientId)) continue
        if (machineId === value || clientId === value) {
          seen.add(clientId)
          ids.push(clientId)
        }
      }
      if (!ids.length && value === this.currentMachineId && this.currentDeviceId) {
        ids.push(this.currentDeviceId)
      }
      return ids
    },

    async handleTargetFilterChange() {
      await this.refreshInstallStatuses(false)
      await this.refreshInstances(false)
    },

    async handlePackageOnlyCompatibleChange() {
      await this.refreshInstallStatuses(false)
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

    getSelectedTargetSideForAction() {
      return this.isServerTargetSelected ? 'server' : 'client'
    },

    getRunButtonLabel() {
      return this.isServerTargetSelected ? 'Run on Server' : 'Run on This Client'
    },

    getInstallMenuLabel() {
      return this.isServerTargetSelected ? 'Install on Server' : 'Install on This Client'
    },

    getRunOnlyMenuLabel() {
      return this.isServerTargetSelected ? 'Run Only on Server' : 'Run Only on This Client'
    },

    getUninstallMenuLabel() {
      return this.isServerTargetSelected ? 'Uninstall from Server' : 'Uninstall from This Client'
    },

handlePackageMoreCommand(command, item) {
  if (command === 'download') return this.downloadTool(item)
  if (command === 'edit') return this.$emit('open-tool-meta-editor', item.id)
  if (!this.canUsePackageAction(item)) return null
  if (command === 'install') return this.installOnly(item)
  if (command === 'run_only') return this.openStartDialog(item, this.getSelectedTargetSideForAction(), 'run_only')
  if (command === 'status') return this.showInstallStatus(item)
  if (command === 'copy') return this.copyInstallCommand(item)
  if (command === 'uninstall') return this.uninstallPackage(item)
  return null
},

    getPackageTargetMachineId(item) {
  if (!item) return ''
  if (this.getSelectedTargetSideForAction() === 'server') return '__server__'
  return this.selectedTargetMachineId
},

getPackageTargetConnectionIds(item) {
  if (!item || this.getSelectedTargetSideForAction() !== 'client' || !this.supportsSide(item, 'client')) return []
  const machineId = this.getPackageTargetMachineId(item)
  const ids = this.getClientDeviceIdsForFilter(machineId)
  if (ids.length) return ids
  const actionDeviceId = this.getActionDeviceId(item)
  return actionDeviceId ? [actionDeviceId] : []
},

getPackageTargetInstanceRows(item) {
  if (!item?.id) return []

  if (this.getSelectedTargetSideForAction() === 'server') {
    return this.allInstances.filter(row => row.side === 'server' && row.tool_id === item.id)
  }

  const machineId = this.getPackageTargetMachineId(item)
  return this.allInstances.filter(row => (
    row.side === 'client' &&
    row.tool_id === item.id &&
    row.machine_id === machineId
  ))
},

hasRunningInstancesForPackage(item) {
  return this.getPackageTargetInstanceRows(item).some(row => row.running || String(row.status || '').toLowerCase() === 'running')
},

canUninstallPackageAction(item) {
  if (!this.canUsePackageAction(item)) return false

  const status = this.installStatuses[this.installStatusKey(
    item,
    this.getSelectedTargetSideForAction(),
    this.getModuleInstallDeviceId(item),
  )]

  if (status && status.installed === false) return false
  return !this.hasRunningInstancesForPackage(item)
},

async uninstallPackage(item) {
  if (!item?.id) return
  if (!this.canUsePackageAction(item)) {
    ElMessage.warning(this.getSelectedTargetSideForAction() === 'client' ? 'Please select a supported client first' : 'This package is not supported')
    return
  }

  // 卸载前刷新一次实例状态，避免 UI 旧数据导致误删。
  try {
    await this.refreshInstances(false)
  } catch (_) {
    // refresh 失败不直接中断，后端/client 仍会再做一次 running 校验。
  }

  if (this.hasRunningInstancesForPackage(item)) {
    ElMessage.warning('This package still has running instances on this machine. Stop them before uninstalling.')
    return
  }

  try {
    await ElMessageBox.confirm(
      `Uninstall ${item.display_name || item.id} from ${this.getSelectedTargetSideForAction() === 'server' ? 'server' : 'this machine'}?`,
      'Uninstall External Tool',
      {
        type: 'warning',
        confirmButtonText: 'Uninstall',
        cancelButtonText: 'Cancel',
      },
    )
  } catch (_) {
    return
  }

  try {
    this.installLoading = true
    let data
    if (this.getSelectedTargetSideForAction() === 'server') {
      data = await this.uninstallServerTool(item)
      this.setInstallStatus(item, 'server', '__server__', {
        ...(data || {}),
        installed: false,
        loading: false,
        error: '',
      })
    } else {
      const deviceIds = this.getPackageTargetConnectionIds(item)
      if (!deviceIds.length) throw new Error('Please select a device')
      // 实际卸载只对当前选中的连接发命令；同 machine 多连接时，后端命令仍落在该机器本地路径。
      const deviceId = this.normalizeDeviceId(this.selectedId || deviceIds[0])
      data = await this.uninstallClientTool(item, deviceId)
      this.setInstallStatus(item, 'client', deviceId, {
        ...(data || {}),
        installed: false,
        loading: false,
        error: '',
      })
      await this.loadClientCatalogStatuses(deviceId, false)
    }

    ElMessage.success(data?.message || `Uninstalled: ${item.display_name || item.id}`)
  } catch (e) {
    ElMessage.error(e.message || 'Failed to uninstall package')
  } finally {
    this.installLoading = false
  }
},

async uninstallServerTool(item) {
  const res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/uninstall`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ params: {} }),
  })
  const json = await res.json()
  if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to uninstall server package')
  return json.data || {}
},

async uninstallClientTool(item, deviceId) {
  const targetDeviceId = this.normalizeDeviceId(deviceId || this.selectedId)
  if (!targetDeviceId) throw new Error('Please select a device')

  const res = await fetch(`/api/connections/${encodeURIComponent(targetDeviceId)}/external-tools/${encodeURIComponent(item.id)}/uninstall`, {
    method: 'POST',
    headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ params: {} }),
  })
  const json = await res.json()
  if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to uninstall client package')
  return json.data || {}
},

    async installOnly(item) {
      if (!this.canUsePackageAction(item)) {
        ElMessage.warning(this.getSelectedTargetSideForAction() === 'client' ? 'Please select a supported client first' : 'This package is not supported')
        return
      }
      try {
        this.installLoading = true
        let res
        const side = this.getSelectedTargetSideForAction()
        const deviceId = side === 'server' ? '__server__' : this.getActionDeviceId(item)
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
      const side = this.getSelectedTargetSideForAction()
      const deviceId = side === 'server' ? '__server__' : this.getActionDeviceId(item)
      return this.fetchInstallStatus(item, side, deviceId, { silent: false, force: true })
    },

    async showInstallStatus(item) {
      const data = await this.getInstallStatusForAction(item)
      if (!data) return
      this.showDetailDialog({
        title: `${item.display_name || item.id} install status`,
        subtitle: `${item.id} / ${this.getSelectedTargetSideForAction()}`,
        copyText: data.command || data.executable_path || '',
        sections: [
          {
            title: 'Package install',
            rows: [
              { label: 'Status', value: data.installed ? 'Installed' : (data.installed === false ? 'Not installed' : 'Unknown') },
              { label: 'Install dir', value: data.install_dir || '-', mono: true },
              { label: 'Executable', value: data.executable_path || '-', mono: true },
              { label: 'Skip path', value: data.skip_path || '-', mono: true },
              { label: 'Command', value: data.command || data.executable_path || '-', mono: true },
              { label: 'Message', value: data.message || data.error || '-' },
            ],
          },
        ],
      })
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

    showDetailDialog({ title = '', subtitle = '', sections = [], copyText = '' } = {}) {
      this.detailDialogTitle = title || 'Details'
      this.detailSubtitle = subtitle || ''
      this.detailSections = (sections || []).map(section => ({
        title: section.title || 'Details',
        rows: (section.rows || []).filter(row => row && row.label),
      })).filter(section => section.rows.length)
      this.detailCopyText = copyText || ''
      this.detailDialogVisible = true
    },

    stringifyDetailValue(value) {
      if (value === undefined || value === null || value === '') return '-'
      if (typeof value === 'string') return value
      try {
        return JSON.stringify(value, null, 2)
      } catch (_) {
        return String(value)
      }
    },

    formatDetailValue(value) {
      return this.stringifyDetailValue(value)
    },

    async copyDetailText() {
      if (!this.detailCopyText) return
      try {
        if (window.isSecureContext && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
          await navigator.clipboard.writeText(this.detailCopyText)
        } else {
          this.copyTextFallback(this.detailCopyText)
        }
        ElMessage.success('Copied')
      } catch (e) {
        try {
          this.copyTextFallback(this.detailCopyText)
          ElMessage.success('Copied')
        } catch (_) {
          ElMessage.error('Failed to copy')
        }
      }
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

    async startClientInstance(item, params, instanceId, installIfNeeded = true, deviceId = '') {
      const targetDeviceId = this.normalizeDeviceId(deviceId || this.getActionDeviceId(item))
      if (!targetDeviceId) throw new Error('Please select a target machine')
      const res = await fetch(`/api/connections/${encodeURIComponent(targetDeviceId)}/external-tools/${encodeURIComponent(item.id)}/instances/start`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ params, instance_id: instanceId, install_if_needed: installIfNeeded }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to start client tool')
      ElMessage.success(json.data?.message || 'Client instance started')
      if (json.data?.install) this.setInstallStatus(item, 'client', targetDeviceId, json.data.install)
      await this.loadClientInstances(item.id, targetDeviceId, false)
    },

    normalizeInstanceRow(item, instance, side, deviceId = '') {
      const runtime = instance.runtime || {}
      const config = instance.config || {}
      const params = instance.params || {}
      const configPath = config.target || instance.config_file || ''
      const normalizedDeviceId = side === 'server' ? '__server__' : this.normalizeDeviceId(deviceId || this.currentDeviceId)
      const machineId = side === 'server' ? '__server__' : this.getMachineIdForConnectionId(normalizedDeviceId)
      const hostname = side === 'server' ? '' : this.getHostnameForConnectionId(normalizedDeviceId)
      return {
        row_key: `${side}:${normalizedDeviceId}:${item.id}:${instance.instance_id}`,
        side,
        device_id: normalizedDeviceId,
        connection_id: normalizedDeviceId,
        machine_id: machineId,
        hostname,
        machine_label: this.getMachineLabel(machineId, side, normalizedDeviceId),
        tool_id: item.id,
        display_name: item.display_name || item.id,
        instance_id: instance.instance_id || 'default',
        status: instance.status || '-',
        running: !!instance.running,
        pid: instance.pid || '',
        pid_file: instance.pid_file || runtime.pid_file || '',
        stdout: instance.stdout || runtime.stdout || '',
        stderr: instance.stderr || runtime.stderr || '',
        state_file: instance.state_file || runtime.state_file || '',
        config_path: configPath,
        params,
        started_at: instance.started_at || '',
        stopped_at: instance.stopped_at || '',
        exec_path: runtime.argv?.[0] || item.package?.executable_rel_path || '',
        cwd: runtime.cwd || instance.cwd || '',
        argv: runtime.argv || instance.argv || [],
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
        this.scrollLogsToBottom()
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

    scrollLogsToBottom() {
      this.$nextTick(() => {
        const el = this.$refs.logContentRef
        if (el && typeof el.scrollTop === 'number') {
          el.scrollTop = el.scrollHeight || 0
        }
      })
    },

    openInstanceInfo(row) {
      const runtime = row.raw?.runtime || {}
      const params = row.params || {}
      this.showDetailDialog({
        title: `${row.side} ${row.tool_id}/${row.instance_id} info`,
        subtitle: row.machine_label || row.side,
        copyText: row.exec_path || '',
        sections: [
          {
            title: 'Overview',
            rows: [
              { label: 'Side', value: row.side },
              { label: 'Machine', value: row.machine_label || row.machine_id },
              { label: 'Machine ID', value: row.machine_id, mono: true },
              { label: 'Connection ID', value: row.connection_id || '-', mono: true },
              { label: 'Hostname', value: row.hostname || '-' },
              { label: 'Tool', value: row.tool_id, mono: true },
              { label: 'Instance', value: row.instance_id, mono: true },
              { label: 'Status', value: row.status },
              { label: 'PID', value: row.pid || '-' },
              { label: 'Port', value: this.formatPortInfo(row), mono: true },
              { label: 'Started', value: this.shortTime(row.started_at) },
              { label: 'Stopped', value: this.shortTime(row.stopped_at) },
              { label: 'Message', value: row.raw?.message || '-' },
            ],
          },
          {
            title: 'Runtime paths',
            rows: [
              { label: 'Executable', value: row.exec_path || runtime.argv?.[0] || '-', mono: true },
              { label: 'CWD', value: row.cwd || runtime.cwd || '-', mono: true },
              { label: 'Config', value: row.config_path || '-', mono: true },
              { label: 'Log', value: row.stdout || '-', mono: true },
              { label: 'Stderr', value: row.stderr || '-', mono: true },
              { label: 'PID file', value: row.pid_file || '-', mono: true },
              { label: 'State file', value: row.state_file || '-', mono: true },
              { label: 'Argv', value: row.argv?.length ? row.argv : (runtime.argv || []), mono: true, multiline: true },
            ],
          },
          {
            title: 'Params',
            rows: [
              { label: 'Runtime params', value: params, mono: true, multiline: true },
            ],
          },
        ],
      })
    },

    canModifyStoppedInstanceFiles(row) {
      if (!row || row.running) return false
      const status = String(row.status || '').toLowerCase()
      return status === 'stopped' || status === 'not_started' || status === 'error'
    },

    canRestartInstance(row) {
      if (!row || row.running) return false
      const status = String(row.status || '').toLowerCase()
      return status === 'stopped' || status === 'not_started' || status === 'error'
    },

    handleInstanceMoreCommand(command, row) {
      if (command === 'info') return this.openInstanceInfo(row)
      if (command === 'restart') return this.restartInstance(row)
      if (command === 'clear_logs') return this.clearInstanceLogs(row)
      if (command === 'remove') return this.removeInstance(row)
      return null
    },

    async restartInstance(row) {
      if (!this.canRestartInstance(row)) {
        ElMessage.warning('Please stop this instance before restarting it')
        return
      }
      try {
        await ElMessageBox.confirm(
          `Restart ${row.side} instance ${row.tool_id}/${row.instance_id} with the same params?`,
          'Restart External Tool Instance',
          { type: 'warning', confirmButtonText: 'Restart', cancelButtonText: 'Cancel' },
        )
      } catch (_) {
        return
      }

      try {
        if (row.side === 'server') {
          await this.startServerInstance(row.module, row.params || {}, row.instance_id, true)
        } else {
          await this.startClientInstance(row.module, row.params || {}, row.instance_id, true, row.connection_id || row.device_id)
        }
        ElMessage.success(`Restarted: ${row.instance_id}`)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to restart instance')
      }
    },

    async removeInstance(row) {
      if (!this.canModifyStoppedInstanceFiles(row)) {
        ElMessage.warning('Stop this instance first')
        return
      }
      try {
        await ElMessageBox.confirm(
          `Remove runtime files for ${row.side} instance ${row.tool_id}/${row.instance_id}?`,
          'Remove External Tool Instance',
          { type: 'warning', confirmButtonText: 'Remove', cancelButtonText: 'Cancel' },
        )
      } catch (_) {
        return
      }

      try {
        if (row.side === 'server') {
          await this.removeServerInstance(row)
        } else {
          await this.removeClientInstance(row)
        }
        ElMessage.success(`Removed: ${row.instance_id}`)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to remove instance')
      }
    },

    async removeServerInstance(row) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(row.tool_id)}/server/instances/${encodeURIComponent(row.instance_id)}/remove`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to remove server instance')
      await this.loadServerInstances(row.tool_id, false)
    },

    async removeClientInstance(row) {
      const deviceId = this.normalizeDeviceId(row.connection_id || row.device_id || this.selectedId)
      if (!deviceId) throw new Error('Please select a device')
      const res = await fetch(`/api/connections/${encodeURIComponent(deviceId)}/external-tools/${encodeURIComponent(row.tool_id)}/instances/${encodeURIComponent(row.instance_id)}/remove`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({}),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to remove client instance')
      await this.loadClientInstances(row.tool_id, deviceId, false)
    },

    async clearInstanceLogs(row) {
      if (!this.canModifyStoppedInstanceFiles(row)) {
        ElMessage.warning('Stop this instance first')
        return
      }
      try {
        await ElMessageBox.confirm(
          `Clear log file for ${row.side} instance ${row.tool_id}/${row.instance_id}?`,
          'Clear External Tool Logs',
          { type: 'warning', confirmButtonText: 'Clear Logs', cancelButtonText: 'Cancel' },
        )
      } catch (_) {
        return
      }

      try {
        if (row.side === 'server') {
          await this.clearServerInstanceLogs(row)
        } else {
          await this.clearClientInstanceLogs(row)
        }
        if (this.currentLogRow?.row_key === row.row_key) {
          this.logContent = ''
          this.scrollLogsToBottom()
        }
        ElMessage.success(`Logs cleared: ${row.instance_id}`)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to clear logs')
      }
    },

    async clearServerInstanceLogs(row) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(row.tool_id)}/server/instances/${encodeURIComponent(row.instance_id)}/clear-logs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to clear server logs')
    },

    async clearClientInstanceLogs(row) {
      const deviceId = this.normalizeDeviceId(row.connection_id || row.device_id || this.selectedId)
      if (!deviceId) throw new Error('Please select a device')
      const res = await fetch(`/api/connections/${encodeURIComponent(deviceId)}/external-tools/${encodeURIComponent(row.tool_id)}/instances/${encodeURIComponent(row.instance_id)}/clear-logs`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({}),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to clear client logs')
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

.external-tool-target-control {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  border: 1px solid rgba(255,255,255,.12);
  border-radius: 12px;
  background: rgba(255,255,255,.045);
}

.external-tool-target-label {
  font-size: 12px;
  font-weight: 800;
  letter-spacing: .02em;
  color: var(--terminal-text, #d9e2ff);
  text-transform: uppercase;
}

.external-tool-target-select {
  width: 320px;
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

.external-tool-action-row.single {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.external-tool-action-row.single > .el-button:first-child:last-child,
.external-tool-action-row.single > .el-dropdown:first-child:last-child {
  grid-column: 1 / -1;
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
  //justify-content: flex-end;
  gap: 8px;
  flex-wrap: wrap;
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
.external-tool-detail-body {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.external-tool-detail-subtitle {
  padding: 8px 10px;
  border-radius: 8px;
  background: rgba(255,255,255,.045);
  color: var(--terminal-muted, #8f9bb3);
  font-size: 12px;
}

.external-tool-detail-section {
  border: 1px solid rgba(255,255,255,.10);
  border-radius: 12px;
  overflow: hidden;
  background: rgba(255,255,255,.025);
}

.external-tool-detail-section-title {
  padding: 9px 12px;
  font-weight: 700;
  border-bottom: 1px solid rgba(255,255,255,.08);
  background: rgba(255,255,255,.035);
}

.external-tool-detail-grid {
  display: grid;
  grid-template-columns: 1fr;
}

.external-tool-detail-row {
  display: grid;
  grid-template-columns: 150px minmax(0, 1fr);
  gap: 12px;
  padding: 9px 12px;
  border-bottom: 1px solid rgba(255,255,255,.06);
}

.external-tool-detail-row:last-child {
  border-bottom: 0;
}

.external-tool-detail-label {
  color: var(--terminal-muted, #8f9bb3);
  font-size: 12px;
}

.external-tool-detail-value {
  min-width: 0;
  overflow: hidden;
}

.external-tool-detail-value.multiline {
  white-space: normal;
  overflow: visible;
}

.external-tool-detail-pre {
  margin: 0;
  max-height: 260px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 10px;
  border-radius: 8px;
  background: #050505;
  border: 1px solid rgba(255,255,255,.10);
  color: #d9e2ff;
  scrollbar-color: #303544 #050505;
  scrollbar-width: thin;
}

.external-tool-detail-pre::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}

.external-tool-detail-pre::-webkit-scrollbar-track {
  background: #050505;
  border-radius: 999px;
}

.external-tool-detail-pre::-webkit-scrollbar-thumb {
  background: #303544;
  border-radius: 999px;
  border: 2px solid #050505;
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
