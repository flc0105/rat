<template>
  <el-dialog
    v-model="infoVisible"
    title="Connection Info"
    width="980px"
    top="6vh"
    class="fixed-dialog connection-info-dialog"
    modal-class="connection-info-overlay"
  >
    <div
      class="fixed-dialog-body connection-info-body"
      v-loading="loading"
    >
      <el-tabs
        v-model="activeTab"
        class="connection-info-tabs"
      >
        <el-tab-pane
          label="Basic Info"
          name="basic"
          class="connection-info-tab-pane"
        >
          <div class="connection-info-tab-scroll">
            <div class="connection-info-stats-grid">
              <div
                v-for="item in connectionInfoCards"
                :key="item.label"
                class="connection-info-stat connection-info-stat-expandable"
                @click="openConnectionInfoValueDialog(item)"
              >
                <div class="connection-info-stat-label">
                  {{ item.label }}
                </div>

                <div
                  class="connection-info-stat-value"
                  :class="{ mono: item.mono }"
                >
                  {{ item.fullValue }}
                </div>
              </div>
            </div>
          </div>
        </el-tab-pane>

        <el-tab-pane
          label="Commands"
          name="commands"
          class="connection-info-tab-pane connection-info-command-tab"
        >
          <div class="connection-command-panel">
            <div class="connection-command-panel-title">
              Command List
            </div>

            <div class="connection-command-list">
              <div
                v-for="(item, index) in connectionInfoClientCommands"
                :key="`${item.template}-${index}`"
                class="connection-command-item"
              >
                <div class="connection-command-group">
                  <span v-if="item.group">{{ item.group }}</span>
                </div>

                <div class="connection-command-text">
                  <span class="mono">{{ item.name || item.template }}</span>
                  <span v-if="item.help"> — {{ item.help }}</span>
                </div>
              </div>

              <div
                v-if="!connectionInfoClientCommands.length"
                class="empty-state compact"
              >
                No commands available
              </div>
            </div>
          </div>
        </el-tab-pane>

        <el-tab-pane
          label="Configuration"
          name="configuration"
          class="connection-info-tab-pane"
        >
          <div
            class="connection-info-tab-scroll"
            v-loading="runtimeConfigLoading"
          >
            <div
              v-if="runtimeConfigError"
              class="empty-state compact"
            >
              {{ runtimeConfigError }}
            </div>

            <div
              v-else-if="runtimeConfigItems.length"
              class="connection-info-stats-grid"
            >
              <div
                v-for="item in runtimeConfigItems"
                :key="item.key"
                class="connection-info-stat connection-config-stat"
                :class="{ 'connection-config-stat-editable': item.editable !== false }"
                :title="item.editable !== false ? 'Double-click to edit' : ''"
                @dblclick="openRuntimeConfigEditor(item)"
              >
                <div class="connection-config-stat-head">
                  <div class="connection-info-stat-label">
                    {{ item.key }}
                  </div>
                  <span
                    v-if="item.source === 'override'"
                    class="connection-config-override-badge"
                  >
                    override
                  </span>
                </div>

                <div class="connection-info-stat-value">
                  {{ formatRuntimeConfigValue(item.value) }}
                </div>
              </div>
            </div>

            <div
              v-else-if="!runtimeConfigLoading"
              class="empty-state compact"
            >
              No runtime configuration available
            </div>
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>
  </el-dialog>

  <el-dialog
    v-model="valueVisible"
    :title="valueTitle || 'Details'"
    width="760px"
    top="12vh"
    class="fixed-dialog connection-info-value-dialog"
    modal-class="connection-info-value-overlay"
  >
    <div class="fixed-dialog-body connection-info-value-body">
      <pre class="connection-info-full-value">{{ valueValue || '-' }}</pre>
    </div>
  </el-dialog>

  <el-dialog
    v-model="runtimeConfigEditorVisible"
    title="Edit Configuration"
    width="560px"
    top="14vh"
    class="connection-config-editor-dialog"
    modal-class="connection-config-editor-overlay"
    :close-on-click-modal="false"
  >
    <div
      v-if="runtimeConfigEditorItem"
      class="connection-config-editor"
    >
      <div class="connection-config-editor-key-row">
        <span class="connection-config-editor-key">
          {{ runtimeConfigEditorItem.key }}
        </span>
        <span
          v-if="runtimeConfigEditorItem.source === 'override'"
          class="connection-config-override-badge"
        >
          override
        </span>
      </div>

      <div
        v-if="runtimeConfigEditorItem.desc"
        class="connection-config-editor-desc"
      >
        {{ runtimeConfigEditorItem.desc }}
      </div>

      <div class="connection-config-editor-meta">
        <div>
          <span>Current</span>
          <strong>{{ formatRuntimeConfigValue(runtimeConfigEditorItem.value) }}</strong>
        </div>
        <div>
          <span>Default</span>
          <strong>{{ formatRuntimeConfigValue(runtimeConfigEditorItem.default_value) }}</strong>
        </div>
      </div>

      <div class="connection-config-editor-control">
        <el-select
          v-if="runtimeConfigEditorChoices.length"
          :key="`${runtimeConfigEditorItem.key}:${formatRuntimeConfigValue(runtimeConfigEditorItem.value)}`"
          v-model="runtimeConfigEditorValue"
          style="width: 100%"
        >
          <el-option
            v-for="choice in runtimeConfigEditorChoices"
            :key="String(choice)"
            :label="String(choice)"
            :value="choice"
          />
        </el-select>

        <el-switch
          v-else-if="runtimeConfigEditorItem.value_type === 'boolean'"
          v-model="runtimeConfigEditorValue"
        />

        <el-input-number
          v-else-if="runtimeConfigEditorItem.value_type === 'integer'"
          v-model="runtimeConfigEditorValue"
          :step="1"
          controls-position="right"
          style="width: 100%"
        />

        <el-input-number
          v-else-if="runtimeConfigEditorItem.value_type === 'float'"
          v-model="runtimeConfigEditorValue"
          controls-position="right"
          style="width: 100%"
        />

        <el-input
          v-else
          v-model="runtimeConfigEditorValue"
        />
      </div>
    </div>

    <template #footer>
      <div class="connection-config-editor-footer">
        <el-button
          :disabled="runtimeConfigSaving || runtimeConfigEditorItem?.source !== 'override'"
          @click="resetRuntimeConfigEditorItem"
        >
          Reset Default
        </el-button>

        <div class="connection-config-editor-footer-right">
          <el-button
            :disabled="runtimeConfigSaving"
            @click="runtimeConfigEditorVisible = false"
          >
            Cancel
          </el-button>
          <el-button
            type="primary"
            :loading="runtimeConfigSaving"
            @click="saveRuntimeConfigEditorItem"
          >
            Save
          </el-button>
        </div>
      </div>
    </template>
  </el-dialog>
</template>

<script>
import { ElMessage } from 'element-plus'

export default {
  name: 'ConnectionInfoDialogs',

  props: {
    selectedId: {
      type: [String, Number],
      default: '',
    },

    currentConnection: {
      type: Object,
      default: null,
    },

    statusNowTick: {
      type: Number,
      default: () => Date.now(),
    },
  },

  data() {
    return {
      infoVisible: false,
      valueVisible: false,
      loading: false,
      jobCount: 0,
      valueTitle: '',
      valueValue: '',
      connectionInfoClientCommands: [],
      activeTab: 'basic',
      runtimeConfigItems: [],
      runtimeConfigStorePath: '',
      runtimeConfigLoading: false,
      runtimeConfigLoaded: false,
      runtimeConfigError: '',
      runtimeConfigEditorVisible: false,
      runtimeConfigEditorItem: null,
      runtimeConfigEditorValue: '',
      runtimeConfigSaving: false,
    }
  },

  computed: {
    connectionInfoCards() {
      const conn = this.currentConnection || {}
      const items = [
        { label: 'Status', value: this.formatStatusText(conn) },
        { label: 'Hostname', value: conn.hostname || '-' },
        { label: 'Address', value: conn.addr || '-', mono: true },
        { label: 'Client ID', value: conn.client_id || '-', mono: true },
        { label: 'OS Type', value: conn.os_type },
        { label: 'Platform', value: conn.os_full || '-' },
        { label: 'OS Name', value: conn.os_name },
        { label: 'OS Version', value: conn.os_ver },
        { label: 'OS Alias', value: conn.os_alias },
        { label: 'Arch', value: conn.arch },
        { label: 'Manufacturer', value: conn.manufacturer },
        { label: 'Model', value: conn.model },
        { label: 'Integrity', value: conn.integrity || '-' },
        { label: 'Build Version', value: conn.build_version || '-' },
        { label: 'Machine ID', value: conn.machine_id || '-', mono: true },
        { label: 'Fingerprint Basis', value: conn.machine_fingerprint_basis || '-', mono: true },
        { label: 'Last Seen', value: this.formatLastSeenText(conn) },
        { label: 'Connected At', value: this.formatDateTimeStandard(conn.connected_at) || '-' },
        { label: 'Disconnected At', value: this.formatDateTimeStandard(conn.disconnected_at) || '-' },
        { label: 'RTT', value: this.formatRttText(conn) },
        { label: 'Working Directory', value: conn.cwd || '-', mono: true },
        { label: 'PID', value: conn.process_id || '-' },
        { label: 'Process Name', value: conn.process_name || '-' },
        { label: 'Launch Command', value: conn.launch_command || '-' },
        { label: 'Username', value: conn.username || '-' },
        { label: 'Python Version', value: conn.python_ver || '-' },
        { label: 'Reported Jobs', value: this.jobCount },
        { label: 'Command Count', value: this.connectionInfoClientCommands.length },
      ]

      return items.map(item => {
        const fullValue = this.normalizeConnectionInfoValue(item.value)
        return {
          ...item,
          fullValue,
          expandable: this.isConnectionInfoValueExpandable(fullValue),
        }
      })
    },

    runtimeConfigEditorChoices() {
      const choices = this.runtimeConfigEditorItem?.choices
      if (!Array.isArray(choices)) return []

      return choices.map(choice => this.normalizeRuntimeConfigChoiceValue(
        choice,
        this.runtimeConfigEditorItem?.value_type,
      ))
    },
  },

  watch: {
    activeTab(value) {
      if (value === 'configuration' && this.infoVisible && !this.runtimeConfigLoaded) {
        this.loadRuntimeConfig(this.selectedId)
      }
    },
  },

  methods: {
    async open() {
      if (!this.selectedId) {
        ElMessage.warning('Please select a device')
        return
      }

      this.infoVisible = true
      this.loading = true
      this.jobCount = 0
      this.valueVisible = false
      this.valueTitle = ''
      this.valueValue = ''
      this.connectionInfoClientCommands = []
      this.activeTab = 'basic'
      this.runtimeConfigItems = []
      this.runtimeConfigStorePath = ''
      this.runtimeConfigLoaded = false
      this.runtimeConfigError = ''
      this.runtimeConfigEditorVisible = false
      this.runtimeConfigEditorItem = null

      try {
        await Promise.all([
          this.loadConnectionInfoClientCommands(this.selectedId),
          this.loadConnectionInfoJobCount(this.selectedId),
        ])
      } catch (e) {
      } finally {
        this.loading = false
      }
    },

    async loadConnectionInfoClientCommands(clientId) {
      const res = await fetch(`/api/connections/${encodeURIComponent(clientId)}/command-candidates`)
      const json = await res.json()

      if (!res.ok || json.code !== 0) {
        throw new Error(json.message || 'Failed to load command candidates')
      }

      this.connectionInfoClientCommands = (Array.isArray(json.data) ? json.data : [])
        .filter(item => item && item.source === 'client' && item.suggest !== false)
        .map(item => this.normalizeConnectionInfoCommand(item))
    },

    async loadConnectionInfoJobCount(clientId) {
      const res = await fetch(`/api/connections/${encodeURIComponent(clientId)}/background-jobs`)
      const json = await res.json()

      if (res.ok && json.code === 0 && Array.isArray(json.data)) {
        this.jobCount = json.data.length
      }
    },

    async loadRuntimeConfig(clientId) {
      if (!clientId || this.runtimeConfigLoading) return

      this.runtimeConfigLoading = true
      this.runtimeConfigError = ''

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(clientId)}/runtime-config`)
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to load runtime configuration')
        }

        this.applyRuntimeConfigPayload(json.data)
        this.runtimeConfigLoaded = true
      } catch (e) {
        this.runtimeConfigItems = []
        this.runtimeConfigLoaded = false
        this.runtimeConfigError = e?.message || 'Failed to load runtime configuration'
      } finally {
        this.runtimeConfigLoading = false
      }
    },

    applyRuntimeConfigPayload(payload) {
      const data = payload && typeof payload === 'object' ? payload : {}
      this.runtimeConfigStorePath = String(data.store_path || '')
      this.runtimeConfigItems = Array.isArray(data.items)
        ? data.items.filter(item => item && item.key)
        : []
    },

    normalizeConnectionInfoCommand(item) {
      const template = String(item.template || '').trim()
      const name = String(item.name || template || '').trim()
      const help = String(item.help || '').trim()
      const group = String(item.group || '').trim()
      const source = String(item.source || '').trim()

      return {
        ...item,
        value: template,
        name,
        template,
        help,
        group,
        source,
      }
    },

    // 连接状态展示逻辑放在组件内，避免继续依赖 legacy connection formatter。
    getConnectionDisplayState(conn) {
      const state = String((conn && conn.connection_state) || '').trim()
      if (state === 'offline') return 'offline'

      if (conn && conn.is_transfer_active) {
        return 'online'
      }

      const disconnectedAt = String((conn && conn.disconnected_at) || '').trim()
      if (disconnectedAt) return 'offline'

      const lastSeenAt = String((conn && conn.last_seen_at) || '').trim()
      if (!lastSeenAt) return state || 'online'

      const staleAfterSeconds = Number((conn && conn.stale_after_seconds) || 45)
      const seenMs = Date.parse(lastSeenAt)
      if (!Number.isFinite(seenMs)) return state || 'online'

      const ageMs = Math.max(this.statusNowTick - seenMs, 0)
      if (ageMs > staleAfterSeconds * 1000) return 'stale'

      return 'online'
    },

    formatStatusText(conn) {
      const state = this.getConnectionDisplayState(conn)
      if (state === 'online') return 'online'
      if (state === 'stale') return 'stale'
      return 'offline'
    },

    formatLastSeenText(conn) {
      if (!conn) return '-'

      const state = this.getConnectionDisplayState(conn)
      if (state === 'offline') {
        return this.formatDateTimeStandard(conn.disconnected_at) || '-'
      }

      return this.formatDateTimeStandard(conn.last_seen_at) || '-'
    },

    formatDateTimeStandard(value) {
      const text = String(value || '').trim()
      if (!text) return '-'

      const normalized = text.replace('T', ' ').split('.')[0]
      return normalized || '-'
    },

    formatRttText(conn) {
      const value = conn && conn.last_rtt_ms
      if (value === null || value === undefined || value === '') return '-'
      return `${value} ms`
    },

    normalizeConnectionInfoValue(value) {
      if (value === null || value === undefined || value === '') return '-'
      if (typeof value === 'boolean') return value ? 'true' : 'false'
      if (Array.isArray(value)) {
        return value.length ? value.join(', ') : '-'
      }
      if (typeof value === 'object') {
        try {
          return JSON.stringify(value, null, 2)
        } catch (_error) {
          return String(value)
        }
      }
      return String(value)
    },

    isConnectionInfoValueExpandable(value) {
      const text = this.normalizeConnectionInfoValue(value)
      if (!text || text === '-') return false
      return text.length > 42 || text.includes('\n')
    },

    openConnectionInfoValueDialog(item) {
      if (!item) return
      this.valueTitle = item.label || 'Details'
      this.valueValue = item.fullValue || '-'
      this.valueVisible = true
    },

    formatRuntimeConfigValue(value) {
      if (value === null || value === undefined) return 'None'
      if (typeof value === 'boolean') return value ? 'true' : 'false'
      return String(value)
    },

    openRuntimeConfigEditor(item) {
      if (!item || item.editable === false) return

      this.runtimeConfigEditorItem = item
      this.runtimeConfigEditorValue = this.normalizeRuntimeConfigEditorValue(item)
      this.runtimeConfigEditorVisible = true
    },

    normalizeRuntimeConfigEditorValue(item) {
      const valueType = String(item?.value_type || '')
      const choices = Array.isArray(item?.choices) ? item.choices : []
      const value = this.normalizeRuntimeConfigChoiceValue(item?.value, valueType)

      if (choices.length) {
        const matchedChoice = choices
          .map(choice => this.normalizeRuntimeConfigChoiceValue(choice, valueType))
          .find(choice => Object.is(choice, value))
        if (matchedChoice !== undefined) return matchedChoice
      }

      if (valueType === 'boolean') return Boolean(value)
      if (valueType === 'integer' || valueType === 'float') {
        const numeric = Number(value)
        return Number.isFinite(numeric) ? numeric : 0
      }
      if (value === null || value === undefined) return ''
      return String(value)
    },

    normalizeRuntimeConfigChoiceValue(value, valueType) {
      if (valueType === 'boolean') {
        if (typeof value === 'string') return value.trim().toLowerCase() === 'true'
        return Boolean(value)
      }
      if (valueType === 'integer' || valueType === 'float') {
        const numeric = Number(value)
        return Number.isFinite(numeric) ? numeric : value
      }
      if (value === null || value === undefined) return ''
      return String(value)
    },

    async saveRuntimeConfigEditorItem() {
      const item = this.runtimeConfigEditorItem
      if (!item || !this.selectedId || this.runtimeConfigSaving) return

      this.runtimeConfigSaving = true

      try {
        const res = await fetch(
          `/api/connections/${encodeURIComponent(this.selectedId)}/runtime-config/${encodeURIComponent(item.key)}`,
          {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ value: this.runtimeConfigEditorValue }),
          },
        )
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to update runtime configuration')
        }

        this.applyRuntimeConfigPayload(json.data)
        this.runtimeConfigLoaded = true
        this.runtimeConfigEditorVisible = false
        ElMessage.success(`${item.key} updated`)
      } catch (e) {
        ElMessage.error(e?.message || 'Failed to update runtime configuration')
      } finally {
        this.runtimeConfigSaving = false
      }
    },

    async resetRuntimeConfigEditorItem() {
      const item = this.runtimeConfigEditorItem
      if (!item || !this.selectedId || item.source !== 'override' || this.runtimeConfigSaving) return

      this.runtimeConfigSaving = true

      try {
        const res = await fetch(
          `/api/connections/${encodeURIComponent(this.selectedId)}/runtime-config/${encodeURIComponent(item.key)}`,
          { method: 'DELETE' },
        )
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to reset runtime configuration')
        }

        this.applyRuntimeConfigPayload(json.data)
        this.runtimeConfigLoaded = true
        this.runtimeConfigEditorVisible = false
        ElMessage.success(`${item.key} reset to default`)
      } catch (e) {
        ElMessage.error(e?.message || 'Failed to reset runtime configuration')
      } finally {
        this.runtimeConfigSaving = false
      }
    },
  },
}
</script>

<style scoped>
.connection-info-body {
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.connection-info-tabs {
  height: 100%;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

.connection-info-tabs :deep(.el-tabs__header) {
  flex: 0 0 auto;
  margin-bottom: 12px;
}

.connection-info-tabs :deep(.el-tabs__content) {
  flex: 1 1 auto;
  min-height: 0;
  overflow: hidden;
}

.connection-info-tabs :deep(.el-tab-pane) {
  height: 100%;
  min-height: 0;
}

.connection-info-tab-pane {
  height: 100%;
  min-height: 0;
}

.connection-info-tab-scroll {
  height: 100%;
  min-height: 0;
  overflow-y: auto;
  padding-right: 2px;
}

.connection-info-stats-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.connection-info-stat {
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
  overflow: hidden;
  min-width: 0;
  padding: 12px 14px;
  border-radius: 12px;
  background: #f8fafc;
  border: 1px solid rgba(15, 23, 42, 0.05);
}

.connection-info-stat-label {
  font-size: 12px;
  line-height: 16px;
  font-weight: 400;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  overflow: hidden;
  word-break: break-word;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  min-height: 16px;
  font-family: inherit;
}

.connection-info-stat-value {
  margin-top: 4px;
  font-size: 13px;
  line-height: 18px;
  font-weight: 400;
  color: var(--text);
  overflow: hidden;
  word-break: break-word;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  min-height: 36px;
  font-family: inherit;
}

.connection-info-stat .mono {
  font-family: inherit !important;
  font-size: 13px;
  line-height: 18px;
  font-weight: 400;
}

.connection-info-stat-expandable {
  cursor: pointer;
  transition: border-color 0.18s ease, background 0.18s ease, box-shadow 0.18s ease;
}

.connection-info-stat-expandable:hover,
.connection-config-stat-editable:hover {
  background: #f3f7ff;
  border-color: rgba(37, 99, 235, 0.18);
  box-shadow: 0 0 0 1px rgba(37, 99, 235, 0.05);
}

.connection-config-stat-editable {
  cursor: pointer;
  transition: border-color 0.18s ease, background 0.18s ease, box-shadow 0.18s ease;
}

.connection-config-stat-head {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  min-width: 0;
}

.connection-config-stat-head .connection-info-stat-label {
  flex: 1 1 auto;
  min-width: 0;
}

.connection-config-override-badge {
  flex: 0 0 auto;
  padding: 1px 6px;
  border-radius: 999px;
  background: #fff7ed;
  border: 1px solid #fed7aa;
  color: #c2410c;
  font-size: 10px;
  line-height: 16px;
  font-weight: 400;
  text-transform: none;
  letter-spacing: 0;
}

.connection-info-command-tab {
  display: flex;
  flex-direction: column;
}

.connection-command-panel {
  height: 100%;
  min-height: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 12px;
  background: #fafcff;
  overflow: hidden;
}

.connection-command-panel-title {
  flex: 0 0 auto;
  padding: 10px 12px;
  font-size: 13px;
  font-weight: 700;
  border-bottom: 1px solid rgba(15, 23, 42, 0.06);
  background: #f8fafc;
}

.connection-command-list {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.connection-command-item {
  padding: 10px 12px;
  border-radius: 10px;
  background: #fff;
  border: 1px solid rgba(15, 23, 42, 0.05);
}

.connection-command-group {
  min-height: 13px;
  font-size: 11px;
  color: var(--muted-2);
  margin-bottom: 6px;
}

.connection-command-text {
  font-size: 13px;
  line-height: 1.6;
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-word;
}

.connection-info-full-value {
  margin: 0;
  padding: 14px;
  min-height: 220px;
  max-height: 62vh;
  overflow: auto;
  border-radius: 14px;
  background: #f8fafc;
  border: 1px solid rgba(15, 23, 42, 0.06);
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.65;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
}

.connection-config-editor {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.connection-config-editor-key-row {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.connection-config-editor-key {
  min-width: 0;
  overflow-wrap: anywhere;
  color: var(--text);
  font-size: 14px;
  font-weight: 700;
}

.connection-config-editor-desc {
  color: var(--muted);
  font-size: 13px;
  line-height: 1.6;
}

.connection-config-editor-meta {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.connection-config-editor-meta > div {
  min-width: 0;
  padding: 10px 12px;
  border-radius: 10px;
  background: #f8fafc;
  border: 1px solid rgba(15, 23, 42, 0.06);
}

.connection-config-editor-meta span,
.connection-config-editor-meta strong {
  display: block;
}

.connection-config-editor-meta span {
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.connection-config-editor-meta strong {
  margin-top: 4px;
  color: var(--text);
  font-size: 13px;
  font-weight: 500;
  overflow-wrap: anywhere;
}

.connection-config-editor-control {
  min-height: 40px;
  display: flex;
  align-items: center;
}

.connection-config-editor-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.connection-config-editor-footer-right {
  display: flex;
  gap: 10px;
}

@media (max-width: 1200px) {
  .connection-info-stats-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 860px) {
  .connection-info-stats-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 480px) {
  .connection-info-stats-grid,
  .connection-config-editor-meta {
    grid-template-columns: repeat(1, minmax(0, 1fr));
  }

  .connection-config-editor-footer {
    align-items: stretch;
    flex-direction: column;
  }

  .connection-config-editor-footer-right {
    justify-content: flex-end;
  }
}
</style>

<style>
/* ConnectionInfoDialogs: 主对话框固定高度，Tab 内容只在内部滚动。 */
.connection-info-overlay .el-dialog {
  height: 680px;
  max-height: 88vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.connection-info-overlay .el-dialog__header {
  flex: 0 0 auto;
}

.connection-info-overlay .el-dialog__body {
  flex: 1 1 auto;
  min-height: 0;
  overflow: hidden !important;
}

.connection-info-value-overlay .el-dialog__body {
  overflow: hidden !important;
}
</style>
