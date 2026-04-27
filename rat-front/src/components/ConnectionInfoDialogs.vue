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

    commandCandidates: {
      type: Array,
      default: () => [],
    },

    commandCandidatesLoadedFor: {
      type: [String, Number],
      default: '',
    },

    loadCommandCandidates: {
      type: Function,
      default: null,
    },

    getConnectionStatusText: {
      type: Function,
      default: null,
    },

    formatConnectionLastSeen: {
      type: Function,
      default: null,
    },

    formatDateTimeStandard: {
      type: Function,
      default: null,
    },

    formatConnectionRtt: {
      type: Function,
      default: null,
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
    }
  },

  computed: {
    connectionInfoClientCommands() {
      return (this.commandCandidates || []).filter(item => item && item.source === 'client')
    },

    connectionInfoCards() {
      const conn = this.currentConnection || {}
      const items = [
        { label: 'Status', value: this.formatStatusText(conn) },
        { label: 'Hostname', value: conn.hostname || '-' },
        { label: 'Address', value: conn.addr || '-', mono: true },
        { label: 'Client ID', value: conn.client_id || '-', mono: true },
        // {label: 'Platform', value: this.formatOsLabel(conn.os_type, conn.os_ver) || '-'},
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
        // {label: 'Machine ID Version', value: conn.machine_id_version || '-'},
        { label: 'Fingerprint Basis', value: conn.machine_fingerprint_basis || '-', mono: true },
        { label: 'Last Seen', value: this.formatLastSeenText(conn) },
        { label: 'Connected At', value: this.formatDateTime(conn.connected_at) || '-' },
        { label: 'Disconnected At', value: this.formatDateTime(conn.disconnected_at) || '-' },
        { label: 'RTT', value: this.formatRttText(conn) },
        { label: 'Working Directory', value: conn.cwd || '-', mono: true },
        { label: 'PID', value: conn.process_id || '-' },
        { label: 'Process Name', value: conn.process_name || '-' },
        { label: 'Launch Command', value: conn.launch_command || '-' },
        { label: 'Username', value: conn.username || '-' },
        { label: 'Python Version', value: conn.python_ver || '-' },
        { label: 'HTTP Transfer Mode', value: conn.http_transfer_mode || '-' },
        { label: 'Python Execution Mode', value: conn.python_execution_mode || '-' },
        { label: 'Remote Watchdog Enabled', value: conn.remote_watchdog_enabled },
        { label: 'Local Watchdog Enabled', value: conn.local_watchdog_enabled },
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

      try {
        if (
          typeof this.loadCommandCandidates === 'function' &&
          (this.commandCandidatesLoadedFor !== this.selectedId || !this.commandCandidates.length)
        ) {
          await this.loadCommandCandidates(this.selectedId)
        }

        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs`)
        const json = await res.json()

        if (res.ok && json.code === 0 && Array.isArray(json.data)) {
          this.jobCount = json.data.length
        }
      } catch (e) {
      } finally {
        this.loading = false
      }
    },

    formatStatusText(conn) {
      if (typeof this.getConnectionStatusText === 'function') {
        return this.getConnectionStatusText(conn)
      }

      return conn?.connection_state || '-'
    },

    formatLastSeenText(conn) {
      if (typeof this.formatConnectionLastSeen === 'function') {
        return this.formatConnectionLastSeen(conn)
      }

      return this.formatDateTime(conn?.last_seen_at) || '-'
    },

    formatDateTime(value) {
      if (typeof this.formatDateTimeStandard === 'function') {
        return this.formatDateTimeStandard(value)
      }

      return value || '-'
    },

    formatRttText(conn) {
      if (typeof this.formatConnectionRtt === 'function') {
        return this.formatConnectionRtt(conn)
      }

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
  },
}
</script>

<style scoped>
.connection-info-body {
  display: flex;
  flex-direction: column;
  min-height: 0;
  gap: 14px;
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

/*
.connection-info-stat-label {
  font-size: 12px;
  line-height: 16px;
  font-weight: 400;
  color: var(--muted);
  overflow: hidden;
  word-break: break-word;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  min-height: 16px;
  font-family: inherit;
}
*/

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

.connection-info-stat-expandable:hover {
  background: #f3f7ff;
  border-color: rgba(37, 99, 235, 0.18);
  box-shadow: 0 0 0 1px rgba(37, 99, 235, 0.05);
}

.connection-command-panel {
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 12px;
  background: #fafcff;
  overflow: hidden;
}

.connection-command-panel-title {
  padding: 10px 12px;
  font-size: 13px;
  font-weight: 700;
  border-bottom: 1px solid rgba(15, 23, 42, 0.06);
  background: #f8fafc;
}

.connection-command-list {
  max-height: 360px;
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
  .connection-info-stats-grid {
    grid-template-columns: repeat(1, minmax(0, 1fr));
  }
}
</style>

<style>
/* ConnectionInfoDialogs: 信息卡和命令列表由组件内部管理滚动。 */
.connection-info-overlay .el-dialog__body,
.connection-info-value-overlay .el-dialog__body {
  overflow: hidden !important;
}
</style>