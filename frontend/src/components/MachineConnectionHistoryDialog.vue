<template>
  <el-dialog
    v-model="visible"
    :title="dialogTitle"
    width="1180px"
    top="4vh"
    class="machine-connection-history-dialog"
    destroy-on-close
  >
    <div class="machine-history-body" v-loading="loading">
      <div class="machine-history-toolbar">
        <div class="machine-history-identity">
          <div class="machine-history-device-name">{{ deviceName || 'Unknown device' }}</div>
          <div class="machine-history-machine-id">machine_id: {{ machineId || '-' }}</div>
        </div>

        <el-button size="small" @click="loadHistory">
          Refresh
        </el-button>
      </div>

      <div class="machine-history-stats">
        <div class="machine-history-stat">
          <div class="machine-history-stat-label">Known sessions</div>
          <div class="machine-history-stat-value">{{ history.known_session_count || 0 }}</div>
        </div>
        <div class="machine-history-stat">
          <div class="machine-history-stat-label">Tracked connections</div>
          <div class="machine-history-stat-value">{{ history.tracked_connection_count || 0 }}</div>
        </div>
        <div class="machine-history-stat">
          <div class="machine-history-stat-label">Online now</div>
          <div class="machine-history-stat-value">{{ history.online_session_count || 0 }}</div>
        </div>
        <div class="machine-history-stat">
          <div class="machine-history-stat-label">Known commands</div>
          <div class="machine-history-stat-value">{{ history.known_command_count || 0 }}</div>
        </div>
        <div class="machine-history-stat">
          <div class="machine-history-stat-label">Tracked online time</div>
          <div class="machine-history-stat-value">{{ formatDuration(history.total_online_duration_ms) }}</div>
        </div>
      </div>

      <el-alert
        v-if="history.unassigned_command_count"
        class="machine-history-alert"
        type="warning"
        :closable="false"
        show-icon
        :title="`${history.unassigned_command_count} command record(s) have no client_id and cannot be assigned to a session.`"
      />

      <el-table
        v-if="sessions.length"
        :data="sessions"
        row-key="client_id"
        border
        stripe
        class="machine-history-table"
      >
        <el-table-column type="expand" width="48">
          <template #default="scope">
            <div class="machine-session-detail">
              <div class="machine-session-meta-grid">
                <div class="machine-session-meta-item">
                  <span class="label">Hostname</span>
                  <span class="value">{{ scope.row.hostname || '-' }}</span>
                </div>
                <div class="machine-session-meta-item">
                  <span class="label">Address</span>
                  <span class="value">{{ scope.row.addr || '-' }}</span>
                </div>
                <div class="machine-session-meta-item">
                  <span class="label">OS</span>
                  <span class="value">{{ formatOs(scope.row) }}</span>
                </div>
                <div class="machine-session-meta-item">
                  <span class="label">User</span>
                  <span class="value">{{ scope.row.username || '-' }}</span>
                </div>
                <div class="machine-session-meta-item">
                  <span class="label">Process</span>
                  <span class="value">{{ formatProcess(scope.row) }}</span>
                </div>
                <div class="machine-session-meta-item">
                  <span class="label">Build</span>
                  <span class="value">{{ scope.row.build_version || '-' }}</span>
                </div>
                <div class="machine-session-meta-item">
                  <span class="label">Last seen</span>
                  <span class="value">{{ formatDateTime(scope.row.last_seen_at) }}</span>
                </div>
                <div class="machine-session-meta-item">
                  <span class="label">Disconnect</span>
                  <span class="value">{{ scope.row.disconnect_reason || '-' }}</span>
                </div>
                <div class="machine-session-meta-item machine-session-meta-wide">
                  <span class="label">Current / last cwd</span>
                  <span class="value">{{ scope.row.cwd || '-' }}</span>
                </div>
              </div>

              <div class="machine-session-command-header">
                <span>Commands ({{ scope.row.command_count || 0 }})</span>
                <span class="machine-session-command-summary">
                  success {{ scope.row.command_success_count || 0 }} ·
                  error {{ scope.row.command_error_count || 0 }} ·
                  running {{ scope.row.command_running_count || 0 }}
                </span>
              </div>

              <el-table
                v-if="scope.row.commands && scope.row.commands.length"
                :data="scope.row.commands"
                size="small"
                border
                max-height="320"
                class="machine-session-command-table"
              >
                <el-table-column label="Started" width="160">
                  <template #default="commandScope">
                    {{ formatDateTime(commandScope.row.started_at) }}
                  </template>
                </el-table-column>
                <el-table-column label="Status" width="92">
                  <template #default="commandScope">
                    <el-tag
                      size="small"
                      :type="commandStatusTagType(commandScope.row.status)"
                    >
                      {{ commandScope.row.status || 'unknown' }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column prop="source" label="Source" width="100" />
                <el-table-column label="Command" min-width="280">
                  <template #default="commandScope">
                    <code class="machine-session-command-text">{{ commandScope.row.command || '-' }}</code>
                  </template>
                </el-table-column>
                <el-table-column label="Duration" width="100">
                  <template #default="commandScope">
                    {{ formatDuration(commandScope.row.duration_ms) }}
                  </template>
                </el-table-column>
                <el-table-column label="Output / files" min-width="200">
                  <template #default="commandScope">
                    <div class="machine-session-output-summary">
                      {{ commandScope.row.output_summary || '-' }}
                      <span v-if="commandScope.row.file_count">
                        · {{ commandScope.row.file_count }} file(s)
                      </span>
                    </div>
                  </template>
                </el-table-column>
              </el-table>

              <div v-else class="empty-state compact">
                No retained command records for this session
              </div>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="#" width="58">
          <template #default="scope">
            {{ scope.$index + 1 }}
          </template>
        </el-table-column>

        <el-table-column label="State" width="138">
          <template #default="scope">
            <el-tag
              size="small"
              :type="sessionStatusTagType(scope.row)"
            >
              {{ sessionStatusText(scope.row) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="client_id" min-width="210">
          <template #default="scope">
            <code class="machine-session-client-id">{{ scope.row.client_id || '-' }}</code>
          </template>
        </el-table-column>

        <el-table-column label="Online" width="170">
          <template #default="scope">
            {{ formatDateTime(scope.row.connected_at) }}
          </template>
        </el-table-column>

        <el-table-column label="Offline" width="170">
          <template #default="scope">
            {{ scope.row.connection_state === 'online' ? 'online' : formatDateTime(scope.row.disconnected_at) }}
          </template>
        </el-table-column>

        <el-table-column label="Duration" width="108">
          <template #default="scope">
            {{ formatDuration(scope.row.duration_ms) }}
          </template>
        </el-table-column>

        <el-table-column label="Commands" width="92" align="right">
          <template #default="scope">
            {{ scope.row.command_count || 0 }}
          </template>
        </el-table-column>
      </el-table>

      <div v-else-if="!loading" class="empty-state machine-history-empty">
        No connection history for this machine yet
      </div>

      <div v-if="history.tracking_started_at" class="machine-history-footer-note">
        Connection lifecycle and command executions are stored in rch.db. Command details are loaded from the permanent execution history for each client session.
      </div>
    </div>
  </el-dialog>
</template>

<script>
import { ElMessage } from 'element-plus'
import { getMachineConnectionHistory } from '../api/connectionsApi.js'

export default {
  name: 'MachineConnectionHistoryDialog',

  data() {
    return {
      visible: false,
      loading: false,
      machineId: '',
      deviceName: '',
      history: {
        sessions: [],
      },
    }
  },

  computed: {
    dialogTitle() {
      return this.deviceName ? `Connection History · ${this.deviceName}` : 'Connection History'
    },

    sessions() {
      return Array.isArray(this.history.sessions) ? this.history.sessions : []
    },
  },

  methods: {
    open(item = {}) {
      this.machineId = String(item.machine_id || '').trim()
      this.deviceName = String(
        item.device_display_name || item.display_hostname || item.device_alias || item.hostname || '',
      ).trim()
      this.visible = true
      return this.loadHistory()
    },

    async loadHistory() {
      if (!this.machineId) {
        this.history = { sessions: [] }
        return
      }

      this.loading = true
      try {
        this.history = await getMachineConnectionHistory(this.machineId)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to load connection history')
      } finally {
        this.loading = false
      }
    },

    formatDateTime(value) {
      const text = String(value || '').trim()
      if (!text) return '-'
      return text.replace('T', ' ').split('.')[0]
    },

    formatDuration(durationMs) {
      const totalSeconds = Math.max(Math.floor(Number(durationMs || 0) / 1000), 0)
      if (!totalSeconds) return '0s'

      const days = Math.floor(totalSeconds / 86400)
      const hours = Math.floor((totalSeconds % 86400) / 3600)
      const minutes = Math.floor((totalSeconds % 3600) / 60)
      const seconds = totalSeconds % 60
      const parts = []

      if (days) parts.push(`${days}d`)
      if (hours) parts.push(`${hours}h`)
      if (minutes) parts.push(`${minutes}m`)
      if (seconds || !parts.length) parts.push(`${seconds}s`)

      return parts.slice(0, 3).join(' ')
    },

    formatOs(row) {
      const type = String(row?.os_type || row?.os_name || '').trim()
      const version = String(row?.os_ver || '').trim()
      return [type, version].filter(Boolean).join(' ') || '-'
    },

    formatProcess(row) {
      const processName = String(row?.process_name || '').trim()
      const processId = String(row?.process_id || '').trim()
      if (processName && processId) return `${processName} (${processId})`
      return processName || processId || '-'
    },

    sessionStatusText(row) {
      if (row?.connection_state === 'online') return 'online'
      if (row?.connection_state === 'interrupted') return 'interrupted'
      return 'offline'
    },

    sessionStatusTagType(row) {
      if (row?.connection_state === 'online') return 'success'
      if (row?.connection_state === 'interrupted') return 'warning'
      return 'info'
    },

    commandStatusTagType(status) {
      if (status === 'success') return 'success'
      if (status === 'error') return 'danger'
      if (status === 'running') return 'warning'
      return 'info'
    },
  },
}
</script>

<style scoped>
.machine-history-body {
  min-height: 260px;
}

.machine-history-toolbar {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 14px;
}

.machine-history-identity {
  min-width: 0;
}

.machine-history-device-name {
  font-size: 15px;
  font-weight: 700;
  color: var(--el-text-color-primary);
}

.machine-history-machine-id {
  margin-top: 4px;
  color: var(--el-text-color-secondary);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  overflow-wrap: anywhere;
}

.machine-history-stats {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}

.machine-history-stat {
  padding: 12px 14px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 8px;
  background: var(--el-fill-color-extra-light);
}

.machine-history-stat-label {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}

.machine-history-stat-value {
  margin-top: 5px;
  color: var(--el-text-color-primary);
  font-size: 17px;
  font-weight: 700;
}

.machine-history-alert {
  margin-bottom: 12px;
}

.machine-history-table {
  width: 100%;
}

.machine-session-detail {
  padding: 12px 18px 18px 62px;
  background: var(--el-fill-color-extra-light);
}

.machine-session-meta-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px 18px;
  margin-bottom: 16px;
}

.machine-session-meta-item {
  display: flex;
  min-width: 0;
  gap: 8px;
  font-size: 12px;
}

.machine-session-meta-item .label {
  flex: 0 0 auto;
  color: var(--el-text-color-secondary);
}

.machine-session-meta-item .value {
  min-width: 0;
  color: var(--el-text-color-regular);
  overflow-wrap: anywhere;
}

.machine-session-meta-wide {
  grid-column: span 2;
}

.machine-session-command-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin: 2px 0 8px;
  font-size: 13px;
  font-weight: 700;
  color: var(--el-text-color-primary);
}

.machine-session-command-summary {
  color: var(--el-text-color-secondary);
  font-size: 12px;
  font-weight: 400;
}

.machine-session-command-text,
.machine-session-client-id {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.machine-session-command-text {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.machine-session-output-summary {
  color: var(--el-text-color-secondary);
  font-size: 12px;
  overflow-wrap: anywhere;
}

.machine-history-empty {
  padding: 56px 0;
}

.machine-history-footer-note {
  margin-top: 12px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
  line-height: 1.6;
}

@media (max-width: 900px) {
  .machine-history-stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .machine-session-meta-grid {
    grid-template-columns: 1fr;
  }

  .machine-session-meta-wide {
    grid-column: span 1;
  }

  .machine-session-detail {
    padding-left: 12px;
  }
}
</style>
