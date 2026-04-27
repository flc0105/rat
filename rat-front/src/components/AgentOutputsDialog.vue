<template>
  <el-dialog
    v-model="visible"
    title="Agent Outputs"
    width="1280px"
    top="4vh"
    class="fixed-dialog agent-outputs-dialog"
    modal-class="agent-outputs-overlay"
  >
    <div class="fixed-dialog-body agent-outputs-body">
      <div class="agent-outputs-toolbar">
        <div class="agent-outputs-toolbar-left">
          <el-button
            type="primary"
            plain
            class="toolbar-btn"
            size="small"
            @click="$emit('open-builder')"
          >
            Build Agent
          </el-button>

          <el-button
            class="toolbar-btn"
            size="small"
            :loading="loading"
            @click="loadAgentOutputs"
          >
            Refresh
          </el-button>
        </div>

        <div class="agent-outputs-toolbar-right">
          <span class="agent-outputs-count">
            {{ outputCountText }}
          </span>
        </div>
      </div>

      <div class="agent-outputs-table-wrap">
        <el-table
          :data="outputs"
          v-loading="loading"
          stripe
          border
          height="100%"
          table-layout="fixed"
          class="dialog-table-shell"
          empty-text="No agent outputs"
        >
          <el-table-column
            label="File"
            min-width="320"
          >
            <template #default="{ row }">
              <div class="agent-output-file-cell">
                <div
                  class="agent-output-file-name"
                  :title="row.file_name"
                >
                  {{ row.file_name || '-' }}
                </div>
              </div>
            </template>
          </el-table-column>

          <el-table-column
            label="Builder"
            min-width="110"
          >
            <template #default="{ row }">
              {{ row.builder || '-' }}
            </template>
          </el-table-column>

          <el-table-column
            label="Version"
            min-width="200"
          >
            <template #default="{ row }">
              <span>{{ row.build_version || '-' }}</span>
            </template>
          </el-table-column>

          <el-table-column
            label="OS"
            min-width="100"
          >
            <template #default="{ row }">
              <el-tag
                size="small"
                effect="plain"
              >
                {{ describeAgentTargetOs(row.target_os) }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column
            label="Arch"
            min-width="100"
          >
            <template #default="{ row }">
              <el-tag
                size="small"
                type="info"
                effect="plain"
              >
                {{ row.target_arch || '-' }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column
            label="Source"
            min-width="110"
          >
            <template #default="{ row }">
              {{ formatAgentSourceText(row.source) }}
            </template>
          </el-table-column>

          <el-table-column
            label="Socket"
            min-width="180"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <span class="agent-output-mono">
                {{ formatAgentListenerText(row) }}
              </span>
            </template>
          </el-table-column>

          <el-table-column
            label="Web"
            min-width="220"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <span class="agent-output-mono">
                {{ formatAgentWebListenerText(row) }}
              </span>
            </template>
          </el-table-column>

          <el-table-column
            label="Build Time"
            min-width="200"
          >
            <template #default="{ row }">
              {{ formatOutputDateTime(row.build_time) }}
            </template>
          </el-table-column>

          <el-table-column
            label="Size"
            min-width="120"
          >
            <template #default="{ row }">
              <span>{{ formatOutputBytes(row.size) }}</span>
            </template>
          </el-table-column>

          <el-table-column
            label="Actions"
            width="170"
            fixed="right"
          >
            <template #default="{ row }">
              <div class="agent-output-actions">
                <a
                  class="table-action-link"
                  :href="row.download_url || '#'"
                  target="_blank"
                  rel="noreferrer"
                >
                  Download
                </a>

                <a
                  class="table-action-link danger"
                  :class="{ disabled: isAgentOutputDeleting(row.file_name) }"
                  @click.prevent="deleteAgentOutput(row)"
                >
                  {{ isAgentOutputDeleting(row.file_name) ? 'Deleting...' : 'Delete' }}
                </a>
              </div>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </div>
  </el-dialog>
</template>

<script>
import { ElMessage, ElMessageBox } from 'element-plus'

export default {
  name: 'AgentOutputsDialog',

  props: {
    formatDateTimeStandard: {
      type: Function,
      default: null,
    },

    formatBytes: {
      type: Function,
      default: null,
    },
  },

  emits: [
    'open-builder',
  ],

  data() {
    return {
      visible: false,
      loading: false,
      outputs: [],
      agentOutputsDeleting: {},
    }
  },

  computed: {
    outputCountText() {
      const count = this.outputs.length
      return `${count} ${count === 1 ? 'output' : 'outputs'}`
    },
  },

  methods: {
    async open() {
      this.visible = true
      await this.loadAgentOutputs()
    },

    isOpen() {
      return this.visible
    },

    async refreshIfOpen(options = {}) {
      if (!this.visible) return
      await this.loadAgentOutputs(options)
    },

    describeAgentTargetOs(targetOs) {
      const mapping = {
        win: 'Windows',
        mac: 'macOS',
        linux: 'Linux',
        bundle: 'Bundle',
      }

      return mapping[targetOs] || targetOs || 'macOS'
    },

    formatAgentSourceText(value) {
      const source = String(value || '').trim()
      if (!source) return '-'

      const mapping = {
        manual: 'Manual',
        update: 'Update',
        loader: 'Loader',
      }

      return mapping[source] || source
    },

    formatAgentListenerText(row) {
      const host = String(row?.server_host || '').trim()
      const port = Number(row?.server_port || 0)
      if (!host || !port) return '-'
      return `${host}:${port}`
    },

    formatAgentWebListenerText(row) {
      const scheme = String(row?.server_web_scheme || 'http').trim() || 'http'
      const host = String(row?.server_web_host || row?.server_host || '').trim()
      const port = Number(row?.web_port || 0)
      if (!host || !port) return '-'
      return `${scheme}://${host}:${port}`
    },

    formatOutputDateTime(value) {
      if (typeof this.formatDateTimeStandard === 'function') {
        return this.formatDateTimeStandard(value)
      }

      return value || '-'
    },

    formatOutputBytes(value) {
      if (typeof this.formatBytes === 'function') {
        return this.formatBytes(value)
      }

      const size = Number(value || 0)
      if (!Number.isFinite(size) || size <= 0) return '-'
      if (size < 1024) return `${size} B`
      if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
      return `${(size / 1024 / 1024).toFixed(1)} MB`
    },

    isAgentOutputDeleting(fileName) {
      return Boolean(this.agentOutputsDeleting[String(fileName || '').trim()])
    },

    async loadAgentOutputs({ silent = false } = {}) {
      if (!silent) this.loading = true

      try {
        const res = await fetch('/api/agent/outputs')
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to load agent outputs')
        }

        this.outputs = Array.isArray(json.data) ? json.data : []
      } catch (e) {
        this.outputs = []

        if (!silent) {
          ElMessage.error(e.message || 'Failed to load agent outputs')
        }
      } finally {
        if (!silent) this.loading = false
      }
    },

    async deleteAgentOutput(row) {
      const fileName = String(row?.file_name || '').trim()
      if (!fileName || this.isAgentOutputDeleting(fileName)) return

      try {
        await ElMessageBox.confirm(
          `Delete agent output ${fileName}?`,
          'Delete agent output',
          {
            confirmButtonText: 'Delete',
            cancelButtonText: 'Cancel',
            type: 'warning',
          }
        )
      } catch (_e) {
        return
      }

      this.agentOutputsDeleting = {
        ...this.agentOutputsDeleting,
        [fileName]: true,
      }

      try {
        const res = await fetch(`/api/agent/outputs/${encodeURIComponent(fileName)}`, {
          method: 'DELETE',
        })
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Delete failed')
        }

        this.outputs = this.outputs.filter(item => String(item?.file_name || '').trim() !== fileName)
        ElMessage.success('Deleted')
      } catch (e) {
        ElMessage.error(e.message || 'Delete failed')
      } finally {
        this.agentOutputsDeleting = {
          ...this.agentOutputsDeleting,
          [fileName]: false,
        }
      }
    },
  },
}
</script>

<style scoped>
.agent-outputs-body {
  display: flex;
  flex: 1 1 auto;
  flex-direction: column;
  width: 100%;
  height: 100%;
  min-width: 0;
  min-height: 0;
  overflow: hidden;
  box-sizing: border-box;
}

.agent-outputs-toolbar {
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  min-width: 0;
  gap: 12px;
  margin-bottom: 12px;
  box-sizing: border-box;
}

.agent-outputs-toolbar-left,
.agent-outputs-toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.agent-outputs-toolbar-left {
  flex: 1 1 auto;
}

.agent-outputs-toolbar-right {
  flex: 0 0 auto;
  justify-content: flex-end;
  margin-left: auto;
}

.agent-outputs-toolbar :deep(.el-button.toolbar-btn) {
  height: 32px;
  min-height: 32px;
  padding: 0 12px;
  border-radius: 10px;
  margin: 0;
}

.agent-outputs-count {
  font-size: 13px;
  color: #667085;
  white-space: nowrap;
}

.agent-outputs-table-wrap {
  flex: 1 1 auto;
  width: 100%;
  min-width: 0;
  min-height: 0;
  overflow: hidden;
}

.agent-outputs-table-wrap :deep(.el-table) {
  width: 100% !important;
  height: 100% !important;
}

.agent-outputs-table-wrap :deep(.el-table__body-wrapper) {
  overflow-y: auto !important;
}

.agent-output-file-cell {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
  padding: 2px 0;
}

.agent-output-file-name {
  min-width: 0;
  color: #111827;
  line-height: 1.45;
  word-break: break-all;
}

.agent-output-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  font-size: 12px;
  color: #374151;
  word-break: break-all;
}

.agent-output-actions {
  display: flex;
  align-items: center;
  gap: 12px;
  padding-top: 2px;
}

.agent-output-actions .disabled {
  opacity: 0.55;
  pointer-events: none;
}

@media (max-width: 768px) {
  .agent-outputs-toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .agent-outputs-toolbar-left,
  .agent-outputs-toolbar-right {
    width: 100%;
  }

  .agent-outputs-toolbar-left {
    flex-wrap: wrap;
  }

  .agent-outputs-toolbar-right {
    justify-content: flex-start;
    margin-left: 0;
  }
}
</style>

<style>
/* AgentOutputsDialog: 构建产物状态和表格滚动放在组件内部。 */
.agent-outputs-overlay .el-dialog {
  height: 76vh !important;
  max-height: 76vh !important;
  display: flex !important;
  flex-direction: column !important;
  overflow: hidden !important;
}

.agent-outputs-overlay .el-dialog__header {
  flex: 0 0 auto !important;
}

.agent-outputs-overlay .el-dialog__body {
  display: flex !important;
  flex: 1 1 auto !important;
  width: 100% !important;
  min-width: 0 !important;
  min-height: 0 !important;
  overflow: hidden !important;
  box-sizing: border-box !important;
}

.agent-outputs-overlay .agent-outputs-body {
  flex: 1 1 auto !important;
  width: 100% !important;
  min-height: 0 !important;
}

@media (min-width: 769px) {
  .agent-outputs-overlay .el-dialog {
    width: 1280px !important;
    max-width: calc(100vw - 32px) !important;
    height: 76vh !important;
    max-height: 76vh !important;
    margin: 4vh auto 0 !important;
    border-radius: var(--el-border-radius-small) !important;
  }
}

@media (max-width: 768px) {
  .agent-outputs-overlay .el-dialog {
    width: 100vw !important;
    max-width: 100vw !important;
    height: 100dvh !important;
    max-height: 100dvh !important;
    margin: 0 !important;
    border-radius: 0 !important;
  }

  .agent-outputs-overlay .el-dialog__header {
    padding: 14px 16px 10px !important;
  }

  .agent-outputs-overlay .el-dialog__body {
    padding: 10px 12px 12px !important;
  }
}
</style>