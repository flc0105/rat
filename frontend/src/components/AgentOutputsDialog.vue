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

          <el-button
            class="toolbar-btn"
            size="small"
            type="danger"
            plain
            :disabled="!selectedOutputFileNames.length"
            :loading="bulkDeleting"
            @click="deleteSelectedAgentOutputs"
          >
            Delete Selected{{ selectedOutputFileNames.length ? ` (${selectedOutputFileNames.length})` : '' }}
          </el-button>
        </div>

        <div class="agent-outputs-toolbar-right">
          <el-select
            v-model="outputBuilderFilter"
            class="agent-output-builder-filter"
            clearable
            filterable
            size="small"
            placeholder="Filter builder"
          >
            <el-option
              v-for="builder in builderOptions"
              :key="builder"
              :label="builder"
              :value="builder"
            />
          </el-select>

          <span class="agent-outputs-count">
            {{ outputCountText }}
          </span>
        </div>
      </div>

      <div class="agent-outputs-table-wrap">
        <el-table
          :data="filteredOutputs"
          v-loading="loading"
          stripe
          border
          height="100%"
          table-layout="fixed"
          row-key="file_name"
          class="dialog-table-shell"
          empty-text="No agent outputs"
          @selection-change="handleOutputSelectionChange"
        >
          <el-table-column
            type="selection"
            width="46"
            align="center"
          />
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
import { formatBytes, formatDateTimeStandard } from '../utils/formatters.js'

export default {
  name: 'AgentOutputsDialog',

  props: {
    // formatDateTimeStandard: {
    //   type: Function,
    //   default: null,
    // },
    //
    // formatBytes: {
    //   type: Function,
    //   default: null,
    // },
  },

  emits: [
    'open-builder',
  ],

  data() {
    return {
      visible: false,
      loading: false,
      outputs: [],
      outputBuilderFilter: '',
      selectedOutputFileNames: [],
      bulkDeleting: false,
      agentOutputsDeleting: {},
    }
  },

  computed: {
    builderOptions() {
      const builders = new Set()
      ;(this.outputs || []).forEach(item => {
        const builder = String(item?.builder || '').trim()
        if (builder) builders.add(builder)
      })
      return Array.from(builders).sort((a, b) => a.localeCompare(b))
    },

    filteredOutputs() {
      const builder = String(this.outputBuilderFilter || '').trim()
      if (!builder) return this.outputs || []
      return (this.outputs || []).filter(item => String(item?.builder || '').trim() === builder)
    },

    selectedOutputs() {
      const selected = new Set(this.selectedOutputFileNames)
      return (this.outputs || []).filter(item => selected.has(String(item?.file_name || '').trim()))
    },

    outputCountText() {
      const count = this.filteredOutputs.length
      const total = this.outputs.length
      const base = `${count} ${count === 1 ? 'output' : 'outputs'}`
      return count === total ? base : `${base} / ${total} total`
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
  return formatDateTimeStandard(value)
},

formatOutputBytes(value) {
  return formatBytes(value)
},

    handleOutputSelectionChange(rows) {
      this.selectedOutputFileNames = (rows || [])
        .map(item => String(item?.file_name || '').trim())
        .filter(Boolean)
    },

    pruneOutputSelection() {
      const available = new Set(
        (this.outputs || [])
          .map(item => String(item?.file_name || '').trim())
          .filter(Boolean)
      )
      this.selectedOutputFileNames = this.selectedOutputFileNames.filter(item => available.has(item))
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
        this.pruneOutputSelection()
      } catch (e) {
        this.outputs = []

        if (!silent) {
          ElMessage.error(e.message || 'Failed to load agent outputs')
        }
      } finally {
        if (!silent) this.loading = false
      }
    },

    async requestDeleteAgentOutput(fileName) {
      const normalized = String(fileName || '').trim()
      if (!normalized) throw new Error('Invalid file name')

      const res = await fetch(`/api/agent/outputs/${encodeURIComponent(normalized)}`, {
        method: 'DELETE',
      })
      const json = await res.json()

      if (!res.ok || json.code !== 0) {
        throw new Error(json.message || 'Delete failed')
      }

      return json.data || {}
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
        await this.requestDeleteAgentOutput(fileName)
        this.outputs = this.outputs.filter(item => String(item?.file_name || '').trim() !== fileName)
        this.selectedOutputFileNames = this.selectedOutputFileNames.filter(item => item !== fileName)
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

    async deleteSelectedAgentOutputs() {
      const selected = this.selectedOutputs
      if (!selected.length || this.bulkDeleting) return

      try {
        await ElMessageBox.confirm(
          `Delete ${selected.length} selected agent output(s)?`,
          'Delete Selected Agent Outputs',
          {
            confirmButtonText: 'Delete',
            cancelButtonText: 'Cancel',
            type: 'warning',
          }
        )
      } catch (_e) {
        return
      }

      this.bulkDeleting = true
      let deletedCount = 0
      let failedCount = 0
      const deletingMap = { ...this.agentOutputsDeleting }

      selected.forEach(item => {
        const fileName = String(item?.file_name || '').trim()
        if (fileName) deletingMap[fileName] = true
      })
      this.agentOutputsDeleting = deletingMap

      try {
        for (const item of selected) {
          const fileName = String(item?.file_name || '').trim()
          if (!fileName) continue

          try {
            await this.requestDeleteAgentOutput(fileName)
            deletedCount += 1
          } catch (_e) {
            failedCount += 1
          } finally {
            this.agentOutputsDeleting = {
              ...this.agentOutputsDeleting,
              [fileName]: false,
            }
          }
        }

        const deletedNames = new Set(selected.map(item => String(item?.file_name || '').trim()).filter(Boolean))
        this.outputs = this.outputs.filter(item => !deletedNames.has(String(item?.file_name || '').trim()))
        this.selectedOutputFileNames = []

        if (failedCount) {
          ElMessage.warning(`Deleted ${deletedCount}, failed ${failedCount}`)
        } else {
          ElMessage.success(`Deleted ${deletedCount} item(s)`)
        }
      } finally {
        this.bulkDeleting = false
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

.agent-output-builder-filter {
  width: 180px;
}

.agent-output-builder-filter :deep(.el-select__wrapper) {
  min-height: 32px;
  height: 32px;
  border-radius: 10px;
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
    flex-wrap: wrap;
  }

  .agent-output-builder-filter {
    width: 100%;
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