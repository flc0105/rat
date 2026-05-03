<template>
  <el-dialog
    :model-value="visible"
    title="Artifact Manager"
    width="1160px"
    top="5vh"
    class="fixed-dialog artifact-dialog"
    modal-class="artifact-overlay"
    @update:model-value="handleVisibleChange"
  >
    <div class="fixed-dialog-body">
      <div class="dialog-head">
        <div class="dialog-head-left">
          <el-button
            size="small"
            @click="loadArtifacts"
          >
            Refresh
          </el-button>

          <el-button
            v-if="isServerFilesTab"
            size="small"
            type="primary"
            :loading="serverFileUploading"
            @click="triggerServerFileUpload"
          >
            Upload
          </el-button>

          <el-button
            size="small"
            type="danger"
            :loading="artifactClearing"
            @click="clearArtifactCategory"
          >
            Clear
          </el-button>
        </div>

        <div class="dialog-head-right">
          <div
            v-if="showArtifactMachineFilter"
            class="dialog-path-box artifact-filter-box"
          >
            <el-select
              v-model="artifactMachineIdFilter"
              clearable
              filterable
              placeholder="Filter by device"
              @change="handleMachineFilterChange"
            >
<!--              <el-option-->
<!--                v-for="item in artifactMachines"-->
<!--                :key="item.machine_id"-->
<!--                :label="formatArtifactMachineOptionLabel(item)"-->
<!--                :value="item.machine_id"-->
<!--              />-->
              <el-option
  v-for="item in artifactMachineOptions"
  :key="item.machine_id"
  :label="formatArtifactMachineOptionLabel(item)"
  :value="item.machine_id"
/>
            </el-select>
          </div>
        </div>
      </div>

      <input
        ref="serverFileUploadInputRef"
        type="file"
        class="artifact-hidden-file-input"
        @change="handleServerFileUploadChange"
      />

      <el-tabs
        :model-value="artifactActiveTab"
        class="artifact-tabs"
        @update:model-value="handleActiveTabChange"
      >
        <el-tab-pane name="files">
          <template #label>
            Downloads ({{ artifactCountMap.files || 0 }})
          </template>
        </el-tab-pane>



                <el-tab-pane name="command_output">
          <template #label>
            Command Output ({{ artifactCountMap.command_output || 0 }})
          </template>
        </el-tab-pane>

        <el-tab-pane name="previews">
          <template #label>
            Previews ({{ artifactCountMap.previews || 0 }})
          </template>
        </el-tab-pane>

                        <el-tab-pane name="server_files">
          <template #label>
            Server Files ({{ artifactCountMap.server_files || 0 }})
          </template>
        </el-tab-pane>


      </el-tabs>

      <div class="dialog-table-shell">
        <el-table
          :data="filteredArtifactItems"
          v-loading="artifactLoading"
          stripe
          width="100%"
          height="100%"
          empty-text="No artifacts available"
          table-layout="fixed"
        >
          <el-table-column
            prop="original_name"
            label="Name"
            min-width="280"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <div class="ellipsis">
                {{ formatArtifactName(row) }}
              </div>
            </template>
          </el-table-column>

          <el-table-column
            v-if="!isServerFilesTab"
            label="Hostname"
            min-width="180"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <div class="ellipsis">
                {{ row.hostname || '-' }}
              </div>
            </template>
          </el-table-column>

          <el-table-column
            v-if="!isServerFilesTab"
            label="Category"
            min-width="160"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <div class="ellipsis">
                {{ row.category || '-' }}
              </div>
            </template>
          </el-table-column>

          <el-table-column
            label="Size"
            width="110"
            align="center"
          >
            <template #default="{ row }">
              {{ formatBytes(row.size) }}
            </template>
          </el-table-column>

          <el-table-column
            label="Created"
            width="170"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <div class="ellipsis">
                {{ row.created_at || '-' }}
              </div>
            </template>
          </el-table-column>

          <el-table-column
            label="Actions"
            :width="isServerFilesTab ? 190 : 200"
            align="center"
            fixed="right"
          >
            <template #default="{ row }">
              <div class="table-actions table-actions-links">
                <a
                  href="#"
                  class="table-action-link"
                  @click.prevent="$emit('preview', row)"
                >
                  Preview
                </a>

                <a
                  class="table-action-link"
                  :href="row.download_url"
                  target="_blank"
                >
                  Download
                </a>

                <template v-if="isServerFileItem(row)">
                  <el-dropdown
                    trigger="click"
                    @command="command => handleArtifactMoreCommand(row, command)"
                  >
                    <span class="table-action-link">More</span>
                    <template #dropdown>
                      <el-dropdown-menu>
                        <el-dropdown-item
                          command="send-current-device"
                          :disabled="!selectedId"
                        >
                          Send to Current Device
                        </el-dropdown-item>
                        <el-dropdown-item
                          command="delete"
                          divided
                        >
                          Delete
                        </el-dropdown-item>
                      </el-dropdown-menu>
                    </template>
                  </el-dropdown>
                </template>

                <a
                  v-else
                  href="#"
                  class="table-action-link danger"
                  @click.prevent="deleteArtifact(row)"
                >
                  Delete
                </a>
              </div>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div class="mobile-file-list-shell">
        <div
          class="mobile-file-list"
          v-loading="artifactLoading"
        >
          <div
            v-if="!filteredArtifactItems.length && !artifactLoading"
            class="empty-state"
          >
            No artifacts available
          </div>

          <div
            v-else
            class="mobile-file-grid"
          >
            <div
              v-for="row in filteredArtifactItems"
              :key="row.artifact_id"
              class="mobile-file-card"
            >
              <div class="mobile-file-card-top">
                <div class="mobile-file-icon">📄</div>

                <div class="mobile-file-main">
                  <div class="mobile-file-name">
                    {{ formatArtifactName(row) }}
                  </div>

                  <div
                    v-if="row.hostname && !isServerFileItem(row)"
                    class="mobile-file-tags"
                  >
                    <el-tag size="small">
                      {{ row.hostname }}
                    </el-tag>
                  </div>

                  <div class="mobile-file-meta">
                    <div
                      v-if="!isServerFileItem(row)"
                      class="mobile-file-meta-item"
                    >
                      <div class="mobile-file-meta-label">Category</div>
                      <div class="mobile-file-meta-value">
                        {{ row.category || '-' }}
                      </div>
                    </div>

                    <div class="mobile-file-meta-item">
                      <div class="mobile-file-meta-label">Size</div>
                      <div class="mobile-file-meta-value">
                        {{ formatBytes(row.size) }}
                      </div>
                    </div>

                    <div class="mobile-file-meta-item">
                      <div class="mobile-file-meta-label">Created</div>
                      <div class="mobile-file-meta-value">
                        {{ row.created_at || '-' }}
                      </div>
                    </div>
                  </div>

                  <div class="mobile-file-actions">
                    <el-button
                      size="small"
                      type="primary"
                      plain
                      @click="$emit('preview', row)"
                    >
                      Preview
                    </el-button>

                    <a :href="row.download_url" target="_blank">
                      <el-button size="small" type="primary" plain>
                        Download
                      </el-button>
                    </a>

                    <template v-if="isServerFileItem(row)">
                      <el-dropdown
                        trigger="click"
                        @command="command => handleArtifactMoreCommand(row, command)"
                      >
                        <el-button size="small" type="primary" plain>
                          More
                        </el-button>
                        <template #dropdown>
                          <el-dropdown-menu>
                            <el-dropdown-item
                              command="send-current-device"
                              :disabled="!selectedId"
                            >
                              Send
                            </el-dropdown-item>
                            <el-dropdown-item
                              command="delete"
                              divided
                            >
                              Delete
                            </el-dropdown-item>
                          </el-dropdown-menu>
                        </template>
                      </el-dropdown>
                    </template>

                    <el-button
                      v-else
                      size="small"
                      type="danger"
                      plain
                      @click="deleteArtifact(row)"
                    >
                      Delete
                    </el-button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </el-dialog>
</template>

<script>
import { ElMessage, ElMessageBox } from 'element-plus'
import { formatBytes as formatBytesValue } from '../utils/formatters.js'

export default {
  name: 'ArtifactDialog',

  props: {
    // formatBytes: {
    //   type: Function,
    //   required: true,
    // },

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
      default: () => ({}),
    },
  },

  emits: ['preview', 'append-output', 'set-active-task'],

  data() {
    return {
      visible: false,
      artifactLoading: false,
      artifactItems: [],
      artifactMachines: [],
      artifactActiveTab: 'files',
      artifactMachineIdFilter: '',
      artifactClearing: false,
      serverFileUploading: false,
    }
  },

  computed: {
    isServerFilesTab() {
      return String(this.artifactActiveTab || '').trim() === 'server_files'
    },

    isCommandOutputTab() {
      return String(this.artifactActiveTab || '').trim() === 'command_output'
    },

    showArtifactMachineFilter() {
      return !this.isServerFilesTab
    },

    showArtifactCategoryColumn() {
      return !this.isServerFilesTab && !this.isCommandOutputTab
    },

    artifactMachineOptions() {
  const map = {}

  ;(this.artifactMachines || []).forEach(item => {
    const machineId = this.normalizeMachineId(item?.machine_id)
    if (!machineId) return

    map[machineId] = {
      ...item,
      machine_id: machineId,
      hostname: String(item?.hostname || '').trim(),
    }
  })

  const currentMachineId = this.getCurrentMachineId()
  if (currentMachineId) {
    const existing = map[currentMachineId] || {}
    const currentHostname = String(this.currentConnection?.hostname || '').trim()

    // 当前选中设备即使还没有 artifact，也要出现在筛选框里。
    map[currentMachineId] = {
      ...existing,
      machine_id: currentMachineId,
      hostname: currentHostname || String(existing.hostname || '').trim(),
    }
  }

  return Object.values(map).sort((a, b) =>
    this.formatArtifactMachineOptionLabel(a).localeCompare(
      this.formatArtifactMachineOptionLabel(b)
    )
  )
},

    filteredArtifactItems() {
      const activeType = String(this.artifactActiveTab || '').trim()
      const machineId = String(this.artifactMachineIdFilter || '').trim()

      return (this.artifactItems || []).filter(item => {
        if (activeType && item.artifact_type !== activeType) return false
        if (!this.isServerFileItem(item) && machineId && item.machine_id !== machineId) return false
        return true
      })
    },

    artifactCountMap() {
      const machineId = String(this.artifactMachineIdFilter || '').trim()
      const counts = { files: 0, previews: 0, server_files: 0, command_output: 0 }

      ;(this.artifactItems || []).forEach(item => {
        if (!item) return

        const type = String(item.artifact_type || '').trim()
        if (!Object.prototype.hasOwnProperty.call(counts, type)) return

        if (type !== 'server_files' && machineId && item.machine_id !== machineId) return
        counts[type] += 1
      })

      return counts
    },
  },

  methods: {
    // async open() {
    //   this.visible = true
    //   await this.loadArtifacts()
    // },

    formatBytes(value) {
      return formatBytesValue(value)
    },

    async open() {
      this.artifactMachineIdFilter = this.getCurrentMachineId()
      this.visible = true
      await this.loadArtifacts()
    },

    normalizeMachineId(value) {
      return String(value || '').trim()
    },

    getCurrentMachineId() {
      return this.normalizeMachineId(this.currentConnection?.machine_id)
    },

    shortenMachineId(machineId) {
      const value = this.normalizeMachineId(machineId)
      if (!value) return '-'

      return value.length > 12 ? value.slice(0, 12) : value
    },

    formatArtifactMachineOptionLabel(machine) {
      const machineId = this.normalizeMachineId(machine?.machine_id)
      if (!machineId) return '-'

      const shortId = this.shortenMachineId(machineId)
      const hostname = String(machine?.hostname || '').trim()

      return hostname ? `${shortId} (${hostname})` : shortId
    },

    formatArtifactName(row) {
      return row?.original_name || row?.stored_name || 'artifact'
    },

    isServerFileItem(item) {
      return String(item?.artifact_type || '').trim() === 'server_files'
    },

    buildJsonHeaders(extra = {}) {
      if (typeof this.getTabScopedHeaders === 'function') {
        return this.getTabScopedHeaders(extra)
      }
      return extra
    },

    isOpen() {
      return this.visible
    },

    async refreshIfOpen() {
      if (!this.visible) return
      await this.loadArtifacts()
    },

    handleVisibleChange(value) {
      this.visible = value

      if (!value) {
        this.artifactMachineIdFilter = ''
      }
    },

    async handleActiveTabChange(tabName) {
      this.artifactActiveTab = tabName || 'files'
      if (!this.isServerFilesTab && !this.artifactMachineIdFilter) {
        this.artifactMachineIdFilter = this.getCurrentMachineId()
      }
      await this.loadArtifacts()
    },

    async handleMachineFilterChange() {
      await this.loadArtifacts()
    },

    async loadArtifacts() {
      this.artifactLoading = true

      try {
        const url = new URL('/api/artifacts', window.location.origin)

        // 保持前端统一持有三类 artifact，设备过滤只在视图层处理。
        const res = await fetch(url.pathname + url.search)
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to load artifacts')
        }

        const data = json.data || {}
        this.artifactItems = Array.isArray(data.items) ? data.items : []
        this.artifactMachines = Array.isArray(data.machines) ? data.machines : []
      } catch (e) {
        this.artifactItems = []
        this.artifactMachines = []
        ElMessage.error(e.message || 'Failed to load artifacts')
      } finally {
        this.artifactLoading = false
      }
    },

    triggerServerFileUpload() {
      const input = this.$refs.serverFileUploadInputRef

      if (input) {
        input.value = ''
        input.click()
      }
    },

    async handleServerFileUploadChange(event) {
      const file = event.target.files && event.target.files[0]
      if (!file) return

      const formData = new FormData()
      formData.append('file', file)
      formData.append('artifact_type', 'server_files')

      this.serverFileUploading = true

      try {
        const res = await fetch('/api/files/upload', {
          method: 'POST',
          headers: this.buildJsonHeaders(),
          body: formData,
        })
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Upload failed')
        }

        ElMessage.success(`Uploaded: ${file.name}`)
        await this.loadArtifacts()
      } catch (e) {
        ElMessage.error(e.message || 'Upload failed')
      } finally {
        this.serverFileUploading = false
        if (event?.target) event.target.value = ''
      }
    },

    async handleArtifactMoreCommand(row, command) {
      if (command === 'send-current-device') {
        await this.sendArtifactToCurrentDevice(row)
        return
      }
      if (command === 'delete') {
        await this.deleteArtifact(row)
      }
    },

    async sendArtifactToCurrentDevice(row) {
      if (!row || !row.artifact_id) {
        ElMessage.warning('Invalid artifact')
        return
      }

      const clientId = String(this.selectedId || this.currentConnection?.client_id || '').trim()
      if (!clientId) {
        ElMessage.warning('Please select a device')
        return
      }

      const displayName = this.formatArtifactName(row)
      this.$emit(
        'append-output',
        clientId,
        `> [Artifact Send] ${displayName} -> current device`,
        'command'
      )

      try {
        const res = await fetch(`/api/artifacts/${encodeURIComponent(row.artifact_id)}/send-to-client`, {
          method: 'POST',
          headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({
            client_id: clientId,
            target_path: '',
          }),
        })
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Send failed')
        }

        const taskId = json.data && json.data.task_id
        this.$emit('set-active-task', clientId, taskId || '')
        ElMessage.success(`Send started: ${displayName}`)
      } catch (e) {
        this.$emit(
          'append-output',
          clientId,
          `[Artifact send failed] ${e.message || 'unknown error'}`,
          'error'
        )
        ElMessage.error(e.message || 'Send failed')
      }
    },

    async deleteArtifact(row) {
      if (!row || !row.artifact_id) {
        ElMessage.warning('Invalid artifact')
        return
      }

      try {
        await ElMessageBox.confirm(
          `Delete "${this.formatArtifactName(row)}"?`,
          'Delete Confirmation',
          { type: 'warning', confirmButtonText: 'Delete', cancelButtonText: 'Cancel' }
        )

        const res = await fetch(`/api/artifacts/${encodeURIComponent(row.artifact_id)}`, {
          method: 'DELETE',
        })
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Delete failed')
        }

        ElMessage.success('Deleted')
        await this.loadArtifacts()
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return
        ElMessage.error(e.message || 'Delete failed')
      }
    },

    async clearArtifactCategory() {
      const activeType = String(this.artifactActiveTab || '').trim()

      if (!activeType) {
        ElMessage.warning('Please select a category')
        return
      }

      try {
        const suffix = this.showArtifactMachineFilter && this.artifactMachineIdFilter ? ' for selected device' : ''

        await ElMessageBox.confirm(
          `Clear all ${activeType}${suffix}?`,
          'Clear Artifacts',
          { type: 'warning', confirmButtonText: 'Clear', cancelButtonText: 'Cancel' }
        )

        this.artifactClearing = true

        const res = await fetch('/api/artifacts/clear', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: activeType,
            machine_id: this.showArtifactMachineFilter ? (this.artifactMachineIdFilter || '') : '',
          }),
        })

        const json = await res.json()
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Clear failed')
        }

        ElMessage.success(`Cleared ${json.data?.deleted_count || 0} item(s)`)
        await this.loadArtifacts()
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return
        ElMessage.error(e.message || 'Clear failed')
      } finally {
        this.artifactClearing = false
      }
    },
  },
}
</script>

<style scoped>
/* ArtifactDialog 逻辑和样式都收在组件内，App 只负责打开和预览回调。 */
.fixed-dialog-body {
  height: 100%;
  min-height: 0;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.dialog-head {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 10px;
  align-items: center;
  margin-bottom: 12px;
  flex-shrink: 0;
}

.dialog-head-left {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  min-width: 0;
}

.dialog-head-left :deep(.el-button) {
  height: 32px;
  min-height: 32px;
  margin: 0;
  padding-inline: 12px;
  border-radius: 10px;
}

.dialog-head-right {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex: 1 1 auto;
  min-width: 0;
  width: 100%;
  margin-left: auto;
}

.artifact-filter-box {
  display: flex;
  justify-content: flex-end;
  min-width: 300px;
  margin-left: auto;
}

.artifact-filter-box :deep(.el-select) {
  display: block;
  width: 300px;
  font-size: 12px;
}

.artifact-filter-box :deep(.el-select__wrapper),
.artifact-filter-box :deep(.el-input__wrapper) {
  min-height: 32px;
  height: 32px;
  border-radius: 10px;
  font-size: 12px;
}

.artifact-hidden-file-input {
  display: none;
}

.artifact-tabs {
  flex: 0 0 auto;
  min-height: 0;
}

.artifact-tabs :deep(.el-tabs__header) {
  margin-bottom: 12px;
}

.dialog-table-shell {
  flex: 1 1 auto;
  min-height: 320px;
  height: auto;
  max-height: none;
  overflow: hidden;
}

.dialog-table-shell :deep(.el-table),
.dialog-table-shell :deep(.el-table__inner-wrapper),
.dialog-table-shell :deep(.el-scrollbar),
.dialog-table-shell :deep(.el-scrollbar__wrap) {
  width: 100%;
  height: 100% !important;
}

.dialog-table-shell :deep(.el-scrollbar__wrap) {
  overflow-y: auto !important;
  overflow-x: auto !important;
}

.dialog-table-shell :deep(.el-table__body-wrapper) {
  overflow-y: auto !important;
}

.dialog-table-shell :deep(.el-table th.el-table__cell) {
  background: #f8fafc !important;
  color: #475569;
  font-weight: 700;
}

.dialog-table-shell :deep(.el-table tr) {
  background: #fff;
}

.dialog-table-shell :deep(.el-table .cell) {
  line-height: 1.5;
}

.ellipsis {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.table-actions {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-wrap: nowrap;
  min-height: 28px;
  white-space: nowrap;
}

.table-actions-links {
  gap: 10px;
}

.table-action-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  line-height: 1;
  color: var(--el-color-primary);
  text-decoration: none;
  font-size: 12px;
  white-space: nowrap;
  vertical-align: middle;
  cursor: pointer;
}

.table-action-link:hover {
  color: var(--el-color-primary-light-5);
  text-decoration: underline;
}

.table-action-link.danger {
  color: var(--danger);
}

.mobile-file-list-shell,
.mobile-file-list {
  display: none;
}

.mobile-file-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 12px;
  height: 100%;
  min-height: 0;
  overflow-y: auto;
  padding-right: 2px;
}

.mobile-file-card {
  background: #fff;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 14px;
  padding: 12px;
  box-shadow: 0 4px 14px rgba(15, 23, 42, 0.04);
}

.mobile-file-card-top {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  min-width: 0;
}

.mobile-file-icon {
  flex: 0 0 auto;
  font-size: 20px;
  line-height: 1;
  margin-top: 2px;
}

.mobile-file-main {
  min-width: 0;
  flex: 1;
}

.mobile-file-name {
  font-size: 14px;
  font-weight: 700;
  color: var(--text);
  line-height: 1.4;
  word-break: break-word;
}

.mobile-file-tags {
  margin-top: 10px;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.mobile-file-meta {
  margin-top: 8px;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px 10px;
}

.mobile-file-meta-item {
  min-width: 0;
}

.mobile-file-meta-label {
  font-size: 11px;
  color: var(--muted-2);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.mobile-file-meta-value {
  margin-top: 2px;
  font-size: 12px;
  color: var(--text);
  word-break: break-word;
  line-height: 1.4;
}

.mobile-file-actions {
  margin-top: 12px;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.mobile-file-actions :deep(.el-button),
.mobile-file-actions :deep(.el-dropdown),
.mobile-file-actions .table-action-link,
.mobile-file-actions a{
  flex: 1 1 calc(33.333% - 8px);
  min-height: 32px;
  margin: 0;
  border-radius: 10px;
  justify-content: center;
}

.mobile-file-actions :deep(.el-dropdown) {
  display: inline-flex;
}

.mobile-file-actions :deep(.el-dropdown .el-button) {
  width: 100%;
}

.mobile-file-actions a {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  text-decoration: none;
}

.mobile-file-actions a .el-button {
  width: 100%;
  height: 100%;
  margin: 0;
}

.mobile-file-actions .table-action-link {
  height: auto;
  padding: 6px 10px;
  background: #f8fafc;
  border: 1px solid rgba(15, 23, 42, 0.06);
}

.empty-state {
  padding: 32px 12px;
  color: var(--muted);
  text-align: center;
  font-size: 13px;
}

@media (max-width: 960px) {
  .dialog-head {
    grid-template-columns: 1fr;
  }

  .dialog-head-left,
  .dialog-head-right {
    width: 100%;
  }

  .dialog-head-right,
  .artifact-filter-box {
    justify-content: flex-start;
    margin-left: 0;
  }
}

@media (max-width: 768px), (max-height: 720px) {
  .dialog-table-shell {
    display: none !important;
  }

  .mobile-file-list-shell {
    display: flex !important;
    flex: 1 1 auto !important;
    min-height: 0 !important;
    overflow: hidden !important;
  }

  .mobile-file-list {
    display: block !important;
    flex: 1 1 auto !important;
    min-height: 0 !important;
    overflow: hidden !important;
  }

  .mobile-file-grid {
    height: 100% !important;
    min-height: 0 !important;
    overflow-y: auto !important;
  }
}

@media (max-width: 640px) {
  .dialog-head-left {
    flex-wrap: wrap;
    align-items: stretch;
  }

  .artifact-filter-box,
  .artifact-filter-box :deep(.el-select) {
    width: 100%;
    min-width: 0;
  }

  .mobile-file-meta {
    grid-template-columns: 1fr;
  }

  .mobile-file-actions {
    gap: 6px;
  }

  .mobile-file-actions :deep(.el-button),
  .mobile-file-actions :deep(.el-dropdown),
  .mobile-file-actions .table-action-link {
    flex: 1 1 calc(50% - 6px);
  }
}
</style>

<style>
/* ArtifactDialog: 固定高度，只让表格或移动卡片内部滚动。 */
.artifact-overlay .el-overlay-dialog {
  overflow: hidden !important;
}

.artifact-overlay .el-dialog {
  height: 78vh !important;
  max-height: 78vh !important;
  margin-top: 5vh !important;
  display: flex !important;
  flex-direction: column !important;
  overflow: hidden !important;
}

.artifact-overlay .el-dialog__header {
  flex: 0 0 auto !important;
}

.artifact-overlay .el-dialog__body {
  flex: 1 1 auto !important;
  min-height: 0 !important;
  overflow: hidden !important;
  padding-top: 12px !important;
  padding-bottom: 12px !important;
}

.artifact-overlay .fixed-dialog-body {
  height: 100% !important;
  min-height: 0 !important;
  overflow: hidden !important;
  display: flex !important;
  flex-direction: column !important;
}

.artifact-overlay .dialog-table-shell {
  flex: 1 1 auto !important;
  min-height: 320px !important;
  height: auto !important;
  max-height: none !important;
  overflow: hidden !important;
}

.artifact-overlay .dialog-table-shell .el-table,
.artifact-overlay .dialog-table-shell .el-table__inner-wrapper,
.artifact-overlay .dialog-table-shell .el-scrollbar,
.artifact-overlay .dialog-table-shell .el-scrollbar__wrap {
  height: 100% !important;
}

.artifact-overlay .dialog-table-shell .el-scrollbar__wrap {
  overflow-y: auto !important;
  overflow-x: auto !important;
}

@media (max-width: 768px), (max-height: 720px) {
  .artifact-overlay .el-dialog {
    width: 100vw !important;
    max-width: 100vw !important;
    height: 100dvh !important;
    max-height: 100dvh !important;
    margin: 0 !important;
    border-radius: 0 !important;
  }

  .artifact-overlay .el-dialog__header {
    padding: 14px 16px 10px !important;
  }

  .artifact-overlay .el-dialog__body {
    padding: 10px 12px 12px !important;
  }

  .artifact-overlay .dialog-table-shell {
    display: none !important;
  }

  .artifact-overlay .mobile-file-list-shell {
    display: flex !important;
    flex: 1 1 auto !important;
    min-height: 0 !important;
    overflow: hidden !important;
  }

  .artifact-overlay .mobile-file-list {
    display: block !important;
    flex: 1 1 auto !important;
    min-height: 0 !important;
    overflow: hidden !important;
  }

  .artifact-overlay .mobile-file-grid {
    height: 100% !important;
    min-height: 0 !important;
    overflow-y: auto !important;
  }
}
</style>
