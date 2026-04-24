<template>
  <el-dialog
    :model-value="processDialogVisible"
    title="Process Manager"
    width="1100px"
    top="5vh"
    class="fixed-dialog process-dialog"
    @update:model-value="$emit('update:processDialogVisible', $event)"
    @close="$emit('close')"
  >
    <div class="fixed-dialog-body">
      <div class="dialog-head process-dialog-head">
        <div class="dialog-head-left process-dialog-head-left">
          <el-button
            size="small"
            :loading="processActiveTab === 'apps' ? appsLoading : processesLoading"
            @click="$emit('refresh')"
          >
            Refresh
          </el-button>

          <el-input
            :model-value="filterText"
            placeholder="Filter by PID, name"
            size="small"
            class="process-dialog-filter-input"
            clearable
            @update:model-value="$emit('update:filterText', $event)"
          />
        </div>

        <div class="dialog-head-right process-dialog-head-right">
          <span class="process-count">{{ processManagerSummaryText }}</span>
        </div>
      </div>

      <el-tabs
        :model-value="processActiveTab"
        style="margin-top: 12px;"
        @update:model-value="$emit('update:processActiveTab', $event)"
      >
        <el-tab-pane :label="processTabLabel" name="processes">
          <div class="dialog-table-shell" style="height: 450px;">
            <el-table
              :data="filteredProcesses"
              v-loading="processesLoading"
              stripe
              height="100%"
              table-layout="fixed"
            >
              <el-table-column
                prop="pid"
                label="PID"
                width="100"
                align="center"
              />

              <el-table-column
                prop="name"
                label="Name"
                min-width="200"
                show-overflow-tooltip
              />

              <el-table-column
                prop="status"
                label="Status"
                width="160"
                align="center"
              />

              <el-table-column
                label="Actions"
                width="240"
                align="center"
                fixed="right"
              >
                <template #default="{ row }">
                  <el-space>
                    <el-button
                      size="small"
                      link
                      type="primary"
                      @click="$emit('open-detail', row.pid)"
                    >
                      Details
                    </el-button>

                    <el-button
                      size="small"
                      link
                      type="danger"
                      @click="$emit('kill-process', row.pid, row.name)"
                    >
                      Kill
                    </el-button>
                  </el-space>
                </template>
              </el-table-column>
            </el-table>
          </div>
        </el-tab-pane>

        <el-tab-pane :label="appTabLabel" name="apps">
          <div class="dialog-table-shell" style="height: 450px;">
            <el-table
              :data="filteredApps"
              v-loading="appsLoading"
              stripe
              height="100%"
              table-layout="fixed"
            >
              <el-table-column
                prop="pid"
                label="PID"
                width="100"
                align="center"
              />

              <el-table-column
                prop="name"
                label="Name"
                min-width="200"
                show-overflow-tooltip
              />

              <el-table-column
                prop="status"
                label="Status"
                min-width="120"
                show-overflow-tooltip
              />

              <el-table-column
                label="Actions"
                width="220"
                align="center"
                fixed="right"
              >
                <template #default="{ row }">
                  <el-space>
                    <el-button
                      size="small"
                      link
                      type="primary"
                      @click="$emit('open-detail', row.pid)"
                    >
                      Details
                    </el-button>

                    <el-button
                      size="small"
                      link
                      type="danger"
                      @click="$emit('kill-app', row.pid, row.name)"
                    >
                      Kill
                    </el-button>
                  </el-space>
                </template>
              </el-table-column>
            </el-table>
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>
  </el-dialog>

  <el-dialog
    :model-value="processDetailDialogVisible"
    title="Process Details"
    width="980px"
    top="6vh"
    class="fixed-dialog"
    @update:model-value="$emit('update:processDetailDialogVisible', $event)"
  >
    <div v-loading="processDetailLoading" style="min-height: 280px;">
      <template v-if="processDetail && !processDetailLoading">
        <div style="margin-bottom: 18px;">
          <div style="font-weight: 600; font-size: 14px; margin-bottom: 10px;">
            Basic Info
          </div>

          <div
            v-for="item in processDetailBasicRows"
            :key="item.key"
            style="display: grid; grid-template-columns: 180px 1fr; gap: 12px; padding: 8px 0; border-bottom: 1px solid #ebeef5;"
          >
            <div style="color: #606266; font-weight: 500;">
              {{ item.label }}
            </div>

            <div style="word-break: break-word;">
              {{ item.value }}
            </div>
          </div>
        </div>

        <div style="margin-bottom: 18px;">
          <div style="font-weight: 600; font-size: 14px; margin-bottom: 10px;">
            Command Line
          </div>

          <div style="padding: 10px 12px; background: #f5f7fa; border-radius: 8px; word-break: break-word; white-space: pre-wrap; font-family: monospace; font-size: 12px; line-height: 1.6;">
            {{ processDetailCommandLineText || '-' }}
          </div>
        </div>

        <div style="margin-bottom: 18px;">
          <div style="font-weight: 600; font-size: 14px; margin-bottom: 10px;">
            Network Connections ({{ (processDetail.connections || []).length }})
          </div>

          <el-table
            :data="processDetail.connections || []"
            stripe
            border
            max-height="220"
            empty-text="No network connections"
          >
            <el-table-column
              prop="local_address"
              label="Local Address"
              min-width="160"
              show-overflow-tooltip
            />

            <el-table-column
              prop="remote_address"
              label="Remote Address"
              min-width="160"
              show-overflow-tooltip
            />

            <el-table-column
              prop="status"
              label="Status"
              width="140"
              align="center"
            />

            <el-table-column
              prop="family"
              label="Family"
              width="200"
              align="center"
            />
          </el-table>
        </div>

        <div>
          <div style="font-weight: 600; font-size: 14px; margin-bottom: 10px;">
            Open Files ({{ (processDetail.open_files || []).length }})
          </div>

          <el-table
            :data="processDetail.open_files || []"
            stripe
            border
            max-height="240"
            empty-text="No open files"
          >
            <el-table-column
              prop="path"
              label="Path"
              show-overflow-tooltip
            />
          </el-table>
        </div>
      </template>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'ProcessDialogs',

  props: {
    processDialogVisible: {
      type: Boolean,
      default: false,
    },

    processDetailDialogVisible: {
      type: Boolean,
      default: false,
    },

    processActiveTab: {
      type: String,
      default: 'processes',
    },

    filterText: {
      type: String,
      default: '',
    },

    processManagerSummaryText: {
      type: String,
      default: '',
    },

    processTabLabel: {
      type: String,
      default: 'Processes',
    },

    appTabLabel: {
      type: String,
      default: 'Apps',
    },

    filteredProcesses: {
      type: Array,
      default: () => [],
    },

    filteredApps: {
      type: Array,
      default: () => [],
    },

    processesLoading: {
      type: Boolean,
      default: false,
    },

    appsLoading: {
      type: Boolean,
      default: false,
    },

    processDetailLoading: {
      type: Boolean,
      default: false,
    },

    processDetail: {
      type: Object,
      default: null,
    },

    processDetailBasicRows: {
      type: Array,
      default: () => [],
    },

    processDetailCommandLineText: {
      type: String,
      default: '',
    },
  },

  emits: [
    'update:processDialogVisible',
    'update:processDetailDialogVisible',
    'update:processActiveTab',
    'update:filterText',
    'close',
    'refresh',
    'open-detail',
    'kill-process',
    'kill-app',
  ],
}
</script>