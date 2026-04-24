<template>
  <el-dialog
    :model-value="visible"
    title="Artifact Manager"
    width="1160px"
    top="5vh"
    class="fixed-dialog recent-files-dialog artifact-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div class="fixed-dialog-body">
      <div class="dialog-head">
        <div class="dialog-head-left">
          <el-button
            size="small"
            @click="$emit('refresh')"
          >
            Refresh
          </el-button>

          <el-button
            size="small"
            type="danger"
            :loading="clearing"
            @click="$emit('clear')"
          >
            Clear
          </el-button>
        </div>

        <div class="dialog-head-right">
          <div class="dialog-path-box artifact-filter-box">
            <el-select
              :model-value="machineIdFilter"
              clearable
              filterable
              placeholder="Filter by device"
              @update:model-value="$emit('update:machineIdFilter', $event)"
              @change="$emit('filter-change', $event)"
            >
              <el-option
                v-for="item in machines"
                :key="item.machine_id"
                :label="item.hostname || item.machine_id"
                :value="item.machine_id"
              />
            </el-select>
          </div>
        </div>
      </div>

      <el-tabs
        :model-value="activeTab"
        class="command-history-tabs"
        @update:model-value="$emit('update:activeTab', $event)"
        @tab-change="$emit('tab-change', $event)"
      >
        <el-tab-pane name="files">
          <template #label>
            Files ({{ countMap.files || 0 }})
          </template>
        </el-tab-pane>

        <el-tab-pane name="previews">
          <template #label>
            Previews ({{ countMap.previews || 0 }})
          </template>
        </el-tab-pane>
      </el-tabs>

      <div class="dialog-table-shell">
        <el-table
          :data="items"
          v-loading="loading"
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
                {{ row.original_name || row.stored_name }}
              </div>
            </template>
          </el-table-column>

          <el-table-column
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
            width="200"
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

                <a
                  href="#"
                  class="table-action-link danger"
                  @click.prevent="$emit('delete', row)"
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
          v-loading="loading"
        >
          <div
            v-if="!items.length && !loading"
            class="empty-state"
          >
            No artifacts available
          </div>

          <div
            v-else
            class="mobile-file-grid"
          >
            <div
              v-for="row in items"
              :key="row.artifact_id"
              class="mobile-file-card"
            >
              <div class="mobile-file-card-top">
                <div class="mobile-file-icon">📄</div>

                <div class="mobile-file-main">
                  <div class="mobile-file-name">
                    {{ row.original_name || row.stored_name }}
                  </div>

                  <div class="mobile-file-tags">
                    <el-tag
                      v-if="row.hostname"
                      size="small"
                    >
                      {{ row.hostname }}
                    </el-tag>
                  </div>

                  <div class="mobile-file-meta">
                    <div class="mobile-file-meta-item">
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

                    <a
                      class="table-action-link"
                      :href="row.download_url"
                      target="_blank"
                    >
                      Download
                    </a>

                    <el-button
                      size="small"
                      type="danger"
                      plain
                      @click="$emit('delete', row)"
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
export default {
  name: 'ArtifactDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    loading: {
      type: Boolean,
      default: false,
    },

    clearing: {
      type: Boolean,
      default: false,
    },

    items: {
      type: Array,
      default: () => [],
    },

    machines: {
      type: Array,
      default: () => [],
    },

    activeTab: {
      type: String,
      default: 'files',
    },

    machineIdFilter: {
      type: String,
      default: '',
    },

    countMap: {
      type: Object,
      default: () => ({
        files: 0,
        previews: 0,
      }),
    },

    formatBytes: {
      type: Function,
      required: true,
    },
  },

  emits: [
    'update:visible',
    'update:activeTab',
    'update:machineIdFilter',
    'tab-change',
    'filter-change',
    'refresh',
    'clear',
    'preview',
    'delete',
  ],
}
</script>