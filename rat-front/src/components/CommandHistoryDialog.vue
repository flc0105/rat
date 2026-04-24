<template>
  <el-dialog
    :model-value="visible"
    title="Command History"
    width="1120px"
    top="5vh"
    class="fixed-dialog recent-files-dialog command-history-dialog"
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
            @click="$emit('clear-history')"
          >
            Clear History
          </el-button>
        </div>

        <div class="dialog-head-right">
          <div class="command-history-toolbar">
            <el-input
              :model-value="searchText"
              size="small"
              clearable
              class="command-history-search-input"
              placeholder="Search by command name"
              @update:model-value="$emit('update:searchText', $event)"
            />

            <div class="command-history-search-summary">
              <span>
                Quick {{ searchSummary.quickVisible }} / {{ searchSummary.quickTotal }}
              </span>

              <span>
                Execution {{ searchSummary.fullVisible }} / {{ searchSummary.fullTotal }}
              </span>

              <el-button
                size="small"
                plain
                :disabled="!searchText"
                @click="$emit('clear-search')"
              >
                Clear Search
              </el-button>
            </div>
          </div>
        </div>
      </div>

      <el-tabs
        :model-value="activeTab"
        class="command-history-tabs"
        @update:model-value="$emit('update:activeTab', $event)"
      >
        <el-tab-pane label="Quick History" name="quick">
          <div class="dialog-table-shell quick-history-table-shell">
            <el-table
              :data="quickItems"
              v-loading="quickLoading"
              stripe
              width="100%"
              height="100%"
              :empty-text="searchText ? 'No matching commands' : 'No command history available'"
              table-layout="fixed"
              @row-dblclick="$emit('apply', $event)"
            >
              <el-table-column
                prop="index"
                label="#"
                width="90"
                align="center"
              >
                <template #default="{ row }">
                  <div class="ellipsis">
                    {{ row.is_pinned ? '⭐ ' : '' }}{{ row.index || '-' }}
                  </div>
                </template>
              </el-table-column>

              <el-table-column
                prop="command"
                label="Command"
                min-width="280"
                show-overflow-tooltip
              >
                <template #default="{ row }">
                  <div class="ellipsis mono">
                    {{ row.command || '-' }}
                  </div>
                </template>
              </el-table-column>

              <el-table-column
                prop="time"
                label="Last Used"
                width="220"
                show-overflow-tooltip
              >
                <template #default="{ row }">
                  <div class="ellipsis">
                    {{ row.time || '-' }}
                  </div>
                </template>
              </el-table-column>

              <el-table-column
                prop="status"
                label="Status"
                width="120"
                align="center"
              >
                <template #default="{ row }">
                  <el-tag
                    :type="buildCommandExecutionStatusTagType(row.status)"
                    size="small"
                  >
                    {{ row.status || '-' }}
                  </el-tag>
                </template>
              </el-table-column>

              <el-table-column
                label="Actions"
                width="220"
                align="center"
                fixed="right"
              >
                <template #default="{ row }">
                  <div class="table-actions table-actions-links history-actions-row">
                    <div class="history-actions-group">
                      <a
                        href="#"
                        class="table-action-link"
                        @click.prevent="$emit('apply', row)"
                      >
                        Use
                      </a>

                      <a
                        href="#"
                        class="table-action-link"
                        @click.prevent="$emit('toggle-pin', row)"
                      >
                        {{ row.is_pinned ? 'Unpin' : 'Pin' }}
                      </a>
                    </div>

                    <template v-if="row.is_pinned">
                      <span class="history-actions-divider"></span>

                      <div class="history-actions-move-group">
                        <a
                          href="#"
                          class="table-action-link"
                          :class="{ 'history-action-disabled': !row.can_move_up }"
                          @click.prevent="row.can_move_up && $emit('move-pin', row, 'up')"
                        >
                          Up
                        </a>

                        <a
                          href="#"
                          class="table-action-link"
                          :class="{ 'history-action-disabled': !row.can_move_down }"
                          @click.prevent="row.can_move_down && $emit('move-pin', row, 'down')"
                        >
                          Down
                        </a>
                      </div>
                    </template>
                  </div>
                </template>
              </el-table-column>
            </el-table>
          </div>

          <div class="quick-history-mobile-shell">
            <div
              class="mobile-file-list"
              v-loading="quickLoading"
            >
              <div
                v-if="!quickItems.length && !quickLoading"
                class="empty-state"
              >
                No command history available
              </div>

              <div
                v-else
                class="mobile-file-grid"
              >
                <div
                  v-for="row in quickItems"
                  :key="`${row.index}-${row.command}-${row.time}`"
                  class="mobile-file-card quick-history-card"
                >
                  <div class="mobile-file-card-top">
                    <div class="mobile-file-icon">⌘</div>

                    <div class="mobile-file-main">
                      <div class="mobile-file-name mono">
                        {{ row.is_pinned ? '⭐ ' : '' }}{{ row.command || '-' }}
                      </div>

                      <div class="mobile-file-tags">
                        <el-tag size="small" type="info">
                          #{{ row.index || '-' }}
                        </el-tag>

                        <el-tag
                          size="small"
                          :type="buildCommandExecutionStatusTagType(row.status)"
                        >
                          {{ row.status || '-' }}
                        </el-tag>
                      </div>

                      <div class="mobile-file-meta">
                        <div class="mobile-file-meta-item">
                          <div class="mobile-file-meta-label">Last Used</div>
                          <div class="mobile-file-meta-value">
                            {{ row.time || '-' }}
                          </div>
                        </div>
                      </div>

                      <div class="mobile-file-actions mobile-history-actions-row">
                        <el-button
                          size="small"
                          type="primary"
                          plain
                          @click="$emit('apply', row)"
                        >
                          Use
                        </el-button>

                        <el-button
                          size="small"
                          plain
                          @click="$emit('toggle-pin', row)"
                        >
                          {{ row.is_pinned ? 'Unpin' : 'Pin' }}
                        </el-button>

                        <template v-if="row.is_pinned">
                          <span class="mobile-history-actions-divider"></span>

                          <div class="mobile-history-move-group">
                            <el-button
                              size="small"
                              plain
                              class="mobile-history-disabled-btn"
                              :class="{ 'is-disabled': !row.can_move_up }"
                              :disabled="!row.can_move_up"
                              @click="row.can_move_up && $emit('move-pin', row, 'up')"
                            >
                              Up
                            </el-button>

                            <el-button
                              size="small"
                              plain
                              class="mobile-history-disabled-btn"
                              :class="{ 'is-disabled': !row.can_move_down }"
                              :disabled="!row.can_move_down"
                              @click="row.can_move_down && $emit('move-pin', row, 'down')"
                            >
                              Down
                            </el-button>
                          </div>
                        </template>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </el-tab-pane>

        <el-tab-pane label="Execution History" name="full">
          <div
            class="command-execution-list-shell"
            v-loading="executionLoading"
          >
            <div
              v-if="!executionItems.length && !executionLoading"
              class="empty-state"
            >
              {{ searchText ? 'No matching executions' : 'No execution history available' }}
            </div>

            <div
              v-else
              class="command-execution-list"
            >
              <div
                v-for="item in executionItems"
                :key="item.entry_id"
                class="execution-card"
              >
                <div class="execution-card-header">
                  <div class="execution-command mono">
                    {{ item.command || '-' }}
                  </div>

                  <div class="execution-badges">
                    <el-tag
                      :type="buildCommandExecutionStatusTagType(item.status)"
                      size="small"
                    >
                      {{ item.status || '-' }}
                    </el-tag>

                    <el-tag
                      v-if="item.has_files"
                      type="primary"
                      size="small"
                    >
                      📎 {{ item.file_count || 0 }}
                    </el-tag>

                    <el-tag
                      v-if="item.output_truncated"
                      type="warning"
                      size="small"
                    >
                      ✂️ truncated
                    </el-tag>
                  </div>
                </div>

                <div class="execution-meta">
                  <span class="meta-source">{{ item.source || '-' }}</span>
                  <span class="meta-separator">•</span>
                  <span class="meta-time">
                    {{ formatDateTimeStandard(item.started_at) || '-' }}
                  </span>
                </div>

                <div class="execution-stats">
                  <div class="stat-item">
                    <span class="stat-label">Duration</span>
                    <span class="stat-value">
                      {{ formatCommandExecutionDuration(item.duration_ms) }}
                    </span>
                  </div>

                  <div class="stat-item">
                    <span class="stat-label">Chunks</span>
                    <span class="stat-value">
                      {{ item.output_chunk_count || 0 }}
                    </span>
                  </div>

                  <div class="stat-item">
                    <span class="stat-label">Lines</span>
                    <span class="stat-value">
                      {{ item.output_line_count || 0 }}
                    </span>
                  </div>
                </div>

                <div
                  class="execution-summary"
                  :title="buildCommandExecutionSingleLineSummary(item)"
                >
                  {{ buildCommandExecutionSingleLineSummary(item) }}
                </div>

                <div class="execution-actions">
                  <el-button
                    plain
                    size="small"
                    @click="$emit('apply', item)"
                  >
                    Use
                  </el-button>

                  <el-button
                    plain
                    size="small"
                    @click="$emit('open-detail', item)"
                  >
                    Details
                  </el-button>

                  <el-button
                    type="danger"
                    plain
                    size="small"
                    @click="$emit('delete-execution', item)"
                  >
                    Delete
                  </el-button>
                </div>
              </div>
            </div>
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'CommandHistoryDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    activeTab: {
      type: String,
      default: 'quick',
    },

    searchText: {
      type: String,
      default: '',
    },

    searchSummary: {
      type: Object,
      default: () => ({
        quickVisible: 0,
        quickTotal: 0,
        fullVisible: 0,
        fullTotal: 0,
      }),
    },

    quickItems: {
      type: Array,
      default: () => [],
    },

    executionItems: {
      type: Array,
      default: () => [],
    },

    quickLoading: {
      type: Boolean,
      default: false,
    },

    executionLoading: {
      type: Boolean,
      default: false,
    },

    buildCommandExecutionStatusTagType: {
      type: Function,
      required: true,
    },

    formatDateTimeStandard: {
      type: Function,
      required: true,
    },

    formatCommandExecutionDuration: {
      type: Function,
      required: true,
    },

    buildCommandExecutionSingleLineSummary: {
      type: Function,
      required: true,
    },
  },

  emits: [
    'update:visible',
    'update:activeTab',
    'update:searchText',
    'refresh',
    'clear-history',
    'clear-search',
    'apply',
    'toggle-pin',
    'move-pin',
    'open-detail',
    'delete-execution',
  ],
}
</script>