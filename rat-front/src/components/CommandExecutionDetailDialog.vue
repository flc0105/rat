<template>
  <el-dialog
    :model-value="visible"
    :title="entry ? (entry.command || 'Execution Detail') : 'Execution Detail'"
    width="1000px"
    top="5vh"
    class="fixed-dialog command-execution-detail-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div
      v-if="entry"
      class="fixed-dialog-body"
    >
      <div class="background-job-stats">
        <div class="background-job-stat">
          <div class="background-job-stat-label">Status</div>
          <div class="background-job-stat-value">
            <el-tag
              :type="buildCommandExecutionStatusTagType(entry.status)"
              size="small"
            >
              {{ entry.status || 'unknown' }}
            </el-tag>
          </div>
        </div>

        <div class="background-job-stat">
          <div class="background-job-stat-label">Source</div>
          <div class="background-job-stat-value">
            {{ entry.source || '-' }}
          </div>
        </div>

        <div class="background-job-stat">
          <div class="background-job-stat-label">Duration</div>
          <div class="background-job-stat-value">
            {{ formatCommandExecutionDuration(entry.duration_ms) }}
          </div>
        </div>

        <div class="background-job-stat">
          <div class="background-job-stat-label">Started</div>
          <div class="background-job-stat-value">
            {{ entry.started_at || '-' }}
          </div>
        </div>

        <div class="background-job-stat">
          <div class="background-job-stat-label">Finished</div>
          <div class="background-job-stat-value">
            {{ entry.finished_at || '-' }}
          </div>
        </div>

        <div class="background-job-stat">
          <div class="background-job-stat-label">Files</div>
          <div class="background-job-stat-value">
            {{ entry.file_count || 0 }}
          </div>
        </div>
      </div>

      <div class="command-execution-detail-section">
        <div class="command-execution-detail-label">Summary</div>
        <div class="command-execution-detail-summary">
          {{ buildCommandExecutionSummary(entry) }}
        </div>
      </div>

      <div class="command-execution-detail-panels">
        <div class="background-job-panel">
          <div class="background-job-panel-title command-output-panel-title">
            <span>Output Records</span>

            <el-button
              size="small"
              plain
              @click="$emit('toggle-output-sort')"
            >
              {{ outputSortOrder === 'desc' ? 'Oldest first' : 'Newest first' }}
            </el-button>
          </div>

          <div class="background-job-message-list">
            <div
              v-for="(record, index) in outputRecords"
              :key="`${entry.entry_id}-output-${index}`"
              class="background-job-message-item"
            >
              <div class="background-job-message-time">
                {{ record.time || '-' }}
              </div>

              <div
                class="background-job-message-text"
                :class="{
                  'is-error': record.status === 0,
                  'is-success': record.status === 1,
                }"
              >
                {{ formatCommandExecutionRecordText(record.text || '') }}
              </div>
            </div>

            <div
              v-if="entry.output_truncated"
              class="empty-state compact"
            >
              Output was truncated for storage safety
            </div>

            <div
              v-if="!entry.output_records || !entry.output_records.length"
              class="empty-state compact"
            >
              No output records
            </div>
          </div>
        </div>

        <div class="background-job-panel">
          <div class="background-job-panel-title">Produced Files</div>

          <div class="background-job-file-list">
            <div
              v-for="(file, index) in entry.files"
              :key="`${entry.entry_id}-file-${index}`"
              class="background-job-file-item"
            >
              <div class="background-job-file-main">
                <div class="background-job-file-name">
                  {{ file.original_name || file.stored_name || '-' }}
                </div>

                <div class="background-job-file-meta">
                  <span>{{ formatBytes(file.size || 0) }}</span>
                  <span>{{ file.created_at || '-' }}</span>
                  <span v-if="getCommandExecutionFileStatusText(file)">
                    [{{ getCommandExecutionFileStatusText(file) }}]
                  </span>
                </div>
              </div>

              <div class="background-job-file-actions">
                <a
                  v-if="file.download_url && file.is_available"
                  style="cursor:pointer"
                  class="table-action-link"
                  @click="$emit('preview-file', file)"
                >
                  Preview
                </a>

                <a
                  v-if="file.download_url && file.is_available"
                  class="table-action-link"
                  :href="file.download_url"
                  target="_blank"
                >
                  Download
                </a>
              </div>
            </div>

            <div
              v-if="!entry.files || !entry.files.length"
              class="empty-state compact"
            >
              No files produced
            </div>
          </div>
        </div>
      </div>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'CommandExecutionDetailDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    entry: {
      type: Object,
      default: null,
    },

    outputRecords: {
      type: Array,
      default: () => [],
    },

    outputSortOrder: {
      type: String,
      default: 'desc',
    },

    buildCommandExecutionStatusTagType: {
      type: Function,
      required: true,
    },

    formatCommandExecutionDuration: {
      type: Function,
      required: true,
    },

    buildCommandExecutionSummary: {
      type: Function,
      required: true,
    },

    formatCommandExecutionRecordText: {
      type: Function,
      required: true,
    },

    getCommandExecutionFileStatusText: {
      type: Function,
      required: true,
    },

    formatBytes: {
      type: Function,
      required: true,
    },
  },

  emits: [
    'update:visible',
    'toggle-output-sort',
    'preview-file',
  ],
}
</script>