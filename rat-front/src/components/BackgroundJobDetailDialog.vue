<template>
  <el-dialog
    :model-value="visible"
    :title="item ? (item.display_name || item.job_name || 'Background Job') : 'Background Job Detail'"
    width="1080px"
    top="5vh"
    class="fixed-dialog background-job-detail-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div
      v-if="item"
      class="fixed-dialog-body"
    >
      <div class="background-job-detail-head">
        <div class="background-job-detail-head-left">
          <div class="background-job-title-line">
            <div class="background-job-title">
              {{ item.display_name || item.job_name }}
            </div>

            <el-tag
              :type="buildBackgroundJobStateTagType(item.state)"
              size="small"
            >
              {{ item.state || 'unknown' }}
            </el-tag>
          </div>

          <div class="background-job-subtitle mono">
            {{ item.job_name }} / {{ item.job_key || '-' }}
          </div>
        </div>

        <div class="background-job-card-head-right">
          <el-button
            size="small"
            type="danger"
            plain
            :disabled="!item.job_key || item.state === 'stopped'"
            @click="$emit('stop-job', item)"
          >
            Stop
          </el-button>
        </div>
      </div>

      <div class="background-job-stats">
        <div class="background-job-stat">
          <div class="background-job-stat-label">Duration</div>
          <div class="background-job-stat-value">
            {{ formatBackgroundJobDuration(item.duration_seconds) }}
          </div>
        </div>

        <div class="background-job-stat">
          <div class="background-job-stat-label">Messages</div>
          <div class="background-job-stat-value">
            {{ item.message_count || 0 }}
          </div>
        </div>

        <div class="background-job-stat">
          <div class="background-job-stat-label">Files</div>
          <div class="background-job-stat-value">
            {{ item.file_count || 0 }}
          </div>
        </div>

        <div class="background-job-stat">
          <div class="background-job-stat-label">Started</div>
          <div class="background-job-stat-value">
            {{ formatDateTimeStandard(item.started_at) || '-' }}
          </div>
        </div>

        <div class="background-job-stat">
          <div class="background-job-stat-label">Stopped</div>
          <div class="background-job-stat-value">
            {{ formatDateTimeStandard(item.stopped_at) || '-' }}
          </div>
        </div>

        <div class="background-job-stat">
          <div class="background-job-stat-label">Thread</div>
          <div class="background-job-stat-value mono">
            {{ item.thread_name || '-' }}
          </div>
        </div>
      </div>

      <div class="background-job-panels">
        <div class="background-job-panel">
          <div class="background-job-panel-title">
            Messages
          </div>

          <div class="background-job-message-list">
            <div
              v-for="(message, index) in safeMessages"
              :key="`${item.job_id || 'job'}-msg-${index}`"
              class="background-job-message-item clickable"
              @click="$emit('open-message', message)"
            >
              <div class="background-job-message-time">
                {{ formatDateTimeStandard(message.time) || '-' }}
              </div>

              <div
                class="background-job-message-text single-line"
                :class="{ 'is-error': message.status === 0, 'is-success': message.status === 1 }"
              >
                {{ formatBackgroundJobMessageText(message.text || '') }}
              </div>
            </div>

            <div
              v-if="!safeMessages.length"
              class="empty-state compact"
            >
              No messages
            </div>
          </div>
        </div>

        <div class="background-job-panel">
          <div class="background-job-panel-title">
            Files
          </div>

          <div class="background-job-file-list">
            <div
              v-for="(file, index) in safeFiles"
              :key="`${item.job_id || 'job'}-file-${index}`"
              class="background-job-file-item"
            >
              <div class="background-job-file-main">
                <div class="background-job-file-name">
                  {{ file.original_name || file.stored_name || '-' }}
                </div>

                <div class="background-job-file-meta">
                  <span>{{ formatBytes(file.size || 0) }}</span>
                  <span>{{ formatDateTimeStandard(file.time) || '-' }}</span>
                </div>
              </div>

              <div class="background-job-file-actions">
                <a
                  class="table-action-link"
                  style="cursor: pointer"
                  @click="$emit('preview-file', file)"
                >
                  Preview
                </a>

                <a
                  class="table-action-link"
                  :href="file.download_url"
                  target="_blank"
                >
                  Download
                </a>
              </div>
            </div>

            <div
              v-if="!safeFiles.length"
              class="empty-state compact"
            >
              No files
            </div>
          </div>
        </div>
      </div>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'BackgroundJobDetailDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },
    item: {
      type: Object,
      default: null,
    },
    messages: {
      type: Array,
      default: () => [],
    },
    files: {
      type: Array,
      default: () => [],
    },
    buildBackgroundJobStateTagType: {
      type: Function,
      required: true,
    },
    formatBackgroundJobDuration: {
      type: Function,
      required: true,
    },
    formatDateTimeStandard: {
      type: Function,
      required: true,
    },
    formatBackgroundJobMessageText: {
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
    'stop-job',
    'open-message',
    'preview-file',
  ],

  computed: {
    safeMessages() {
      return Array.isArray(this.messages) ? this.messages : []
    },

    safeFiles() {
      return Array.isArray(this.files) ? this.files : []
    },
  },
}
</script>