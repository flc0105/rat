<template>
  <el-dialog
    :model-value="visible"
    title="Background Jobs"
    width="1180px"
    top="5vh"
    class="fixed-dialog background-jobs-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div class="fixed-dialog-body background-jobs-body">
      <el-tabs
        :model-value="activeTab"
        class="background-jobs-tabs"
        @update:model-value="$emit('update:active-tab', $event)"
      >
        <el-tab-pane label="Modules" name="modules">
          <div class="background-jobs-toolbar">
            <el-button
              size="small"
              type="primary"
              class="toolbar-btn"
              plain
              @click="$emit('create-job')"
            >
              New
            </el-button>

            <el-button
              size="small"
              class="toolbar-btn"
              :loading="uploadLoading"
              @click="$emit('trigger-upload')"
            >
              Upload
            </el-button>

            <el-button
              size="small"
              class="toolbar-btn"
              :loading="modulesLoading"
              @click="$emit('refresh-modules')"
            >
              Refresh
            </el-button>

            <input
              id="server-job-upload-input"
              type="file"
              accept=".py,text/x-python"
              style="display: none"
              @change="$emit('upload-change', $event)"
            >
          </div>

          <div class="background-jobs-modules panel-lite">
            <div class="background-jobs-section-title">Available Jobs</div>

            <div
              v-if="!modules.length && !modulesLoading"
              class="empty-state"
            >
              No background jobs available
            </div>

            <div
              v-else
              class="background-job-module-list"
            >
              <div
                v-for="item in modules"
                :key="item.module_id || `job:${item.job_name}`"
                class="background-job-module-card"
              >
                <div class="background-job-module-main">
                  <div
                    class="background-job-module-name"
                    :title="item.display_name || item.job_name"
                  >
                    {{ item.display_name || item.job_name }}
                  </div>

                  <div
                    v-if="item.subtitle"
                    class="background-job-module-key mono"
                    :title="item.subtitle"
                  >
                    {{ item.subtitle }}
                  </div>

                  <div
                    v-if="item.description"
                    class="background-job-module-desc"
                    :title="item.description"
                  >
                    {{ item.description }}
                  </div>

                  <div class="background-job-module-tags">
                    <el-tag
                      size="small"
                      :type="isJobSupportedForCurrentConnection(item) ? 'info' : 'danger'"
                    >
                      {{ formatJobPlatformLabel(item.metadata?.platforms || []) }}
                    </el-tag>

                    <el-tag
                      v-if="hasBackgroundJobParams(item)"
                      size="small"
                      type="warning"
                    >
                      Params
                    </el-tag>
                  </div>
                </div>

                <div class="background-job-module-actions">
                  <el-button
                    size="small"
                    type="primary"
                    plain
                    :disabled="isBackgroundJobStartDisabled(item)"
                    @click="$emit('start-job', item)"
                  >
                    Start
                  </el-button>

                  <el-button
                    size="small"
                    plain
                    @click="$emit('edit-job', item.job_name)"
                  >
                    Edit
                  </el-button>

                  <el-button
                    size="small"
                    type="danger"
                    plain
                    @click="$emit('delete-job', item.job_name)"
                  >
                    Delete
                  </el-button>
                </div>
              </div>
            </div>
          </div>
        </el-tab-pane>

        <el-tab-pane label="Jobs" name="jobs">
          <div class="background-jobs-toolbar">
            <el-button
              size="small"
              class="toolbar-btn"
              :loading="jobsLoading"
              @click="$emit('refresh-jobs')"
            >
              Refresh
            </el-button>
          </div>

          <div
            class="background-jobs-list-shell panel-lite"
            v-loading="jobsLoading"
          >
            <div class="background-jobs-section-title">Reported Jobs</div>

            <div
              v-if="!jobs.length && !jobsLoading"
              class="empty-state"
            >
              No background jobs reported for this connection
            </div>

            <div
              v-else
              class="background-jobs-list"
            >
              <div
                v-for="job in jobs"
                :key="job.job_id"
                class="background-job-summary-card"
              >
                <div class="background-job-summary-main">
                  <div class="background-job-summary-top">
                    <div class="background-job-summary-title-wrap">
                      <div class="background-job-summary-title-line">
                        <span class="background-job-summary-title">
                          {{ job.display_name || job.job_name }}
                        </span>

                        <el-tag
                          :type="buildBackgroundJobStateTagType(job.state)"
                          size="small"
                        >
                          {{ job.state || 'unknown' }}
                        </el-tag>
                      </div>

                      <div class="background-job-summary-subtitle mono">
                        {{ job.job_name }} / {{ job.job_key || '-' }}
                      </div>
                    </div>
                  </div>

                  <div class="background-job-summary-stats">
                    <span>{{ formatBackgroundJobDuration(job.duration_seconds) }}</span>
                    <span>{{ job.message_count || 0 }} msgs</span>
                    <span>{{ job.file_count || 0 }} files</span>
                    <span>{{ job.thread_name || '-' }}</span>
                    <span>{{ formatDateTimeStandard(job.started_at) || '-' }}</span>
                  </div>
                </div>

                <div class="background-job-summary-actions">
                  <el-button
                    size="small"
                    plain
                    @click="$emit('open-detail', job)"
                  >
                    Details
                  </el-button>

                  <el-button
                    size="small"
                    type="danger"
                    plain
                    :disabled="!job.job_key || job.state === 'stopped'"
                    @click="$emit('stop-job', job)"
                  >
                    Stop
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
  name: 'BackgroundJobsDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },
    activeTab: {
      type: String,
      default: 'modules',
    },
    modules: {
      type: Array,
      default: () => [],
    },
    jobs: {
      type: Array,
      default: () => [],
    },
    modulesLoading: {
      type: Boolean,
      default: false,
    },
    jobsLoading: {
      type: Boolean,
      default: false,
    },
    uploadLoading: {
      type: Boolean,
      default: false,
    },

    isJobSupportedForCurrentConnection: {
      type: Function,
      required: true,
    },
    formatJobPlatformLabel: {
      type: Function,
      required: true,
    },
    hasBackgroundJobParams: {
      type: Function,
      required: true,
    },
    isBackgroundJobStartDisabled: {
      type: Function,
      required: true,
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
  },

  emits: [
    'update:visible',
    'update:active-tab',

    'create-job',
    'trigger-upload',
    'upload-change',
    'refresh-modules',

    'start-job',
    'edit-job',
    'delete-job',

    'refresh-jobs',
    'open-detail',
    'stop-job',
  ],
}
</script>