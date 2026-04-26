<template>
  <el-dialog
    :model-value="visible"
    title="Background Jobs"
    width="1180px"
    top="5vh"
    class="fixed-dialog background-jobs-dialog"
    @update:model-value="handleVisibleChange"
  >
    <div class="fixed-dialog-body background-jobs-body">
      <el-tabs
        v-model="activeTab"
        class="background-jobs-tabs"
      >
        <el-tab-pane label="Modules" name="modules">
          <div class="background-jobs-toolbar">
            <el-button
              size="small"
              type="primary"
              class="toolbar-btn"
              plain
              @click="createRemoteJobPrompt"
            >
              New
            </el-button>

            <el-button
              size="small"
              class="toolbar-btn"
              :loading="serverJobUploadLoading"
              @click="triggerServerJobUpload"
            >
              Upload
            </el-button>

            <el-button
              size="small"
              class="toolbar-btn"
              :loading="backgroundJobModulesLoading"
              @click="loadBackgroundJobModules"
            >
              Refresh
            </el-button>

            <input
              ref="serverJobUploadInputRef"
              type="file"
              accept=".py,text/x-python"
              class="hidden-file-input"
              @change="handleServerJobUpload"
            >
          </div>

          <div class="background-jobs-modules panel-lite">
            <div class="background-jobs-section-title">Available Jobs</div>

            <div
              v-if="!backgroundJobModules.length && !backgroundJobModulesLoading"
              class="empty-state"
            >
              No background jobs available
            </div>

            <div
              v-else
              class="background-job-module-list"
            >
              <div
                v-for="item in backgroundJobModules"
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
                    @click="openBackgroundJobStartDialog(item)"
                  >
                    Start
                  </el-button>

                  <el-button
                    size="small"
                    plain
                    @click="$emit('open-job-editor', item.job_name)"
                  >
                    Edit
                  </el-button>

                  <el-button
                    size="small"
                    type="danger"
                    plain
                    @click="deleteBackgroundJobModule(item.job_name)"
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
              :loading="backgroundJobsLoading"
              @click="loadBackgroundJobs"
            >
              Refresh
            </el-button>
          </div>

          <div
            class="background-jobs-list-shell panel-lite"
            v-loading="backgroundJobsLoading"
          >
            <div class="background-jobs-section-title">Reported Jobs</div>

            <div
              v-if="!sortedBackgroundJobs.length && !backgroundJobsLoading"
              class="empty-state"
            >
              No background jobs reported for this connection
            </div>

            <div
              v-else
              class="background-jobs-list"
            >
              <div
                v-for="job in sortedBackgroundJobs"
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
                    @click="openBackgroundJobDetail(job)"
                  >
                    Details
                  </el-button>

                  <el-button
                    size="small"
                    type="danger"
                    plain
                    :disabled="!job.job_key || job.state === 'stopped'"
                    @click="stopBackgroundJob(job)"
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

  <BackgroundJobStartDialog
    v-model:visible="backgroundJobStartDialogVisible"
    :item="pendingStartJobModule"
    :params="pendingStartJobModule?.metadata?.params || []"
    :param-form="backgroundJobParamForm || {}"
    :submitting="backgroundJobStartSubmitting"
    :is-job-supported-for-current-connection="isJobSupportedForCurrentConnection"
    :format-job-platform-label="formatJobPlatformLabel"
    @update-param="updateBackgroundJobParam"
    @cancel="closeBackgroundJobStartDialog"
    @confirm="confirmStartBackgroundJobWithParams"
  />

  <BackgroundJobDetailDialog
    v-model:visible="backgroundJobDetailDialogVisible"
    :item="selectedBackgroundJob"
    :messages="selectedBackgroundJobMessagesDesc || []"
    :files="selectedBackgroundJob?.files || []"
    :build-background-job-state-tag-type="buildBackgroundJobStateTagType"
    :format-background-job-duration="formatBackgroundJobDuration"
    :format-date-time-standard="formatDateTimeStandard"
    :format-background-job-message-text="formatBackgroundJobMessageText"
    :format-bytes="formatBytes"
    @stop-job="stopBackgroundJob"
    @open-message="openBackgroundJobMessageDialog"
    @preview-file="$emit('preview-file', $event)"
  />

  <BackgroundJobMessageDialog
    v-model:visible="backgroundJobMessageDialogVisible"
    :message="selectedBackgroundJobMessage || {}"
    :format-date-time-standard="formatDateTimeStandard"
    :format-background-job-message-text="formatBackgroundJobMessageText"
  />
</template>

<script>
import { ElMessage, ElMessageBox } from 'element-plus'
import BackgroundJobStartDialog from './BackgroundJobStartDialog.vue'
import BackgroundJobDetailDialog from './BackgroundJobDetailDialog.vue'
import BackgroundJobMessageDialog from './BackgroundJobMessageDialog.vue'

export default {
  name: 'BackgroundJobsDialog',

  components: {
    BackgroundJobStartDialog,
    BackgroundJobDetailDialog,
    BackgroundJobMessageDialog,
  },

  props: {
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
      default: null,
    },

    formatBytes: {
      type: Function,
      required: true,
    },

    formatDateTimeStandard: {
      type: Function,
      required: true,
    },
  },

  emits: [
    'set-active-task',
    'preview-file',
    'open-job-editor',
    'open-new-job-editor',
    'job-deleted',
  ],

  data() {
    return {
      visible: false,
      backgroundJobsLoading: false,
      backgroundJobModulesLoading: false,
      backgroundJobModules: [],
      backgroundJobs: [],
      backgroundJobsRefreshTimer: null,
      backgroundJobDetailDialogVisible: false,
      selectedBackgroundJobId: '',
      activeTab: 'modules',
      backgroundJobMessageDialogVisible: false,
      selectedBackgroundJobMessage: {},
      serverJobUploadLoading: false,
      backgroundJobStartDialogVisible: false,
      backgroundJobStartSubmitting: false,
      pendingStartJobModule: null,
      backgroundJobParamForm: {},
    }
  },

  computed: {
    selectedBackgroundJob() {
      return this.backgroundJobs.find(item => item.job_id === this.selectedBackgroundJobId) || null
    },

    sortedBackgroundJobs() {
      return [...this.backgroundJobs].sort((a, b) => {
        const ta = String(a.updated_at || a.started_at || a.created_at || '')
        const tb = String(b.updated_at || b.started_at || b.created_at || '')
        return tb.localeCompare(ta)
      })
    },

    selectedBackgroundJobMessagesDesc() {
      const messages = this.selectedBackgroundJob && Array.isArray(this.selectedBackgroundJob.messages)
        ? this.selectedBackgroundJob.messages
        : []

      return [...messages].sort((a, b) => {
        const ta = String(a.time || '')
        const tb = String(b.time || '')
        return tb.localeCompare(ta)
      })
    },

    activeBackgroundJobKeySet() {
      const set = new Set()

      for (const job of this.backgroundJobs || []) {
        const state = String(job?.state || '').trim().toLowerCase()
        if (!['running', 'stopping'].includes(state)) continue

        const rawKey = String(job?.job_key || job?.job_name || '').trim()
          .replace(/\\/g, '/')
          .replace(/\.py$/i, '')
        const key = rawKey.split('/').pop()
        if (key) set.add(key)
      }

      return set
    },
  },

  watch: {
    backgroundJobDetailDialogVisible(value) {
      if (!value) {
        this.selectedBackgroundJobId = ''
      }
    },

    backgroundJobMessageDialogVisible(value) {
      if (!value) {
        this.selectedBackgroundJobMessage = {}
      }
    },

    backgroundJobStartDialogVisible(value) {
      if (!value) {
        this.closeBackgroundJobStartDialog()
      }
    },
  },

  beforeUnmount() {
    this.clearBackgroundJobsRefreshTimer()
  },

  methods: {
    async open() {
      if (!this.selectedId) {
        ElMessage.warning('Please select a device')
        return
      }

      this.visible = true

      await Promise.all([
        this.loadBackgroundJobModules(),
        this.loadBackgroundJobs(),
      ])
    },

    isOpen() {
      return this.visible
    },

    async refreshIfOpen() {
      if (!this.visible) return

      await Promise.all([
        this.loadBackgroundJobModules(),
        this.loadBackgroundJobs(),
      ])
    },

    async refreshModulesIfOpen() {
      if (!this.visible) return
      await this.loadBackgroundJobModules()
    },

    async refreshJobsIfOpen() {
      if (!this.visible) return
      await this.loadBackgroundJobs()
    },

    handleVisibleChange(value) {
      this.visible = value

      if (!value) {
        this.clearBackgroundJobsRefreshTimer()
      }
    },

    clearBackgroundJobsRefreshTimer() {
      if (this.backgroundJobsRefreshTimer) {
        clearTimeout(this.backgroundJobsRefreshTimer)
        this.backgroundJobsRefreshTimer = null
      }
    },

    normalizeBackgroundJobModule(item = {}) {
      const rawJobName = String(item.job_name || item.name || item.job_key || '').trim()
      const rawJobKey = String(item.job_key || '').trim()
      const rawDisplayName = String(item.display_name || '').trim()
      const metadata = this.normalizeJobMetadata(item.metadata || {})

      const isHeadingLike = /^(available\s+client\s+job\s+modules:?|available\s+remote\s+scripts:?|no\s+remote\s+scripts\s+available)$/i.test(rawJobName)
      const stripPySuffix = (value = '') => String(value).replace(/\.py$/i, '').trim()

      let jobName = rawJobName
      let jobKey = rawJobKey || stripPySuffix(rawJobName) || rawJobName
      let displayName = rawDisplayName

      if (!displayName) {
        displayName = metadata.display_name || jobName
      }

      if (!jobKey) {
        jobKey = stripPySuffix(jobName) || jobName
      }

      const subtitle = jobKey && displayName !== jobKey ? jobKey : ''
      const description = String(item.description || metadata.description || '').trim()

      return {
        ...item,
        source: 'job',
        job_name: jobName,
        job_key: jobKey,
        display_name: displayName,
        description,
        metadata,
        subtitle,
        module_id: `job:${jobKey || jobName}`,
        hidden_invalid: !jobName || isHeadingLike,
      }
    },

    normalizeJobMetadata(metadata = {}) {
      if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
        return {
          name: '',
          display_name: '',
          description: '',
          platforms: [],
          params: [],
        }
      }

      const normalizeParam = (item = {}) => {
        const name = String(item.name || '').trim()
        if (!name) return null

        return {
          ...item,
          name,
          type: String(item.type || 'string').trim().toLowerCase() || 'string',
          required: !!item.required,
          description: String(item.description || '').trim(),
        }
      }

      return {
        ...metadata,
        name: String(metadata.name || '').trim(),
        display_name: String(metadata.display_name || '').trim(),
        description: String(metadata.description || '').trim(),
        platforms: this.normalizeJobPlatforms(metadata.platforms),
        params: Array.isArray(metadata.params)
          ? metadata.params.map(item => normalizeParam(item)).filter(Boolean)
          : [],
      }
    },

    normalizeJobPlatforms(platforms) {
      const source = Array.isArray(platforms)
        ? platforms
        : (typeof platforms === 'string' && platforms.trim() ? [platforms] : [])

      const result = []
      const seen = new Set()

      for (const item of source) {
        const normalized = this.normalizeJobPlatform(item)
        if (!normalized || seen.has(normalized)) continue
        seen.add(normalized)
        result.push(normalized)
      }

      return result
    },

    normalizeJobPlatform(platform) {
      const value = String(platform || '').trim().toLowerCase()
      if (!value) return ''
      if (['*', 'all', 'any'].includes(value)) return '*'
      if (['darwin', 'mac', 'macos', 'osx'].includes(value)) return 'mac'
      if (['windows', 'win', 'win32', 'nt'].includes(value)) return 'win'
      if (value === 'linux') return 'linux'
      return value
    },

    normalizeClientPlatform(osType = '') {
      const value = String(osType || '').trim().toLowerCase()
      if (!value) return ''
      if (value.includes('darwin') || value.includes('mac')) return 'mac'
      if (value.includes('win')) return 'win'
      if (value.includes('linux')) return 'linux'
      return this.normalizeJobPlatform(value)
    },

    formatJobPlatformLabel(platforms) {
      const normalized = this.normalizeJobPlatforms(platforms)

      if (!normalized.length || normalized.includes('*')) {
        return 'All OS'
      }

      const labels = normalized.map(item => {
        if (item === 'mac') return 'macOS'
        if (item === 'win') return 'Windows'
        if (item === 'linux') return 'Linux'
        if (item === 'ios') return 'iOS'
        return item
      })

      return labels.join(' / ')
    },

    isJobSupportedForCurrentConnection(item) {
      const metadata = this.normalizeJobMetadata(item?.metadata || {})
      const platforms = metadata.platforms || []
      if (!platforms.length || platforms.includes('*')) return true

      const current = this.normalizeClientPlatform(this.currentConnection?.os_type || '')
      if (!current) return true

      return platforms.includes(current)
    },

    hasBackgroundJobParams(item) {
      const metadata = this.normalizeJobMetadata(item?.metadata || {})
      return Array.isArray(metadata.params) && metadata.params.length > 0
    },

    buildBackgroundJobParamDefaults(item) {
      const metadata = this.normalizeJobMetadata(item?.metadata || {})
      const result = {}

      for (const param of metadata.params || []) {
        if (Object.prototype.hasOwnProperty.call(param, 'default')) {
          const defaultValue = param.default
          result[param.name] = defaultValue === null || defaultValue === undefined ? '' : String(defaultValue)
        } else {
          result[param.name] = ''
        }
      }

      return result
    },

    openBackgroundJobStartDialog(item) {
      if (!this.selectedId) {
        ElMessage.warning('Please select a device')
        return
      }

      if (!item || !String(item.job_name || '').trim()) {
        ElMessage.warning('Invalid job name')
        return
      }

      if (!this.isJobSupportedForCurrentConnection(item)) {
        const jobName = item.display_name || item.job_name
        const platformLabel = this.formatJobPlatformLabel(item.metadata?.platforms || [])
        ElMessage.warning(`${jobName} only supports: ${platformLabel}`)
        return
      }

      if (this.isBackgroundJobStartDisabled(item)) {
        ElMessage.warning('This background job is already running')
        return
      }

      if (!this.hasBackgroundJobParams(item)) {
        this.startBackgroundJob(item.job_name)
        return
      }

      this.pendingStartJobModule = item
      this.backgroundJobParamForm = this.buildBackgroundJobParamDefaults(item)
      this.backgroundJobStartDialogVisible = true
    },

    closeBackgroundJobStartDialog() {
      this.backgroundJobStartDialogVisible = false
      this.backgroundJobStartSubmitting = false
      this.pendingStartJobModule = null
      this.backgroundJobParamForm = {}
    },

    updateBackgroundJobParam(name, value) {
      if (!name) return

      this.backgroundJobParamForm = {
        ...this.backgroundJobParamForm,
        [name]: value,
      }
    },

    coerceBackgroundJobParamValue(param, rawValue) {
      const type = String(param?.type || 'string').trim().toLowerCase()
      const value = rawValue === null || rawValue === undefined ? '' : String(rawValue).trim()

      if (type === 'integer' || type === 'int') {
        if (!/^-?\d+$/.test(value)) {
          throw new Error(`Param "${param.name}" must be an integer`)
        }

        const parsed = parseInt(value, 10)
        if (param.min !== undefined && parsed < Number(param.min)) {
          throw new Error(`Param "${param.name}" must be >= ${param.min}`)
        }

        if (param.max !== undefined && parsed > Number(param.max)) {
          throw new Error(`Param "${param.name}" must be <= ${param.max}`)
        }

        return parsed
      }

      if (type === 'number' || type === 'float') {
        const parsed = Number(value)
        if (Number.isNaN(parsed)) {
          throw new Error(`Param "${param.name}" must be a number`)
        }

        if (param.min !== undefined && parsed < Number(param.min)) {
          throw new Error(`Param "${param.name}" must be >= ${param.min}`)
        }

        if (param.max !== undefined && parsed > Number(param.max)) {
          throw new Error(`Param "${param.name}" must be <= ${param.max}`)
        }

        return parsed
      }

      if (type === 'boolean' || type === 'bool') {
        const lowered = value.toLowerCase()
        if (['1', 'true', 'yes', 'on'].includes(lowered)) return true
        if (['0', 'false', 'no', 'off'].includes(lowered)) return false
        throw new Error(`Param "${param.name}" must be true/false`)
      }

      return value
    },

    buildBackgroundJobStartParams(item) {
      const metadata = this.normalizeJobMetadata(item?.metadata || {})
      const params = {}

      for (const param of metadata.params || []) {
        const hasValue = Object.prototype.hasOwnProperty.call(this.backgroundJobParamForm, param.name)
        const rawValue = hasValue ? this.backgroundJobParamForm[param.name] : ''
        const textValue = rawValue === null || rawValue === undefined ? '' : String(rawValue).trim()

        if (!textValue) {
          if (param.required && (param.default === undefined || param.default === null || String(param.default).trim() === '')) {
            throw new Error(`Missing required param: ${param.name}`)
          }

          if (param.default !== undefined && param.default !== null && String(param.default).trim() !== '') {
            params[param.name] = this.coerceBackgroundJobParamValue(param, param.default)
          }

          continue
        }

        params[param.name] = this.coerceBackgroundJobParamValue(param, rawValue)
      }

      return params
    },

    buildJsonHeaders() {
      const headers = { 'Content-Type': 'application/json' }

      if (typeof this.getTabScopedHeaders === 'function') {
        return this.getTabScopedHeaders(headers)
      }

      return headers
    },

    async submitBackgroundJobStart(jobName, params = {}) {
      const normalized = String(jobName || '').trim()
      if (!normalized) {
        ElMessage.warning('Invalid job name')
        return null
      }

      const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs/start`, {
        method: 'POST',
        headers: this.buildJsonHeaders(),
        body: JSON.stringify({ job_name: normalized, params }),
      })

      const json = await res.json()
      if (!res.ok || json.code !== 0) {
        throw new Error(json.message || 'Failed to start background job')
      }

      const taskId = json.data && json.data.task_id
      this.$emit('set-active-task', this.selectedId, taskId || '')
      return json.data || {}
    },

    async confirmStartBackgroundJobWithParams() {
      const item = this.pendingStartJobModule
      if (!item) {
        this.closeBackgroundJobStartDialog()
        return
      }

      try {
        this.backgroundJobStartSubmitting = true
        const params = this.buildBackgroundJobStartParams(item)
        await this.submitBackgroundJobStart(item.job_name, params)
        ElMessage.success(`Start request submitted: ${item.display_name || item.job_name}`)
        this.activeTab = 'jobs'
        this.closeBackgroundJobStartDialog()
        setTimeout(() => this.loadBackgroundJobs(), 500)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to start background job')
      } finally {
        this.backgroundJobStartSubmitting = false
      }
    },

    async loadBackgroundJobModules() {
      if (!this.selectedId) return

      this.backgroundJobModulesLoading = true

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs/catalog`)
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to load background job catalog')
        }

        const modules = Array.isArray(json.data) ? json.data : []
        this.backgroundJobModules = modules
          .map(item => this.normalizeBackgroundJobModule(item))
          .filter(item => item.job_name && !item.hidden_invalid)
      } catch (e) {
        this.backgroundJobModules = []
        ElMessage.error(e.message || 'Failed to load job modules')
      } finally {
        this.backgroundJobModulesLoading = false
      }
    },

    async loadBackgroundJobs() {
      if (!this.selectedId) return

      this.backgroundJobsLoading = true

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs`)
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to load background jobs')
        }

        const jobs = Array.isArray(json.data) ? json.data : []
        this.backgroundJobs = jobs

        if (this.selectedBackgroundJobId) {
          const exists = jobs.some(item => item.job_id === this.selectedBackgroundJobId)
          if (!exists) {
            this.backgroundJobDetailDialogVisible = false
            this.selectedBackgroundJobId = ''
          }
        }
      } catch (e) {
        this.backgroundJobs = []
        ElMessage.error(e.message || 'Failed to load background jobs')
      } finally {
        this.backgroundJobsLoading = false
      }
    },

    scheduleBackgroundJobsRefresh(clientId = '') {
      if (!this.visible) return
      if (clientId && clientId !== this.selectedId) return

      this.clearBackgroundJobsRefreshTimer()

      this.backgroundJobsRefreshTimer = setTimeout(() => {
        this.loadBackgroundJobs()
      }, 200)
    },

    async startBackgroundJob(jobName, params = {}) {
      if (!this.selectedId) {
        ElMessage.warning('Please select a device')
        return
      }

      const normalized = String(jobName || '').trim()
      if (!normalized) {
        ElMessage.warning('Invalid job name')
        return
      }

      try {
        await this.submitBackgroundJobStart(normalized, params)
        ElMessage.success(`Start request submitted: ${normalized}`)
        this.activeTab = 'jobs'
        setTimeout(() => this.loadBackgroundJobs(), 500)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to start background job')
      }
    },

    async stopBackgroundJob(job) {
      const jobKey = String(job && job.job_key || '').trim()
      if (!this.selectedId || !jobKey) {
        ElMessage.warning('Invalid background job')
        return
      }

      try {
        await ElMessageBox.confirm(
          `Stop "${job.display_name || job.job_name || jobKey}"?`,
          'Stop Background Job',
          {
            type: 'warning',
            confirmButtonText: 'Stop',
            cancelButtonText: 'Cancel',
          }
        )

        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs/stop`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ job_key: jobKey }),
        })

        const json = await res.json()
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to stop background job')
        }

        ElMessage.success(`Stop request sent: ${jobKey}`)
        await this.loadBackgroundJobs()
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return
        ElMessage.error(e.message || 'Failed to stop background job')
      }
    },

    openBackgroundJobDetail(job) {
      if (!job || !job.job_id) return
      this.selectedBackgroundJobId = job.job_id
      this.backgroundJobDetailDialogVisible = true
    },

    openBackgroundJobMessageDialog(message) {
      this.selectedBackgroundJobMessage = message || {}
      this.backgroundJobMessageDialogVisible = true
    },

    normalizeServerJobFilename(scriptName, fallbackName = 'new_job.py') {
      let normalized = String(scriptName || '').trim().replace(/\\/g, '/').replace(/^\/+/, '')
      if (!normalized) {
        normalized = fallbackName
      }

      if (!/\.py$/i.test(normalized)) {
        normalized = `${normalized}.py`
      }

      return normalized
    },

    triggerServerJobUpload() {
      if (!this.selectedId) {
        ElMessage.warning('Please select a device')
        return
      }

      const input = this.$refs.serverJobUploadInputRef
      if (input) {
        input.value = ''
        input.click()
      }
    },

    async handleServerJobUpload(event) {
      const input = event && event.target
      const file = input && input.files && input.files[0]
      if (!file) return

      if (!/\.py$/i.test(file.name || '')) {
        ElMessage.warning('Only .py files are supported')
        input.value = ''
        return
      }

      this.serverJobUploadLoading = true

      try {
        const formData = new FormData()
        formData.append('file', file, file.name)

        const res = await fetch('/api/jobs/upload', {
          method: 'POST',
          body: formData,
        })

        const json = await res.json()
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to upload job')
        }

        const uploadedName = this.normalizeServerJobFilename(json.data?.name || file.name)
        ElMessage.success(`Job uploaded: ${uploadedName}`)

        if (this.visible) {
          await this.loadBackgroundJobModules()
        }

        this.$emit('open-job-editor', uploadedName)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to upload job')
      } finally {
        this.serverJobUploadLoading = false
        if (input) input.value = ''
      }
    },

    async deleteBackgroundJobModule(scriptName) {
      const normalizedScriptName = this.normalizeServerJobFilename(scriptName)
      if (!normalizedScriptName) {
        ElMessage.warning('Invalid job name')
        return
      }

      try {
        await ElMessageBox.confirm(
          `Delete "${normalizedScriptName}"? This action cannot be undone.`,
          'Delete Job',
          {
            type: 'warning',
            confirmButtonText: 'Delete',
            cancelButtonText: 'Cancel',
          }
        )

        const res = await fetch('/api/jobs/delete', {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: normalizedScriptName }),
        })

        const json = await res.json()
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to delete job')
        }

        this.$emit('job-deleted', normalizedScriptName)
        ElMessage.success(`Deleted: ${normalizedScriptName}`)

        if (this.visible) {
          await this.loadBackgroundJobModules()
        }
      } catch (e) {
        if (e === 'cancel' || e === 'close') return
        ElMessage.error(e.message || 'Failed to delete job')
      }
    },

    async createRemoteJobPrompt() {
      if (!this.selectedId) {
        ElMessage.warning('Please select a device')
        return
      }

      try {
        const { value } = await ElMessageBox.prompt(
          'Enter the new job filename',
          'New Job',
          {
            confirmButtonText: 'Create',
            cancelButtonText: 'Cancel',
            inputValue: 'new_job.py',
            inputPlaceholder: 'new_job.py',
          }
        )

        this.$emit('open-new-job-editor', value || 'new_job.py')
      } catch (e) {
        if (e === 'cancel' || e === 'close') return
      }
    },

    buildBackgroundJobStateTagType(state) {
      const value = String(state || '').toLowerCase()
      if (value === 'running') return 'success'
      if (value === 'stopping') return 'warning'
      if (value === 'error') return 'danger'
      return 'info'
    },

    formatBackgroundJobDuration(totalSeconds) {
      const seconds = Number(totalSeconds || 0)
      if (!seconds) return '0s'

      const hours = Math.floor(seconds / 3600)
      const minutes = Math.floor((seconds % 3600) / 60)
      const remain = seconds % 60

      const parts = []
      if (hours) parts.push(`${hours}h`)
      if (minutes) parts.push(`${minutes}m`)
      if (remain || !parts.length) parts.push(`${remain}s`)

      return parts.join(' ')
    },

    formatBackgroundJobMessageText(text) {
      const raw = String(text || '').trim()
      return raw.replace(/^\[[^\]]*?client=[^\]]*?\]\s*/, '')
    },

    isBackgroundJobStartDisabled(item) {
      const rawKey = String(item?.job_key || item?.job_name || '').trim()
        .replace(/\\/g, '/')
        .replace(/\.py$/i, '')
      const key = rawKey.split('/').pop()
      return !!key && this.activeBackgroundJobKeySet.has(key)
    },
  },
}
</script>

<style scoped>
/* BackgroundJobsDialog 收口：列表状态、请求逻辑、轮询刷新和主样式都留在组件内。 */
.background-jobs-body {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.background-jobs-tabs {
  min-height: 0;
  height: 100%;
  display: flex;
  flex-direction: column;
}

.background-jobs-tabs :deep(.el-tabs__header) {
  margin-bottom: 12px;
}

.background-jobs-tabs :deep(.el-tabs__content) {
  flex: 1 1 auto;
  min-height: 0;
  overflow: hidden;
}

.background-jobs-tabs :deep(.el-tab-pane) {
  height: 100%;
  min-height: 0;
  overflow: hidden;
}

.background-jobs-toolbar {
  margin-bottom: 10px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.background-jobs-toolbar :deep(.el-button) {
  height: 32px;
  min-height: 32px;
  margin: 0;
  border-radius: 10px;
  padding-inline: 12px;
}

.hidden-file-input {
  display: none;
}

.panel-lite {
  background: #fff;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 14px;
  padding: 14px;
}

.background-jobs-section-title {
  font-size: 14px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 12px;
}

.background-jobs-modules,
.background-jobs-list-shell {
  height: calc(100% - 42px);
  min-height: 0;
  overflow-y: auto;
}

.background-job-module-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
  align-items: stretch;
}

.background-job-module-card {
  min-width: 0;
  min-height: 200px;
  padding: 14px;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 12px;
  background: #fff;
  display: flex;
  flex-direction: column;
  gap: 10px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  transition: box-shadow 0.2s ease, transform 0.2s ease;
}

.background-job-module-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
  transform: translateY(-1px);
}

.background-job-module-main {
  flex: 1 1 auto;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.background-job-module-name,
.background-job-module-key,
.background-job-module-desc {
  min-width: 0;
  margin: 0;
}

.background-job-module-name {
  font-size: 15px;
  line-height: 22px;
  font-weight: 700;
  color: var(--text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.background-job-module-key {
  font-size: 12px;
  line-height: 18px;
  color: #667085;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.background-job-module-desc {
  font-size: 13px;
  line-height: 20px;
  color: #667085;
  overflow: hidden;
  word-break: break-word;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
}

.background-job-module-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: flex-start;
  align-content: flex-start;
  min-height: 0;
  margin: auto 0 10px 0;
}

.background-job-module-tags :deep(.el-tag) {
  margin: 0;
}

.background-job-module-actions {
  margin-top: auto;
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  align-items: end;
}

.background-job-module-actions :deep(.el-button) {
  width: 100%;
  min-width: 0;
  margin: 0;
  border-radius: 10px;
}

.background-jobs-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 0;
  padding-right: 2px;
}

.background-job-summary-card {
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 14px;
  padding: 14px;
  background: #fff;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.02);
}

.background-job-summary-main,
.background-job-summary-title-wrap {
  min-width: 0;
}

.background-job-summary-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.background-job-summary-title-line {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.background-job-summary-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--text);
  word-break: break-word;
}

.background-job-summary-subtitle {
  margin-top: 8px;
  color: var(--muted);
  font-size: 12px;
}

.background-job-summary-stats {
  margin-top: 10px;
  display: flex;
  flex-wrap: wrap;
  gap: 8px 14px;
  font-size: 12px;
  color: var(--muted);
}

.background-job-summary-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  flex-shrink: 0;
}

.background-job-summary-actions :deep(.el-button) {
  margin: 0;
  border-radius: 10px;
}

.empty-state {
  color: var(--muted-2);
  text-align: center;
  padding: 24px;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

@media (max-width: 960px) {
  .background-job-summary-card {
    grid-template-columns: 1fr;
  }

  .background-job-summary-actions {
    justify-content: flex-start;
  }
}

@media (max-width: 768px), (max-height: 720px) {
  .background-job-module-list {
    grid-template-columns: 1fr;
  }

  .background-jobs-modules,
  .background-jobs-list-shell {
    height: calc(100% - 42px);
  }
}

@media (max-width: 640px) {
  .background-job-module-actions,
  .background-job-summary-actions {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    display: grid;
    width: 100%;
    gap: 6px;
  }

  .background-job-module-actions :deep(.el-button),
  .background-job-summary-actions :deep(.el-button) {
    width: 100%;
    justify-content: center;
  }
}
</style>

<style>
/* Background job 子弹窗样式收口：Start / Detail / Message 仍是独立组件，但样式随 Jobs 组件加载。 */
.background-job-start-tags {
  margin-bottom: 12px;
}

.background-job-param-hint {
  margin-top: 6px;
}

.background-job-detail-dialog .fixed-dialog-body,
.background-job-message-dialog .fixed-dialog-body {
  height: 100%;
  min-height: 0;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.background-job-detail-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
}

.background-job-detail-head-left,
.background-job-file-main {
  min-width: 0;
}

.background-job-title-line {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.background-job-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--text);
  word-break: break-word;
}

.background-job-subtitle {
  margin-top: 8px;
  color: var(--muted);
  font-size: 12px;
}

.background-job-card-head-right {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  flex-shrink: 0;
}

.background-job-stats {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
}

.background-job-stat {
  padding: 10px 12px;
  border-radius: 12px;
  background: #f8fafc;
  border: 1px solid rgba(15, 23, 42, 0.05);
}

.background-job-stat-label {
  font-size: 11px;
  color: var(--muted-2);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.background-job-stat-value {
  margin-top: 4px;
  font-size: 13px;
  color: var(--text);
  word-break: break-word;
}

.background-job-panels {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 12px;
  margin-top: 14px;
  flex: 1 1 auto;
  min-height: 0;
  overflow: hidden;
}

.background-job-panel {
  min-height: 0;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 12px;
  background: #fafcff;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.background-job-panel-title {
  padding: 10px 12px;
  font-size: 13px;
  font-weight: 700;
  border-bottom: 1px solid rgba(15, 23, 42, 0.06);
  background: #f8fafc;
}

.background-job-message-list,
.background-job-file-list {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.background-job-message-item,
.background-job-file-item {
  padding: 10px 12px;
  border-radius: 10px;
  background: #fff;
  border: 1px solid rgba(15, 23, 42, 0.05);
}

.background-job-message-item.clickable {
  cursor: pointer;
  transition: background 0.18s ease, border-color 0.18s ease;
}

.background-job-message-item.clickable:hover {
  background: #f8fafc;
  border-color: rgba(37, 99, 235, 0.16);
}

.background-job-message-time {
  font-size: 11px;
  color: var(--muted-2);
  margin-bottom: 6px;
}

.background-job-message-text {
  font-size: 13px;
  line-height: 1.6;
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-word;
}

.background-job-message-text.is-error,
.background-job-full-message-text.is-error {
  color: var(--danger);
}

.background-job-message-text.is-success,
.background-job-full-message-text.is-success {
  color: #166534;
}

.background-job-message-text.single-line {
  height: 20px;
  line-height: 20px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  word-break: normal;
}

.background-job-file-name {
  font-size: 13px;
  font-weight: 700;
  color: var(--text);
  word-break: break-word;
}

.background-job-file-meta {
  margin-top: 6px;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  font-size: 12px;
  color: var(--muted);
}

.background-job-file-actions {
  margin-top: 6px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.background-job-full-message-time {
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 10px;
}

.background-job-full-message-text {
  margin: 0;
  padding: 14px;
  min-height: 280px;
  max-height: 62vh;
  overflow: auto;
  border-radius: 14px;
  background: #f8fafc;
  border: 1px solid rgba(15, 23, 42, 0.06);
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.65;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
}


.background-job-detail-dialog .background-job-stat {
    height: 64px;
  min-height: 64px;
    box-sizing: border-box;
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding-top: 8px;
  padding-bottom: 8px;
}

.background-job-detail-dialog .background-job-stat-value {
  min-height: 20px;
  display: flex;
  align-items: center;
}

.background-job-detail-dialog .table-action-link,
.background-job-detail-dialog .table-action-link:link,
.background-job-detail-dialog .table-action-link:visited,
.background-job-detail-dialog .table-action-link:active {
  color: var(--el-color-primary) !important;
  font-size: 12px;
  line-height: 1;
  text-decoration: none !important;
  cursor: pointer;
  white-space: nowrap;
}

.background-job-detail-dialog .table-action-link:hover {
  color: var(--el-color-primary-light-5) !important;
  text-decoration: none !important;
}

.background-job-detail-dialog .empty-state,
.background-job-message-dialog .empty-state {
  color: var(--muted-2);
  text-align: center;
  padding: 24px;
}

.background-job-detail-dialog .empty-state.compact {
  padding: 12px;
}

@media (max-width: 768px), (max-height: 720px) {
  .background-job-stats,
  .background-job-panels {
    grid-template-columns: 1fr;
  }

  .background-job-detail-head {
    flex-direction: column;
    align-items: stretch;
  }

  .background-job-card-head-right {
    justify-content: flex-start;
  }
}
</style>