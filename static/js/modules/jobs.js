window.AppJobsModule = {
    data() {
        return {
            backgroundJobsDialogVisible: false,
            backgroundJobsLoading: false,
            backgroundJobModulesLoading: false,
            backgroundJobModules: [],
            backgroundJobs: [],
            backgroundJobsRefreshTimer: null,
            backgroundJobDetailDialogVisible: false,
            selectedBackgroundJobId: '',
            backgroundJobsActiveTab: 'modules',
            backgroundJobMessageDialogVisible: false,
            selectedBackgroundJobMessage: {},
            serverJobUploadLoading: false,
            backgroundJobStartDialogVisible: false,
            backgroundJobStartSubmitting: false,
            pendingStartJobModule: null,
            backgroundJobParamForm: {},
        }
    },

    methods: {
        async openBackgroundJobsDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            this.backgroundJobsDialogVisible = true;
            await Promise.all([
                this.loadBackgroundJobModules(),
                this.loadBackgroundJobs()
            ]);
        },

        normalizeBackgroundJobModule(item = {}) {
            const rawJobName = String(item.job_name || item.name || item.job_key || '').trim();
            const rawJobKey = String(item.job_key || '').trim();
            const rawDisplayName = String(item.display_name || '').trim();
            const metadata = this.normalizeJobMetadata(item.metadata || {});

            const isHeadingLike = /^(available\s+client\s+job\s+modules:?|available\s+remote\s+scripts:?|no\s+remote\s+scripts\s+available)$/i.test(rawJobName);
            const stripPySuffix = (value = '') => String(value).replace(/\.py$/i, '').trim();

            let jobName = rawJobName;
            let jobKey = rawJobKey || stripPySuffix(rawJobName) || rawJobName;
            let displayName = rawDisplayName;

            if (!displayName) {
                displayName = metadata.display_name || jobName;
            }
            if (!jobKey) {
                jobKey = stripPySuffix(jobName) || jobName;
            }

            const subtitle = jobKey && displayName !== jobKey ? jobKey : '';
            const description = String(item.description || metadata.description || '').trim();

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
            };
        },

        normalizeJobMetadata(metadata = {}) {
            if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
                return {
                    name: '',
                    display_name: '',
                    description: '',
                    platforms: [],
                    params: [],
                };
            }

            const normalizeParam = (item = {}) => {
                const name = String(item.name || '').trim();
                if (!name) return null;
                return {
                    ...item,
                    name,
                    type: String(item.type || 'string').trim().toLowerCase() || 'string',
                    required: !!item.required,
                    description: String(item.description || '').trim(),
                };
            };

            return {
                ...metadata,
                name: String(metadata.name || '').trim(),
                display_name: String(metadata.display_name || '').trim(),
                description: String(metadata.description || '').trim(),
                platforms: this.normalizeJobPlatforms(metadata.platforms),
                params: Array.isArray(metadata.params)
                    ? metadata.params.map(item => normalizeParam(item)).filter(Boolean)
                    : [],
            };
        },

        normalizeJobPlatforms(platforms) {
            const source = Array.isArray(platforms)
                ? platforms
                : (typeof platforms === 'string' && platforms.trim() ? [platforms] : []);

            const result = [];
            const seen = new Set();
            for (const item of source) {
                const normalized = this.normalizeJobPlatform(item);
                if (!normalized || seen.has(normalized)) continue;
                seen.add(normalized);
                result.push(normalized);
            }
            return result;
        },

        normalizeJobPlatform(platform) {
            const value = String(platform || '').trim().toLowerCase();
            if (!value) return '';
            if (['*', 'all', 'any'].includes(value)) return '*';
            if (['darwin', 'mac', 'macos', 'osx'].includes(value)) return 'mac';
            if (['windows', 'win', 'win32', 'nt'].includes(value)) return 'win';
            if (value === 'linux') return 'linux';
            return value;
        },

        normalizeClientPlatform(osType = '') {
            const value = String(osType || '').trim().toLowerCase();
            if (!value) return '';
            if (value.includes('darwin') || value.includes('mac')) return 'mac';
            if (value.includes('win')) return 'win';
            if (value.includes('linux')) return 'linux';
            return this.normalizeJobPlatform(value);
        },

        formatJobPlatformLabel(platforms) {
            const normalized = this.normalizeJobPlatforms(platforms);
            if (!normalized.length || normalized.includes('*')) {
                return 'All OS';
            }

            const labels = normalized.map(item => {
                if (item === 'mac') return 'macOS';
                if (item === 'win') return 'Windows';
                if (item === 'linux') return 'Linux';
                if (item === 'ios') return 'iOS';
                return item;
            });

            return labels.join(' / ');
        },

        isJobSupportedForCurrentConnection(item) {
            const metadata = this.normalizeJobMetadata(item?.metadata || {});
            const platforms = metadata.platforms || [];
            if (!platforms.length || platforms.includes('*')) return true;

            const current = this.normalizeClientPlatform(this.currentConnection?.os_type || '');
            if (!current) return true;

            return platforms.includes(current);
        },

        hasBackgroundJobParams(item) {
            const metadata = this.normalizeJobMetadata(item?.metadata || {});
            return Array.isArray(metadata.params) && metadata.params.length > 0;
        },

        buildBackgroundJobParamDefaults(item) {
            const metadata = this.normalizeJobMetadata(item?.metadata || {});
            const result = {};

            for (const param of metadata.params || []) {
                if (Object.prototype.hasOwnProperty.call(param, 'default')) {
                    const defaultValue = param.default;
                    result[param.name] = defaultValue === null || defaultValue === undefined ? '' : String(defaultValue);
                } else {
                    result[param.name] = '';
                }
            }

            return result;
        },

        openBackgroundJobStartDialog(item) {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            if (!item || !String(item.job_name || '').trim()) {
                ElementPlus.ElMessage.warning('Invalid job name');
                return;
            }

            if (!this.isJobSupportedForCurrentConnection(item)) {
                const jobName = item.display_name || item.job_name;
                const platformLabel = this.formatJobPlatformLabel(item.metadata?.platforms || []);
                ElementPlus.ElMessage.warning(`${jobName} only supports: ${platformLabel}`);
                return;
            }

            if (this.isBackgroundJobStartDisabled(item)) {
                ElementPlus.ElMessage.warning('This background job is already running');
                return;
            }

            if (!this.hasBackgroundJobParams(item)) {
                this.startBackgroundJob(item.job_name);
                return;
            }

            this.pendingStartJobModule = item;
            this.backgroundJobParamForm = this.buildBackgroundJobParamDefaults(item);
            this.backgroundJobStartDialogVisible = true;
        },

        closeBackgroundJobStartDialog() {
            this.backgroundJobStartDialogVisible = false;
            this.backgroundJobStartSubmitting = false;
            this.pendingStartJobModule = null;
            this.backgroundJobParamForm = {};
        },

        coerceBackgroundJobParamValue(param, rawValue) {
            const type = String(param?.type || 'string').trim().toLowerCase();
            const value = rawValue === null || rawValue === undefined ? '' : String(rawValue).trim();

            if (type === 'integer' || type === 'int') {
                if (!/^-?\d+$/.test(value)) {
                    throw new Error(`Param "${param.name}" must be an integer`);
                }
                const parsed = parseInt(value, 10);
                if (param.min !== undefined && parsed < Number(param.min)) {
                    throw new Error(`Param "${param.name}" must be >= ${param.min}`);
                }
                if (param.max !== undefined && parsed > Number(param.max)) {
                    throw new Error(`Param "${param.name}" must be <= ${param.max}`);
                }
                return parsed;
            }

            if (type === 'number' || type === 'float') {
                const parsed = Number(value);
                if (Number.isNaN(parsed)) {
                    throw new Error(`Param "${param.name}" must be a number`);
                }
                if (param.min !== undefined && parsed < Number(param.min)) {
                    throw new Error(`Param "${param.name}" must be >= ${param.min}`);
                }
                if (param.max !== undefined && parsed > Number(param.max)) {
                    throw new Error(`Param "${param.name}" must be <= ${param.max}`);
                }
                return parsed;
            }

            if (type === 'boolean' || type === 'bool') {
                const lowered = value.toLowerCase();
                if (['1', 'true', 'yes', 'on'].includes(lowered)) return true;
                if (['0', 'false', 'no', 'off'].includes(lowered)) return false;
                throw new Error(`Param "${param.name}" must be true/false`);
            }

            return value;
        },

        buildBackgroundJobStartParams(item) {
            const metadata = this.normalizeJobMetadata(item?.metadata || {});
            const params = {};

            for (const param of metadata.params || []) {
                const hasValue = Object.prototype.hasOwnProperty.call(this.backgroundJobParamForm, param.name);
                const rawValue = hasValue ? this.backgroundJobParamForm[param.name] : '';
                const textValue = rawValue === null || rawValue === undefined ? '' : String(rawValue).trim();

                if (!textValue) {
                    if (param.required && (param.default === undefined || param.default === null || String(param.default).trim() === '')) {
                        throw new Error(`Missing required param: ${param.name}`);
                    }
                    if (param.default !== undefined && param.default !== null && String(param.default).trim() !== '') {
                        params[param.name] = this.coerceBackgroundJobParamValue(param, param.default);
                    }
                    continue;
                }

                params[param.name] = this.coerceBackgroundJobParamValue(param, rawValue);
            }

            return params;
        },

        async submitBackgroundJobStart(jobName, params = {}) {
            const normalized = String(jobName || '').trim();
            if (!normalized) {
                ElementPlus.ElMessage.warning('Invalid job name');
                return;
            }

            const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs/start`, {
                method: 'POST',
                headers: this.getTabScopedHeaders({'Content-Type': 'application/json'}),
                body: JSON.stringify({job_name: normalized, params})
            });

            const json = await res.json();
            if (!res.ok || json.code !== 0) {
                throw new Error(json.message || 'Failed to start background job');
            }

            const taskId = json.data && json.data.task_id;
            this.setActiveTask(this.selectedId, taskId || '');
            return json.data || {};
        },

        async confirmStartBackgroundJobWithParams() {
            const item = this.pendingStartJobModule;
            if (!item) {
                this.closeBackgroundJobStartDialog();
                return;
            }

            try {
                this.backgroundJobStartSubmitting = true;
                const params = this.buildBackgroundJobStartParams(item);
                await this.submitBackgroundJobStart(item.job_name, params);
                ElementPlus.ElMessage.success(`Start request submitted: ${item.display_name || item.job_name}`);
                this.backgroundJobsActiveTab = 'jobs';
                this.closeBackgroundJobStartDialog();
                setTimeout(() => this.loadBackgroundJobs(), 500);
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to start background job');
            } finally {
                this.backgroundJobStartSubmitting = false;
            }
        },

        async loadBackgroundJobModules() {
            if (!this.selectedId) return;

            this.backgroundJobModulesLoading = true;
            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs/catalog`);
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load background job catalog');
                }

                const modules = Array.isArray(json.data) ? json.data : [];
                this.backgroundJobModules = modules
                    .map(item => this.normalizeBackgroundJobModule(item))
                    .filter(item => item.job_name && !item.hidden_invalid);
            } catch (e) {
                this.backgroundJobModules = [];
                ElementPlus.ElMessage.error(e.message || 'Failed to load job modules');
            } finally {
                this.backgroundJobModulesLoading = false;
            }
        },

        async loadBackgroundJobs() {
            if (!this.selectedId) return;

            this.backgroundJobsLoading = true;
            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs`);
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load background jobs');
                }

                const jobs = Array.isArray(json.data) ? json.data : [];
                this.backgroundJobs = jobs;

                if (this.selectedBackgroundJobId) {
                    const exists = jobs.some(item => item.job_id === this.selectedBackgroundJobId);
                    if (!exists) {
                        this.backgroundJobDetailDialogVisible = false;
                        this.selectedBackgroundJobId = '';
                    }
                }
            } catch (e) {
                this.backgroundJobs = [];
                ElementPlus.ElMessage.error(e.message || 'Failed to load background jobs');
            } finally {
                this.backgroundJobsLoading = false;
            }
        },

        scheduleBackgroundJobsRefresh(clientId = '') {
            if (!this.backgroundJobsDialogVisible) return;
            if (clientId && clientId !== this.selectedId) return;

            if (this.backgroundJobsRefreshTimer) {
                clearTimeout(this.backgroundJobsRefreshTimer);
            }

            this.backgroundJobsRefreshTimer = setTimeout(() => {
                this.loadBackgroundJobs();
            }, 200);
        },

        async startBackgroundJob(jobName, params = {}) {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            const normalized = String(jobName || '').trim();
            if (!normalized) {
                ElementPlus.ElMessage.warning('Invalid job name');
                return;
            }

            try {
                await this.submitBackgroundJobStart(normalized, params);
                ElementPlus.ElMessage.success(`Start request submitted: ${normalized}`);
                this.backgroundJobsActiveTab = 'jobs';
                setTimeout(() => this.loadBackgroundJobs(), 500);
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to start background job');
            }
        },

        async stopBackgroundJob(job) {
            const jobKey = String(job && job.job_key || '').trim();
            if (!this.selectedId || !jobKey) {
                ElementPlus.ElMessage.warning('Invalid background job');
                return;
            }

            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Stop "${job.display_name || job.job_name || jobKey}"?`,
                    'Stop Background Job',
                    {
                        type: 'warning',
                        confirmButtonText: 'Stop',
                        cancelButtonText: 'Cancel'
                    }
                );

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs/stop`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({job_key: jobKey})
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to stop background job');
                }

                ElementPlus.ElMessage.success(`Stop request sent: ${jobKey}`);
                await this.loadBackgroundJobs();
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Failed to stop background job');
            }
        },

        openBackgroundJobDetail(job) {
            if (!job || !job.job_id) return;
            this.selectedBackgroundJobId = job.job_id;
            this.backgroundJobDetailDialogVisible = true;
        },

        openBackgroundJobMessageDialog(message) {
            this.selectedBackgroundJobMessage = message || {};
            this.backgroundJobMessageDialogVisible = true;
        },

        normalizeServerJobFilename(scriptName, fallbackName = 'new_job.py') {
            let normalized = String(scriptName || '').trim().replace(/\\/g, '/').replace(/^\/+/, '');
            if (!normalized) {
                normalized = fallbackName;
            }
            if (!/\.py$/i.test(normalized)) {
                normalized = `${normalized}.py`;
            }
            return normalized;
        },

        buildServerJobTemplate(scriptName = 'new_job.py') {
            const normalizedScriptName = this.normalizeServerJobFilename(scriptName);
            const classBaseName = normalizedScriptName
                .replace(/\.py$/i, '')
                .split('/')
                .pop()
                .split(/[^a-zA-Z0-9]+/)
                .filter(Boolean)
                .map(part => part.charAt(0).toUpperCase() + part.slice(1))
                .join('') || 'NewBackgroundJob';

            return `JOB_METADATA = {\n    "name": "${normalizedScriptName.replace(/\.py$/i, '')}",\n    "display_name": "${classBaseName}",\n    "description": "Describe what this job does",\n    "platforms": ["mac"],\n    "params": [\n        {\n            "name": "interval_seconds",\n            "type": "integer",\n            "required": false,\n            "default": 10,\n            "min": 1,\n            "description": "Loop interval in seconds"\n        }\n    ]\n}\n\nimport time\n\nfrom client.jobs.core.job import Job\n\n\nclass ${classBaseName}(Job):\n    def __init__(self):\n        super().__init__()\n        self.interval = 10\n\n    def on_context_bound(self):\n        self.interval = int(self.get_job_param("interval_seconds", 10) or 10)\n\n    def run(self):\n        self.mark_running()\n        self.send_to_server(1, "${normalizedScriptName} started")\n\n        try:\n            while not self.stop_event.is_set():\n                self.send_to_server(1, f"heartbeat: {time.strftime('%Y-%m-%d %H:%M:%S')}")\n                time.sleep(self.interval)\n        finally:\n            self.send_to_server(1, "${normalizedScriptName} stopped")\n            self.mark_stopped()\n\n    def stop(self, notify=True):\n        self.request_stop(notify=notify)\n`;
        },

        triggerServerJobUpload() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            const input = document.getElementById('server-job-upload-input');
            if (input) {
                input.value = '';
                input.click();
            }
        },

        async handleServerJobUpload(event) {
            const input = event && event.target;
            const file = input && input.files && input.files[0];
            if (!file) {
                return;
            }

            if (!/\.py$/i.test(file.name || '')) {
                ElementPlus.ElMessage.warning('Only .py files are supported');
                input.value = '';
                return;
            }

            this.serverJobUploadLoading = true;
            try {
                const formData = new FormData();
                formData.append('file', file, file.name);

                const res = await fetch('/api/jobs/upload', {
                    method: 'POST',
                    body: formData
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to upload job');
                }

                const uploadedName = this.normalizeServerJobFilename(json.data?.name || file.name);
                ElementPlus.ElMessage.success(`Job uploaded: ${uploadedName}`);

                if (this.backgroundJobsDialogVisible) {
                    await this.loadBackgroundJobModules();
                }

                if (typeof this.openRemoteJobEditor === 'function') {
                    await this.openRemoteJobEditor(uploadedName);
                }
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to upload job');
            } finally {
                this.serverJobUploadLoading = false;
                if (input) input.value = '';
            }
        },

        async deleteRemoteScript(scriptName) {
            const normalizedScriptName = this.normalizeServerJobFilename(scriptName);
            if (!normalizedScriptName) {
                ElementPlus.ElMessage.warning('Invalid job name');
                return;
            }

            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Delete "${normalizedScriptName}"? This action cannot be undone.`,
                    'Delete Job',
                    {
                        type: 'warning',
                        confirmButtonText: 'Delete',
                        cancelButtonText: 'Cancel',
                    }
                );

                const res = await fetch('/api/jobs/delete', {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name: normalizedScriptName})
                });
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to delete job');
                }

                if (
                    this.previewDialogVisible &&
                    (this.previewSource === 'server_job' || this.previewSource === 'background_job')
                ) {
                    const currentPreviewName = this.normalizeServerJobFilename(this.previewFilePath || this.previewTitle || '');
                    if (currentPreviewName === normalizedScriptName) {
                        this.previewDialogVisible = false;
                        if (typeof this.destroyMonacoEditor === 'function') {
                            this.destroyMonacoEditor();
                        }
                    }
                }

                ElementPlus.ElMessage.success(`Deleted: ${normalizedScriptName}`);

                if (this.backgroundJobsDialogVisible) {
                    await this.loadBackgroundJobModules();
                }
            } catch (e) {
                if (e === 'cancel' || e === 'close') return;
                ElementPlus.ElMessage.error(e.message || 'Failed to delete job');
            }
        },

        async createRemoteJobPrompt() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            try {
                const {value} = await ElementPlus.ElMessageBox.prompt(
                    'Enter the new job filename',
                    'New Job',
                    {
                        confirmButtonText: 'Create',
                        cancelButtonText: 'Cancel',
                        inputValue: 'new_job.py',
                        inputPlaceholder: 'new_job.py',
                    }
                );

                if (typeof this.openNewRemoteJobEditor === 'function') {
                    this.openNewRemoteJobEditor(value || 'new_job.py');
                }
            } catch (e) {
                if (e === 'cancel' || e === 'close') return;
            }
        },

        buildBackgroundJobStateTagType(state) {
            const value = String(state || '').toLowerCase();
            if (value === 'running') return 'success';
            if (value === 'stopping') return 'warning';
            if (value === 'error') return 'danger';
            return 'info';
        },

        formatBackgroundJobDuration(totalSeconds) {
            const seconds = Number(totalSeconds || 0);
            if (!seconds) return '0s';

            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const remain = seconds % 60;

            const parts = [];
            if (hours) parts.push(`${hours}h`);
            if (minutes) parts.push(`${minutes}m`);
            if (remain || !parts.length) parts.push(`${remain}s`);

            return parts.join(' ');
        },

        formatBackgroundJobMessageText(text) {
            const raw = String(text || '').trim();
            return raw.replace(/^\[[^\]]*?client=[^\]]*?\]\s*/, '');
        },

        isBackgroundJobStartDisabled(item) {
            const rawKey = String(item?.job_key || item?.job_name || '').trim()
                .replace(/\\/g, '/')
                .replace(/\.py$/i, '');
            const key = rawKey.split('/').pop();
            return !!key && this.activeBackgroundJobKeySet.has(key);
        },
    },

    computed: {
        selectedBackgroundJob() {
            return this.backgroundJobs.find(item => item.job_id === this.selectedBackgroundJobId) || null;
        },

        sortedBackgroundJobs() {
            return [...this.backgroundJobs].sort((a, b) => {
                const ta = String(a.updated_at || a.started_at || a.created_at || '');
                const tb = String(b.updated_at || b.started_at || b.created_at || '');
                return tb.localeCompare(ta);
            });
        },

        selectedBackgroundJobMessagesDesc() {
            const messages = this.selectedBackgroundJob && Array.isArray(this.selectedBackgroundJob.messages)
                ? this.selectedBackgroundJob.messages
                : [];

            return [...messages].sort((a, b) => {
                const ta = String(a.time || '');
                const tb = String(b.time || '');
                return tb.localeCompare(ta);
            });
        },

        activeBackgroundJobKeySet() {
            const set = new Set();
            for (const job of this.backgroundJobs || []) {
                const state = String(job?.state || '').trim().toLowerCase();
                if (!['running', 'stopping'].includes(state)) continue;

                const rawKey = String(job?.job_key || job?.job_name || '').trim()
                    .replace(/\\/g, '/')
                    .replace(/\.py$/i, '');
                const key = rawKey.split('/').pop();
                if (key) set.add(key);
            }
            return set;
        },
    },

    watch: {
        backgroundJobsDialogVisible(val) {
            if (!val) {
                if (this.backgroundJobsRefreshTimer) {
                    clearTimeout(this.backgroundJobsRefreshTimer);
                    this.backgroundJobsRefreshTimer = null;
                }
            }
        },

        backgroundJobDetailDialogVisible(val) {
            if (!val) {
                this.selectedBackgroundJobId = '';
            }
        },

        backgroundJobMessageDialogVisible(val) {
            if (!val) {
                this.selectedBackgroundJobMessage = {};
            }
        },

        backgroundJobStartDialogVisible(val) {
            if (!val) {
                this.closeBackgroundJobStartDialog();
            }
        },
    }
};
