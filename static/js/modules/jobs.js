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
            const rawSource = String(item.source || '').trim().toLowerCase();
            const source = rawSource === 'server' ? 'server' : 'client';

            const rawJobName = String(item.job_name || item.name || item.job_key || '').trim();
            const rawJobKey = String(item.job_key || '').trim();
            const rawDisplayName = String(item.display_name || '').trim();

            const isHeadingLike = /^(available\s+client\s+job\s+modules:?|available\s+remote\s+scripts:?|no\s+remote\s+scripts\s+available)$/i.test(rawJobName);
            const looksSyntheticRemoteAlias = source === 'client' && /\s+-\s+server$/i.test(rawJobName);

            const stripPySuffix = (value = '') => String(value).replace(/\.py$/i, '').trim();

            let jobName = rawJobName;
            let jobKey = rawJobKey || stripPySuffix(rawJobName) || rawJobName;
            let displayName = rawDisplayName;

            if (source === 'client') {
                // client 模块：标题保留 .py，副标题显示去掉 .py 的模块名
                if (!displayName) {
                    displayName = jobName;
                }
                if (!jobKey) {
                    jobKey = stripPySuffix(jobName) || jobName;
                }
            } else {
                // server 脚本：标题优先 display_name（通常带 .py），副标题显示 job_key / job_name（通常不带 .py）
                if (!displayName) {
                    displayName = jobName;
                }
                if (!jobKey) {
                    jobKey = stripPySuffix(jobName) || jobName;
                }
            }

            const subtitle = jobKey && displayName !== jobKey ? jobKey : '';

            return {
                ...item,
                source,
                job_name: jobName,
                job_key: jobKey,
                display_name: displayName,
                subtitle,
                module_id: `${source}:${jobKey || jobName}`,
                hidden_invalid: !jobName || isHeadingLike || looksSyntheticRemoteAlias,
            };
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

        async startBackgroundJob(jobName, source = 'auto') {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            const normalized = String(jobName || '').trim();
            if (!normalized) {
                ElementPlus.ElMessage.warning('Invalid job name');
                return;
            }

            const normalizedSource = ['auto', 'client', 'server'].includes(String(source || '').trim())
                ? String(source || '').trim()
                : 'auto';

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs/start`, {
                    method: 'POST',
                    headers: this.getTabScopedHeaders({'Content-Type': 'application/json'}),
                    body: JSON.stringify({job_name: normalized, source: normalizedSource})
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to start background job');
                }

                const taskId = json.data && json.data.task_id;
                this.setActiveTask(this.selectedId, taskId || '');

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

        normalizeServerJobFilename(scriptName, fallbackName = 'new_server_job.py') {
            let normalized = String(scriptName || '').trim().replace(/\\/g, '/').replace(/^\/+/, '');
            if (!normalized) {
                normalized = fallbackName;
            }
            if (!/\.py$/i.test(normalized)) {
                normalized = `${normalized}.py`;
            }
            return normalized;
        },

        buildServerJobTemplate(scriptName = 'new_server_job.py') {
            const normalizedScriptName = this.normalizeServerJobFilename(scriptName);
            const classBaseName = normalizedScriptName
                .replace(/\.py$/i, '')
                .split('/')
                .pop()
                .split(/[^a-zA-Z0-9]+/)
                .filter(Boolean)
                .map(part => part.charAt(0).toUpperCase() + part.slice(1))
                .join('') || 'NewServerJob';

            return `import time\n\nfrom client.jobs.core.job import Job\n\n\nclass ${classBaseName}(Job):\n    def __init__(self):\n        super().__init__()\n        self.interval = 10\n\n    def run(self):\n        self.mark_running()\n        self.send_to_server(1, "${normalizedScriptName} started")\n\n        try:\n            while not self.stop_event.is_set():\n                self.send_to_server(1, f"heartbeat: {time.strftime('%Y-%m-%d %H:%M:%S')}")\n                time.sleep(self.interval)\n        finally:\n            self.send_to_server(1, "${normalizedScriptName} stopped")\n            self.mark_stopped()\n\n    def stop(self, notify=True):\n        self.request_stop(notify=notify)\n`;
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

                const res = await fetch('/api/server/jobs/upload', {
                    method: 'POST',
                    body: formData
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to upload script');
                }

                const uploadedName = this.normalizeServerJobFilename(json.data?.name || file.name);
                ElementPlus.ElMessage.success(`Script uploaded: ${uploadedName}`);

                if (this.backgroundJobsDialogVisible) {
                    await this.loadBackgroundJobModules();
                }

                await this.openRemoteJobEditor(uploadedName);
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to upload script');
            } finally {
                this.serverJobUploadLoading = false;
                if (input) input.value = '';
            }
        },

        async deleteRemoteScript(scriptName) {
            const normalizedScriptName = this.normalizeServerJobFilename(scriptName);
            if (!normalizedScriptName) {
                ElementPlus.ElMessage.warning('Invalid script name');
                return;
            }

            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Delete "${normalizedScriptName}"? This action cannot be undone.`,
                    'Delete Server Job',
                    {
                        type: 'warning',
                        confirmButtonText: 'Delete',
                        cancelButtonText: 'Cancel',
                    }
                );

                const res = await fetch('/api/server/jobs/delete', {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name: normalizedScriptName})
                });
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to delete script');
                }

                if (this.previewDialogVisible && this.previewSource === 'server_job') {
                    const currentPreviewName = this.normalizeServerJobFilename(this.previewFilePath || this.previewTitle || '');
                    if (currentPreviewName === normalizedScriptName) {
                        this.previewDialogVisible = false;
                        this.destroyMonacoEditor();
                    }
                }

                ElementPlus.ElMessage.success(`Deleted: ${normalizedScriptName}`);

                if (this.backgroundJobsDialogVisible) {
                    await this.loadBackgroundJobModules();
                }
            } catch (e) {
                if (e === 'cancel' || e === 'close') return;
                ElementPlus.ElMessage.error(e.message || 'Failed to delete script');
            }
        },

        async createRemoteJobPrompt() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            try {
                const {value} = await ElementPlus.ElMessageBox.prompt(
                    'Enter the new server-side job filename',
                    'New Server Job',
                    {
                        confirmButtonText: 'Create',
                        cancelButtonText: 'Cancel',
                        inputValue: 'new_server_job.py',
                        inputPlaceholder: 'new_server_job.py',
                    }
                );

                this.openNewRemoteJobEditor(value || 'new_server_job.py');
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
    }
};








