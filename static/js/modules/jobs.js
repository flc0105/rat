window.AppJobsModule = {
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

// async loadBackgroundJobModules() {
//     if (!this.selectedId) return;
//
//     this.backgroundJobModulesLoading = true;
//     try {
//         // 加载本地模块
//         const localRes = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs/modules`);
//         const localJson = await localRes.json();
//
//         // 加载远程脚本
//         const remoteRes = await fetch('/api/server/jobs/list');
//         const remoteJson = await remoteRes.json();
//
//         const localModules = localRes.ok && localJson.code === 0 && Array.isArray(localJson.data)
//             ? localJson.data.map(item => ({ ...item, source: 'local' }))
//             : [];
//
//         const remoteModules = remoteRes.ok && remoteJson.code === 0 && Array.isArray(remoteJson.data?.scripts)
//             ? remoteJson.data.scripts.map(item => ({
//                 ...item,
//                 source: 'remote',  // 关键：标记为 remote
//                 job_name: item.name,
//                 job_key: item.name.replace(/\.py$/, '')
//               }))
//             : [];
//
//         this.backgroundJobModules = [...localModules, ...remoteModules];
//     } catch (e) {
//         this.backgroundJobModules = [];
//         ElementPlus.ElMessage.error(e.message || 'Failed to load job modules');
//     } finally {
//         this.backgroundJobModulesLoading = false;
//     }
// },

        async loadBackgroundJobModules() {
            if (!this.selectedId) return;

            this.backgroundJobModulesLoading = true;
            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs/modules`);
                const json = await res.json();

                // 加载远程脚本
                const remoteRes = await fetch('/api/server/jobs/list');
                const remoteJson = await remoteRes.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load client job modules');
                }

                if (!remoteRes.ok || remoteJson.code !== 0) {
                    throw new Error(json.message || 'Failed to load server job modules');
                }

                localModules = json.data
                remoteModules = remoteJson.data

                this.backgroundJobModules = [...localModules, ...remoteModules];

                // this.backgroundJobModules = Array.isArray(json.data) ? json.data : [];
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

        // async startBackgroundJob(jobName) {
        //     if (!this.selectedId) {
        //         ElementPlus.ElMessage.warning('Please select a device');
        //         return;
        //     }
        //
        //     const normalized = String(jobName || '').trim();
        //     if (!normalized) {
        //         ElementPlus.ElMessage.warning('Invalid job name');
        //         return;
        //     }
        //
        //     try {
        //         const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs/start`, {
        //             method: 'POST',
        //             headers: {'Content-Type': 'application/json'},
        //             body: JSON.stringify({job_name: normalized})
        //         });
        //
        //         const json = await res.json();
        //         if (!res.ok || json.code !== 0) {
        //             throw new Error(json.message || 'Failed to start background job');
        //         }
        //
        //         ElementPlus.ElMessage.success(`Background job started: ${normalized}`);
        //         this.backgroundJobsActiveTab = 'jobs';
        //         await this.loadBackgroundJobs();
        //     } catch (e) {
        //         ElementPlus.ElMessage.error(e.message || 'Failed to start background job');
        //     }
        // },

        // static/js/modules/jobs.js

        async startBackgroundJob(jobName, source = 'client') {
            console.log(source)
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
                let command;
                if (source === 'server') {
                    // 远程脚本用 start_job_remote
                    command = `start_job_remote ${normalized}`;
                } else {
                    // 本地脚本用 start_job
                    command = `start_job ${normalized}`;
                }

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command`, {
                    method: 'POST',
                    headers: this.getTabScopedHeaders({'Content-Type': 'application/json'}),
                    body: JSON.stringify({command})
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to start background job');
                }

                const taskId = json.data && json.data.task_id;
                this.setActiveTask(this.selectedId, taskId || '');

                ElementPlus.ElMessage.success(`Background job started: ${normalized}`);
                this.backgroundJobsActiveTab = 'jobs';
                await this.loadBackgroundJobs();
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
        }
    }
};





