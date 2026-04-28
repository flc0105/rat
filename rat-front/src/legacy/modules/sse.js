export default {
    data() {
        return {
            tabId: '',
            eventSource: null,
            sseReady: false,
        }
    },


    methods: {
        initSSE() {
            if (this.eventSource) this.eventSource.close();

            const tabId = this.ensureTabId();
            const streamUrl = `/api/stream?tab_id=${encodeURIComponent(tabId)}`;
            const es = new EventSource(streamUrl);
            this.eventSource = es;

            const getConnectionLabel = (clientId) => {
                const normalizedClientId = String(clientId || '').trim();
                const conn = this.connections.find(item => item.client_id === normalizedClientId) || {};
                return conn.hostname || conn.client_id || normalizedClientId || 'Unknown device';
            };

            es.addEventListener('open', () => {
                if (!this.sseReady) this.sseReady = true;
            });

            es.addEventListener('connection_online', (event) => {
                const payload = JSON.parse(event.data);
                const conn = payload.connection;
                this.upsertConnection(conn);

                ElementPlus.ElNotification({
                    title: 'Device Online',
                    message: `${conn.hostname || conn.client_id} is now available`,
                    type: 'success'
                });
            });

            es.addEventListener('connection_offline', (event) => {
                const payload = JSON.parse(event.data);
                const clientId = payload.client_id;
                const conn = payload.connection || this.connections.find(item => item.client_id === clientId) || {client_id: clientId};

                this.upsertConnection({
                    ...conn,
                    connection_state: 'offline',
                    disconnected_at: conn.disconnected_at || payload.time,
                    is_transfer_active: false,
                });

                this.clearActiveTask(clientId);

                ElementPlus.ElNotification({
                    title: 'Device Offline',
                    message: `${(conn && conn.hostname) || clientId} went offline`,
                    type: 'warning'
                });
            });

            //TODO 这里会让dataList重新渲染

            es.addEventListener('connection_heartbeat', (event) => {
                const payload = JSON.parse(event.data);
                const conn = payload.connection;
                //
                // //add
                // this.statusNowTick = Date.now();

                this.upsertConnection(conn);
            });

            es.addEventListener('command_result', (event) => {
                const payload = JSON.parse(event.data);
                this.appendOutput(payload.client_id, payload.text || '');
            });

            es.addEventListener('command_complete', async (event) => {
                const payload = JSON.parse(event.data);
                const statusText = String(payload.status || '').trim();

                let finishText = 'Failed';
                let finishKind = 'error';

                if (statusText === 'cancelled' || payload.cancelled) {
                    finishText = 'Cancelled';
                    finishKind = 'info';
                } else if (payload.success) {
                    finishText = 'Success';
                    finishKind = 'success';
                }

                this.appendOutput(
                    payload.client_id,
                    `[Command finished] ${payload.command} (${finishText})`,
                    finishKind
                );

                this.clearActiveTask(payload.client_id, payload.task_id);

                const pendingRefresh = this.pendingRemoteUploadRefresh;
                if (
                    pendingRefresh &&
                    pendingRefresh.taskId &&
                    payload.task_id === pendingRefresh.taskId
                ) {
                    const refreshClientId = pendingRefresh.clientId;
                    const refreshPath = pendingRefresh.path || '';

                    this.pendingRemoteUploadRefresh = null;

                    if (
                        payload.success &&
                        this.remoteFilesDialogVisible &&
                        this.selectedId === refreshClientId
                    ) {
                        try {
                            await this.loadRemoteDirectory(refreshPath);
                        } catch (e) {
                        }
                    }
                }

                this.commandCandidatesLoadedFor = '';
                await this.loadConnections();
            });

            es.addEventListener('background_message', async (event) => {
                const payload = JSON.parse(event.data);
                this.appendOutput(payload.client_id, `[Background] ${payload.text || ''}`, 'info');
                await this.loadConnections();
            });

            es.addEventListener('background_job_status', async (event) => {
                const payload = JSON.parse(event.data);
                // this.scheduleBackgroundJobsRefresh(payload.client_id);
                this.scheduleBackgroundJobsRefresh?.(payload.client_id);
            });

            es.addEventListener('background_job_lifecycle', async (event) => {
                const payload = JSON.parse(event.data || '{}');
                const state = String(payload.state || payload.status || '').trim().toLowerCase();
                const jobName = payload.display_name || payload.job_key || payload.job_name || 'background job';
                const deviceName = getConnectionLabel(payload.client_id);

                let title = 'Background Job';
                let type = 'info';
                let stateText = state || 'updated';

                if (state === 'running') {
                    title = 'Background Job Started';
                    type = 'success';
                    stateText = 'started';
                } else if (state === 'stopped') {
                    title = 'Background Job Finished';
                    type = 'success';
                    stateText = 'finished';
                } else if (state === 'error') {
                    title = 'Background Job Error';
                    type = 'error';
                    stateText = 'ended with error';
                }

                ElementPlus.ElNotification({
                    title,
                    message: `${jobName} ${stateText} on ${deviceName}`,
                    type,
                    duration: 5000,
                });

                this.scheduleBackgroundJobsRefresh?.(payload.client_id);
            });

            es.addEventListener('background_job_message', async (event) => {
                const payload = JSON.parse(event.data);
                this.scheduleBackgroundJobsRefresh?.(payload.client_id);
                // this.scheduleBackgroundJobsRefresh(payload.client_id);
            });

            es.addEventListener('background_job_file', async (event) => {
                const payload = JSON.parse(event.data);
                // this.scheduleBackgroundJobsRefresh(payload.client_id);
                this.scheduleBackgroundJobsRefresh?.(payload.client_id);

                await this.refreshArtifactsIfOpen?.();
            });

            es.addEventListener('pty_lifecycle', (event) => {
                const payload = JSON.parse(event.data || '{}');
                const state = String(payload.state || '').trim().toLowerCase();
                const deviceName = getConnectionLabel(payload.client_id);

                if (state === 'opened') {
                    ElementPlus.ElNotification({
                        title: 'PTY Started',
                        message: `PTY session started on ${deviceName}`,
                        type: 'success',
                        duration: 4000,
                    });
                    return;
                }

                if (state === 'closed') {
                    const exitCode = payload.exit_code === null || payload.exit_code === undefined
                        ? ''
                        : `, exit=${payload.exit_code}`;
                    ElementPlus.ElNotification({
                        title: 'PTY Stopped',
                        message: `PTY session stopped on ${deviceName}${exitCode}`,
                        type: 'warning',
                        duration: 4000,
                    });
                }
            });

            es.addEventListener('artifact_created', async (event) => {
                const payload = JSON.parse(event.data || '{}');
                const fileName = payload.original_name || payload.stored_name || 'file';

                if (!payload.artifact_id) return;

                if (payload.client_id) {
                    this.appendOutput(
                        payload.client_id,
                        `[File Ready] ${fileName}`,
                        'success',
                        {
                            artifactInfo: {
                                artifact_id: payload.artifact_id,
                                original_name: payload.original_name || '',
                                stored_name: payload.stored_name || '',
                                download_url: payload.download_url || '',
                                raw_url: payload.raw_url || '',
                                size: payload.size || 0,
                                hostname: payload.hostname || '',
                                category: payload.category || '',
                                source_type: payload.source_type || ''
                            }
                        }
                    );
                }

                if (!this.selectedId || payload.client_id === this.selectedId || !payload.client_id) {
                    ElementPlus.ElNotification({
                        title: 'File Ready',
                        dangerouslyUseHTMLString: true,
                        message: `
        <div>
          <div>${fileName} has been saved</div>
          <div style="margin-top:6px;">
            <a href="${payload.download_url || `/api/artifacts/${encodeURIComponent(payload.artifact_id)}/download`}" target="_blank" style="color:#409eff;text-decoration:none;">
              Download now
            </a>
          </div>
        </div>
    `,
                        type: 'success',
                        duration: 6000
                    });
                }

                await this.refreshArtifactsIfOpen?.();
            });


            es.onerror = () => {
                // EventSource reconnects automatically
            };
        },

        ensureTabId() {
            const key = 'rat_web_tab_id';
            let tabId = '';

            try {
                tabId = String(sessionStorage.getItem(key) || '').trim();
            } catch (e) {
                tabId = '';
            }

            if (!tabId) {
                if (window.crypto && typeof window.crypto.randomUUID === 'function') {
                    tabId = window.crypto.randomUUID();
                } else {
                    tabId = `tab_${Date.now()}_${Math.random().toString(16).slice(2)}`;
                }

                try {
                    sessionStorage.setItem(key, tabId);
                } catch (e) {
                }
            }

            this.tabId = tabId;
            return tabId;
        },

        getTabScopedHeaders(extra = {}) {
            const headers = {...extra};
            if (this.tabId) {
                headers['X-Tab-Id'] = this.tabId;
            }
            return headers;
        },
    }
};