window.AppSseModule = {
    methods: {
        upsertConnection(conn) {
            const idx = this.connections.findIndex(item => item.client_id === conn.client_id);
            if (idx === -1) {
                this.connections.unshift(conn);
            } else {
                this.connections[idx] = conn;
            }

            if (!this.selectedId) this.selectedId = conn.client_id;
        },

        removeConnection(clientId) {
            this.connections = this.connections.filter(item => item.client_id !== clientId);
            if (this.selectedId === clientId) {
                this.selectedId = this.connections.length ? this.connections[0].client_id : '';
            }
        },

        initSSE() {
            if (this.eventSource) this.eventSource.close();

            const es = new EventSource('/api/stream');
            this.eventSource = es;

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
                const oldConn = this.connections.find(item => item.client_id === clientId);

                this.removeConnection(clientId);

                ElementPlus.ElNotification({
                    title: 'Device Offline',
                    message: `${(oldConn && oldConn.hostname) || clientId} went offline`,
                    type: 'warning'
                });
            });

            es.addEventListener('command_result', (event) => {
                const payload = JSON.parse(event.data);
                this.appendOutput(payload.client_id, payload.text || '');
            });

            es.addEventListener('command_complete', async (event) => {
                const payload = JSON.parse(event.data);

                this.appendOutput(
                    payload.client_id,
                    `[Command finished] ${payload.command} (${payload.success ? 'Success' : 'Failed'})`,
                    payload.success ? 'success' : 'error'
                );

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
                this.scheduleBackgroundJobsRefresh(payload.client_id);
            });

            es.addEventListener('background_job_message', async (event) => {
                const payload = JSON.parse(event.data);
                this.scheduleBackgroundJobsRefresh(payload.client_id);
            });

            es.addEventListener('background_job_file', async (event) => {
                const payload = JSON.parse(event.data);
                this.scheduleBackgroundJobsRefresh(payload.client_id);

                if (payload.client_id === this.selectedId) {
                    ElementPlus.ElNotification({
                        title: 'Background Job File',
                        message: `${payload.display_name || payload.job_name || 'job'} uploaded a file`,
                        type: 'success'
                    });
                }

                if(this.artifactDialogVisible) {
                    await this.loadArtifacts()
                }
            });

            es.addEventListener('file_received', async (event) => {
                const payload = JSON.parse(event.data);
                const fileName = payload.stored_name || payload.original_name || 'file';
                const downloadUrl = payload.download_url || (payload.artifact_id ? `/api/artifacts/${encodeURIComponent(payload.artifact_id)}/download` : '#');
                const sourceText = this.formatArtifactSourceLabel(payload);

                ElementPlus.ElNotification({
    title: 'File Received',
    dangerouslyUseHTMLString: true,
    message: `
        <div>
          <div>${payload.original_name || fileName} has been saved</div>
          <div style="margin-top:6px;">
            <a href="${downloadUrl}" target="_blank" style="color:#409eff;text-decoration:none;">
              Download now
            </a>
          </div>
        </div>
    `,
    type: 'success',
    duration: 6000
});

                if (this.artifactDialogVisible) {
                    await this.loadArtifacts();
                }
            });

            es.onerror = () => {
                // EventSource reconnects automatically
            };
        }
    }
};
