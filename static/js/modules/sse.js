window.AppSseModule = {
    methods: {
        upsertConnection(conn) {
            if (!conn || !conn.client_id) return;

            const identityKey = this.buildConnectionIdentityKey(conn);
            const incomingState = this.getConnectionDisplayState(conn);

            const duplicates = [];
            this.connections.forEach((item, index) => {
                if (!item) return;

                const sameClientId = item.client_id === conn.client_id;
                const sameIdentity = identityKey && this.buildConnectionIdentityKey(item) === identityKey;

                if (sameClientId || sameIdentity) {
                    duplicates.push({index, item});
                }
            });

            if (!duplicates.length) {
                this.connections.unshift(conn);
                this.connections = this.dedupeConnections(this.connections);
                return;
            }

            let best = duplicates[0];
            duplicates.forEach((entry) => {
                const currentState = this.getConnectionDisplayState(entry.item);
                const currentRank = currentState === 'online' ? 0 : (currentState === 'stale' ? 1 : 2);
                const bestState = this.getConnectionDisplayState(best.item);
                const bestRank = bestState === 'online' ? 0 : (bestState === 'stale' ? 1 : 2);

                if (currentRank < bestRank) {
                    best = entry;
                    return;
                }

                if (currentRank === bestRank) {
                    const currentTime = String(entry.item.last_seen_at || entry.item.connected_at || entry.item.disconnected_at || '');
                    const bestTime = String(best.item.last_seen_at || best.item.connected_at || best.item.disconnected_at || '');
                    if (currentTime > bestTime) {
                        best = entry;
                    }
                }
            });

            const merged = {
                ...best.item,
                ...conn
            };

            if (incomingState === 'online') {
                merged.disconnected_at = '';
            }

            this.connections.splice(best.index, 1, merged);

            const removeIndexes = duplicates
                .map(entry => entry.index)
                .filter(index => index !== best.index)
                .sort((a, b) => b - a);

            removeIndexes.forEach(index => {
                this.connections.splice(index, 1);
            });

            this.connections = this.dedupeConnections(this.connections);
        },

        removeConnection(clientId) {
            const idx = this.connections.findIndex(item => item.client_id === clientId);
            if (idx === -1) return;

            const oldItem = this.connections[idx];
            this.connections[idx] = {
                ...oldItem,
                connection_state: 'offline',
                disconnected_at: oldItem.disconnected_at || new Date().toISOString(),
                is_transfer_active: false,
            };

            this.connections = this.dedupeConnections(this.connections);
        },

        initSSE() {
            if (this.eventSource) this.eventSource.close();

            const tabId = this.ensureTabId();
            const streamUrl = `/api/stream?tab_id=${encodeURIComponent(tabId)}`;
            const es = new EventSource(streamUrl);
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
                const conn = payload.connection || this.connections.find(item => item.client_id === clientId) || {client_id: clientId};

                this.upsertConnection({
                    ...conn,
                    connection_state: 'offline',
                    disconnected_at: conn.disconnected_at || payload.time,
                    is_transfer_active: false,
                });

                ElementPlus.ElNotification({
                    title: 'Device Offline',
                    message: `${(conn && conn.hostname) || clientId} went offline`,
                    type: 'warning'
                });
            });

            es.addEventListener('connection_heartbeat', (event) => {
                const payload = JSON.parse(event.data);
                const conn = payload.connection;
                this.upsertConnection(conn);
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

                if (this.artifactDialogVisible) {
                    await this.loadArtifacts();
                }
            });

            es.addEventListener('artifact_created', async (event) => {
                const payload = JSON.parse(event.data || '{}');
                const fileName = payload.original_name || payload.stored_name || 'file';

                if (!payload.artifact_id) return;

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