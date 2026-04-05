window.AppConnectionModule = {
    methods: {
        buildConnectionIdentityKey(item) {
            if (!item) return '';
            // 直接返回 clientId 作为唯一标识
            return item.client_id;
        },

        dedupeConnections(items) {
            const order = {online: 0, stale: 1, offline: 2};
            const grouped = new Map();

            (Array.isArray(items) ? items : []).forEach((item) => {
                if (!item || !item.client_id) return;

                const key = item.client_id;  // 直接用 clientId
                const existing = grouped.get(key);

                if (!existing) {
                    grouped.set(key, {...item});
                    return;
                }

                const existingState = this.getConnectionDisplayState(existing);
                const currentState = this.getConnectionDisplayState(item);

                const existingOrder = Object.prototype.hasOwnProperty.call(order, existingState) ? order[existingState] : 9;
                const currentOrder = Object.prototype.hasOwnProperty.call(order, currentState) ? order[currentState] : 9;

                if (currentOrder < existingOrder) {
                    grouped.set(key, {...existing, ...item});
                    return;
                }

                if (currentOrder > existingOrder) {
                    return;
                }

                const existingTime = String(existing.last_seen_at || existing.connected_at || existing.disconnected_at || '');
                const currentTime = String(item.last_seen_at || item.connected_at || item.disconnected_at || '');

                if (currentTime >= existingTime) {
                    grouped.set(key, {...existing, ...item});
                }
            });

            return Array.from(grouped.values()).sort((a, b) => {
                const sa = this.getConnectionDisplayState(a);
                const sb = this.getConnectionDisplayState(b);

                const oa = Object.prototype.hasOwnProperty.call(order, sa) ? order[sa] : 9;
                const ob = Object.prototype.hasOwnProperty.call(order, sb) ? order[sb] : 9;
                if (oa !== ob) return oa - ob;

                const ta = String(a.last_seen_at || a.connected_at || a.disconnected_at || '');
                const tb = String(b.last_seen_at || b.connected_at || b.disconnected_at || '');
                return tb.localeCompare(ta);
            });
        },

        async loadConnections() {
            try {
                const res = await fetch('/api/connections');
                const json = await res.json();
                const activeConnections = Array.isArray(json.data) ? json.data : [];

                const mergedMap = new Map();
                (this.connections || []).forEach(item => {
                    if (item && item.client_id) {
                        mergedMap.set(item.client_id, {...item});
                    }
                });

                activeConnections.forEach(item => {
                    mergedMap.set(item.client_id, {...mergedMap.get(item.client_id), ...item});
                });

                const activeIds = new Set(activeConnections.map(item => item.client_id));
                mergedMap.forEach((item, key) => {
                    if (!activeIds.has(key) && item.disconnected_at) {
                        item.connection_state = 'offline';
                    }
                });

                this.connections = this.dedupeConnections(Array.from(mergedMap.values()));

                if (!this.selectedId && this.connections.length > 0) {
                    this.selectedId = this.connections[0].client_id;
                }

                if (this.selectedId && !this.connections.find(item => item.client_id === this.selectedId)) {
                    this.selectedId = this.connections.length > 0 ? this.connections[0].client_id : '';
                }

                if (this.selectedId) {
                    await this.loadCommandCandidates(this.selectedId);
                }
            } catch (e) {
                ElementPlus.ElMessage.error('Failed to load devices');
            }
        },

        selectConnection(clientId) {
            this.selectedId = clientId;
            this.ensureOutputBucket(clientId);
            this.commandHistoryItems = [];
            this.commandExecutionItems = [];
            this.loadCommandCandidates(clientId);
            this.scrollToBottom();

            if (this.backgroundJobsDialogVisible) {
                this.loadBackgroundJobModules();
                this.loadBackgroundJobs();
            }
        },

        async openConnectionInfoDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            this.connectionInfoDialogVisible = true;
            this.connectionInfoLoading = true;
            this.connectionInfoJobCount = 0;

            try {
                if (this.commandCandidatesLoadedFor !== this.selectedId || !this.commandCandidates.length) {
                    await this.loadCommandCandidates(this.selectedId);
                }

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/background-jobs`);
                const json = await res.json();

                if (res.ok && json.code === 0 && Array.isArray(json.data)) {
                    this.connectionInfoJobCount = json.data.length;
                }
            } catch (e) {
            } finally {
                this.connectionInfoLoading = false;
            }
        },
    }
}