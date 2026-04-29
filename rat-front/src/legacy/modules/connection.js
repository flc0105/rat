export default {
    data() {
        return {
            connections: [],
            selectedId: '',
        }
    },

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
    await this.reloadCommandCandidatesFromRuntime?.({
        reset: true,
        silent: true,
    });
}

                console.log(this.connections)
            } catch (e) {
                ElementPlus.ElMessage.error('Failed to load devices');
            }
        },

        selectConnection(clientId) {
            this.selectedId = clientId;
            this.ensureOutputBucket(clientId);
            this.commandHistoryItems = [];
            this.commandExecutionItems = [];
            this.reloadCommandCandidatesFromRuntime?.({
    reset: true,
    silent: true,
});
            this.scrollToBottom();

            // if (this.backgroundJobsDialogVisible) {
            //     this.loadBackgroundJobModules();
            //     this.loadBackgroundJobs();
            // }

            this.refreshBackgroundJobsIfOpen?.();


        },

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

        getConnectionDisplayState(conn) {
            const state = String(conn && conn.connection_state || '').trim();
            if (state === 'offline') return 'offline';

            if (conn && conn.is_transfer_active) {
                return 'online';
            }

            const disconnectedAt = String(conn && conn.disconnected_at || '').trim();
            if (disconnectedAt) return 'offline';

            const lastSeenAt = String(conn && conn.last_seen_at || '').trim();
            if (!lastSeenAt) return state || 'online';

            const staleAfterSeconds = Number(conn && conn.stale_after_seconds || 45);
            const seenMs = Date.parse(lastSeenAt);
            if (!Number.isFinite(seenMs)) return state || 'online';

            const ageMs = Math.max(this.statusNowTick - seenMs, 0);
            if (ageMs > staleAfterSeconds * 1000) return 'stale';

            return 'online';
        },

        // getConnectionStatusDotClass(conn) {
        //     const state = this.getConnectionDisplayState(conn);
        //     if (state === 'online') return 'device-dot-online';
        //     if (state === 'stale') return 'device-dot-stale';
        //     return 'device-dot-offline';
        // },
        //
        // getConnectionStatusText(conn) {
        //     const state = this.getConnectionDisplayState(conn);
        //     if (state === 'online') return 'online';
        //     if (state === 'stale') return 'stale';
        //     return 'offline';
        // },
        //
        // formatConnectionLastSeen(conn) {
        //     if (!conn) return '-';
        //
        //     const state = this.getConnectionDisplayState(conn);
        //     if (state === 'offline') {
        //         return this.formatDateTimeStandard(conn.disconnected_at) || '-';
        //     }
        //
        //     return this.formatDateTimeStandard(conn.last_seen_at) || '-';
        // },
        //
        // formatConnectionLastSeenRelative(conn) {
        //     if (!conn) return '-';
        //
        //     const state = this.getConnectionDisplayState(conn);
        //     const baseText = state === 'offline'
        //         ? String(conn.disconnected_at || '').trim()
        //         : String(conn.last_seen_at || '').trim();
        //
        //     if (!baseText) return '-';
        //
        //     const ts = Date.parse(baseText);
        //     if (!Number.isFinite(ts)) return '-';
        //
        //     const diffMs = Math.max(this.statusNowTick - ts, 0);
        //     const diffSec = Math.floor(diffMs / 1000);
        //
        //     if (diffSec < 5) return 'just now';
        //     if (diffSec < 60) return `${diffSec}s ago`;
        //
        //     const diffMin = Math.floor(diffSec / 60);
        //     if (diffMin < 60) return `${diffMin}m ago`;
        //
        //     const diffHour = Math.floor(diffMin / 60);
        //     if (diffHour < 24) return `${diffHour}h ago`;
        //
        //     const diffDay = Math.floor(diffHour / 24);
        //     return `${diffDay}d ago`;
        // },
        //
        // formatConnectionRtt(conn) {
        //     const value = conn && conn.last_rtt_ms;
        //     if (value === null || value === undefined || value === '') return '-';
        //     return `${value} ms`;
        // },
        //
        // formatOsLabel(osType, osVer) {
        //     const type = osType || 'Unknown';
        //     return osVer ? `${type}` : type;
        // },
        //
        // formatAddress(addr) {
        //     if (!addr) return '-';
        //     const raw = String(addr);
        //     const parts = raw.split(':');
        //     if (parts.length >= 2) return parts.slice(0, -1).join(':') || raw;
        //     return raw;
        // },
    },
    computed: {
        currentConnection() {
            return this.connections.find(item => item.client_id === this.selectedId) || null;
        },

        onlineConnectionsCount() {
            return (this.connections || []).filter(item => this.getConnectionDisplayState(item) === 'online').length;
        },
    }
}