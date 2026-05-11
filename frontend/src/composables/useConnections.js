import { listConnections } from '../api/connectionsApi.js';

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
    const grouped = new Map();
    const ordered = [];

    (Array.isArray(items) ? items : []).forEach((item) => {
        if (!item || !item.client_id) return;

        const key = item.client_id;
        const existing = grouped.get(key);

        if (!existing) {
            const copy = {...item};
            grouped.set(key, copy);
            ordered.push(copy);
            return;
        }

        const existingState = this.getConnectionDisplayState(existing);
        const currentState = this.getConnectionDisplayState(item);

        // 同一个 client_id 重复时，优先保留非 offline 状态，避免旧离线缓存覆盖在线连接。
        if (existingState === 'offline' && currentState !== 'offline') {
            Object.assign(existing, item, {disconnected_at: ''});
            return;
        }

        if (existingState !== 'offline' && currentState === 'offline') {
            return;
        }

        const existingTime = this.getConnectionActivityTimeMs(existing);
        const currentTime = this.getConnectionActivityTimeMs(item);

        if (currentTime >= existingTime) {
            Object.assign(existing, item);
        }
    });

    const activeItems = [];
    const offlineItems = [];

    ordered.forEach((item) => {
        if (this.getConnectionDisplayState(item) === 'offline') {
            offlineItems.push(item);
        } else {
            activeItems.push(item);
        }
    });

    // 在线 / stale 保持原顺序；离线组内部按最后活动时间排序。
    offlineItems.sort(this.compareConnectionActivityDesc);

    return activeItems.concat(offlineItems);
},

//         dedupeConnections(items) {
//     const grouped = new Map();
//     const ordered = [];
//
//     (Array.isArray(items) ? items : []).forEach((item) => {
//         if (!item || !item.client_id) return;
//
//         const key = item.client_id;
//         const existing = grouped.get(key);
//
//         if (!existing) {
//             const copy = {...item};
//             grouped.set(key, copy);
//             ordered.push(copy);
//             return;
//         }
//
//         const existingState = this.getConnectionDisplayState(existing);
//         const currentState = this.getConnectionDisplayState(item);
//
//         // 同一个 client_id 重复时，优先保留非 offline 状态，避免旧离线缓存覆盖在线连接。
//         if (existingState === 'offline' && currentState !== 'offline') {
//             Object.assign(existing, item, {disconnected_at: ''});
//             return;
//         }
//
//         if (existingState !== 'offline' && currentState === 'offline') {
//             return;
//         }
//
//         const existingTime = String(existing.last_seen_at || existing.connected_at || existing.disconnected_at || '');
//         const currentTime = String(item.last_seen_at || item.connected_at || item.disconnected_at || '');
//
//         if (currentTime >= existingTime) {
//             Object.assign(existing, item);
//         }
//     });
//
//     const activeItems = [];
//     const offlineItems = [];
//
//     ordered.forEach((item) => {
//         if (this.getConnectionDisplayState(item) === 'offline') {
//             offlineItems.push(item);
//         } else {
//             activeItems.push(item);
//         }
//     });
//
//     // 不再按 last_seen_at 排序：心跳只更新数据，不改变设备位置。
//     return activeItems.concat(offlineItems);
// },

        async loadConnections() {
    try {
        const fetchedConnections = await listConnections();

        const existingMap = new Map();
        (this.connections || []).forEach(item => {
            if (item && item.client_id) {
                existingMap.set(item.client_id, {...item});
            }
        });

        const fetchedMap = new Map();
        const frontItems = [];

        fetchedConnections.forEach(item => {
            if (!item || !item.client_id) return;

            const existing = existingMap.get(item.client_id);
            const existingState = this.getConnectionDisplayState(existing);
            const incomingState = this.getConnectionDisplayState(item);
            const merged = {
                ...existing,
                ...item,
            };

            if (incomingState !== 'offline') {
                merged.disconnected_at = '';
            }

            fetchedMap.set(item.client_id, merged);

            // 全新连接、或者离线设备重连，放到最前。
            if (!existing || (existingState === 'offline' && incomingState !== 'offline')) {
                frontItems.push(merged);
            }
        });

        // frontItems.sort((a, b) => {
        //     const ta = String(a.connected_at || a.last_seen_at || '');
        //     const tb = String(b.connected_at || b.last_seen_at || '');
        //     return tb.localeCompare(ta);
        // });

        frontItems.sort(this.compareConnectionActivityDesc);

        const nextItems = [];
        const usedIds = new Set();

        frontItems.forEach(item => {
            if (!item || !item.client_id || usedIds.has(item.client_id)) return;
            nextItems.push(item);
            usedIds.add(item.client_id);
        });

        // 已存在设备保持原位置，只更新内容。
        (this.connections || []).forEach(oldItem => {
            if (!oldItem || !oldItem.client_id || usedIds.has(oldItem.client_id)) return;

            const merged = fetchedMap.get(oldItem.client_id) || oldItem;
            nextItems.push(merged);
            usedIds.add(oldItem.client_id);
        });

        // API 返回但本地还没放进去的项补到后面，通常是 recent offline 缓存。
        fetchedConnections.forEach(item => {
            if (!item || !item.client_id || usedIds.has(item.client_id)) return;

            const merged = fetchedMap.get(item.client_id) || item;
            nextItems.push(merged);
            usedIds.add(item.client_id);
        });

        this.connections = this.dedupeConnections(nextItems);

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
    } catch (e) {
        ElementPlus.ElMessage.error('Failed to load devices');
    }
},


        upsertConnection(conn) {
    if (!conn || !conn.client_id) return;

    const identityKey = this.buildConnectionIdentityKey(conn);
    const incomingState = this.getConnectionDisplayState(conn);

    const duplicateIndexes = [];
    this.connections.forEach((item, index) => {
        if (!item) return;

        const sameClientId = item.client_id === conn.client_id;
        const sameIdentity = identityKey && this.buildConnectionIdentityKey(item) === identityKey;

        if (sameClientId || sameIdentity) {
            duplicateIndexes.push(index);
        }
    });

    if (!duplicateIndexes.length) {
        const nextItem = {...conn};

        if (incomingState === 'offline') {
            this.connections.push(nextItem);
        } else {
            this.connections.unshift(nextItem);
        }

        this.connections = this.dedupeConnections(this.connections);
        return;
    }

    const primaryIndex = duplicateIndexes[0];
    const oldItem = this.connections[primaryIndex];
    const oldState = this.getConnectionDisplayState(oldItem);

    const merged = {
        ...oldItem,
        ...conn,
    };

    if (incomingState !== 'offline') {
        merged.disconnected_at = '';
    }

    if (incomingState === 'offline' && !merged.disconnected_at) {
    merged.disconnected_at = new Date().toISOString();
}

    duplicateIndexes
        .slice()
        .sort((a, b) => b - a)
        .forEach(index => {
            this.connections.splice(index, 1);
        });

    if (incomingState === 'offline') {
        // 只有断连接才往后扔。
        this.connections.push(merged);
    } else if (oldState === 'offline') {
        // 离线设备重新上线，按新连接处理，放最前。
        this.connections.unshift(merged);
    } else {
        // 心跳 / 普通状态更新：保持原位置。
        const removedBefore = duplicateIndexes.filter(index => index < primaryIndex).length;
        const stableIndex = Math.max(primaryIndex - removedBefore, 0);
        this.connections.splice(stableIndex, 0, merged);
    }

    this.connections = this.dedupeConnections(this.connections);
},


        removeConnection(clientId) {
    const idx = this.connections.findIndex(item => item.client_id === clientId);
    if (idx === -1) return;

    const oldItem = this.connections[idx];
    const offlineItem = {
        ...oldItem,
        connection_state: 'offline',
        disconnected_at: oldItem.disconnected_at || new Date().toISOString(),
        is_transfer_active: false,
    };

    this.connections.splice(idx, 1);
    this.connections.push(offlineItem);
    this.connections = this.dedupeConnections(this.connections);
},


        getConnectionActivityTimeMs(item) {
    if (!item) return Number.NEGATIVE_INFINITY;

    const candidates = [
        item.disconnected_at,
        item.last_seen_at,
        item.connected_at,
    ];

    const validTimes = candidates
        .map(value => Date.parse(String(value || '').trim()))
        .filter(value => Number.isFinite(value));

    if (!validTimes.length) {
        return Number.NEGATIVE_INFINITY;
    }

    return Math.max(...validTimes);
},

compareConnectionActivityDesc(a, b) {
    const ta = this.getConnectionActivityTimeMs(a);
    const tb = this.getConnectionActivityTimeMs(b);

    if (ta !== tb) {
        return tb > ta ? 1 : -1;
    }

    const fa = String(a?.hostname || a?.machine_id || a?.client_id || '');
    const fb = String(b?.hostname || b?.machine_id || b?.client_id || '');
    return fa.localeCompare(fb);
},


        //
        // dedupeConnections(items) {
        //     const order = {online: 0, stale: 1, offline: 2};
        //     const grouped = new Map();
        //
        //     (Array.isArray(items) ? items : []).forEach((item) => {
        //         if (!item || !item.client_id) return;
        //
        //         const key = item.client_id;  // 直接用 clientId
        //         const existing = grouped.get(key);
        //
        //         if (!existing) {
        //             grouped.set(key, {...item});
        //             return;
        //         }
        //
        //         const existingState = this.getConnectionDisplayState(existing);
        //         const currentState = this.getConnectionDisplayState(item);
        //
        //         const existingOrder = Object.prototype.hasOwnProperty.call(order, existingState) ? order[existingState] : 9;
        //         const currentOrder = Object.prototype.hasOwnProperty.call(order, currentState) ? order[currentState] : 9;
        //
        //         if (currentOrder < existingOrder) {
        //             grouped.set(key, {...existing, ...item});
        //             return;
        //         }
        //
        //         if (currentOrder > existingOrder) {
        //             return;
        //         }
        //
        //         const existingTime = String(existing.last_seen_at || existing.connected_at || existing.disconnected_at || '');
        //         const currentTime = String(item.last_seen_at || item.connected_at || item.disconnected_at || '');
        //
        //         if (currentTime >= existingTime) {
        //             grouped.set(key, {...existing, ...item});
        //         }
        //     });
        //
        //     return Array.from(grouped.values()).sort((a, b) => {
        //         const sa = this.getConnectionDisplayState(a);
        //         const sb = this.getConnectionDisplayState(b);
        //
        //         const oa = Object.prototype.hasOwnProperty.call(order, sa) ? order[sa] : 9;
        //         const ob = Object.prototype.hasOwnProperty.call(order, sb) ? order[sb] : 9;
        //         if (oa !== ob) return oa - ob;
        //
        //         const ta = String(a.last_seen_at || a.connected_at || a.disconnected_at || '');
        //         const tb = String(b.last_seen_at || b.connected_at || b.disconnected_at || '');
        //         return tb.localeCompare(ta);
        //     });
        // },
        //
        // async loadConnections() {
        //     try {
        //         const res = await fetch('/api/connections');
        //         const json = await res.json();
        //         const activeConnections = Array.isArray(json.data) ? json.data : [];
        //
        //         const mergedMap = new Map();
        //         (this.connections || []).forEach(item => {
        //             if (item && item.client_id) {
        //                 mergedMap.set(item.client_id, {...item});
        //             }
        //         });
        //
        //         activeConnections.forEach(item => {
        //             mergedMap.set(item.client_id, {...mergedMap.get(item.client_id), ...item});
        //         });
        //
        //         const activeIds = new Set(activeConnections.map(item => item.client_id));
        //         mergedMap.forEach((item, key) => {
        //             if (!activeIds.has(key) && item.disconnected_at) {
        //                 item.connection_state = 'offline';
        //             }
        //         });
        //
        //         this.connections = this.dedupeConnections(Array.from(mergedMap.values()));
        //
        //         if (!this.selectedId && this.connections.length > 0) {
        //             this.selectedId = this.connections[0].client_id;
        //         }
        //
        //         if (this.selectedId && !this.connections.find(item => item.client_id === this.selectedId)) {
        //             this.selectedId = this.connections.length > 0 ? this.connections[0].client_id : '';
        //         }
        //
        //         if (this.selectedId) {
        //             await this.reloadCommandCandidatesFromRuntime?.({
        //                 reset: true,
        //                 silent: true,
        //             });
        //         }
        //
        //         console.log(this.connections)
        //     } catch (e) {
        //         ElementPlus.ElMessage.error('Failed to load devices');
        //     }
        // },

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
            this.refreshBackgroundJobsIfOpen?.();
        },

        // upsertConnection(conn) {
        //     if (!conn || !conn.client_id) return;
        //
        //     const identityKey = this.buildConnectionIdentityKey(conn);
        //     const incomingState = this.getConnectionDisplayState(conn);
        //
        //     const duplicates = [];
        //     this.connections.forEach((item, index) => {
        //         if (!item) return;
        //
        //         const sameClientId = item.client_id === conn.client_id;
        //         const sameIdentity = identityKey && this.buildConnectionIdentityKey(item) === identityKey;
        //
        //         if (sameClientId || sameIdentity) {
        //             duplicates.push({index, item});
        //         }
        //     });
        //
        //     if (!duplicates.length) {
        //         this.connections.unshift(conn);
        //         this.connections = this.dedupeConnections(this.connections);
        //         return;
        //     }
        //
        //     let best = duplicates[0];
        //     duplicates.forEach((entry) => {
        //         const currentState = this.getConnectionDisplayState(entry.item);
        //         const currentRank = currentState === 'online' ? 0 : (currentState === 'stale' ? 1 : 2);
        //         const bestState = this.getConnectionDisplayState(best.item);
        //         const bestRank = bestState === 'online' ? 0 : (bestState === 'stale' ? 1 : 2);
        //
        //         if (currentRank < bestRank) {
        //             best = entry;
        //             return;
        //         }
        //
        //         if (currentRank === bestRank) {
        //             const currentTime = String(entry.item.last_seen_at || entry.item.connected_at || entry.item.disconnected_at || '');
        //             const bestTime = String(best.item.last_seen_at || best.item.connected_at || best.item.disconnected_at || '');
        //             if (currentTime > bestTime) {
        //                 best = entry;
        //             }
        //         }
        //     });
        //
        //     const merged = {
        //         ...best.item,
        //         ...conn
        //     };
        //
        //     if (incomingState === 'online') {
        //         merged.disconnected_at = '';
        //     }
        //
        //     this.connections.splice(best.index, 1, merged);
        //
        //     const removeIndexes = duplicates
        //         .map(entry => entry.index)
        //         .filter(index => index !== best.index)
        //         .sort((a, b) => b - a);
        //
        //     removeIndexes.forEach(index => {
        //         this.connections.splice(index, 1);
        //     });
        //
        //     this.connections = this.dedupeConnections(this.connections);
        // },
        //
        // removeConnection(clientId) {
        //     const idx = this.connections.findIndex(item => item.client_id === clientId);
        //     if (idx === -1) return;
        //
        //     const oldItem = this.connections[idx];
        //     this.connections[idx] = {
        //         ...oldItem,
        //         connection_state: 'offline',
        //         disconnected_at: oldItem.disconnected_at || new Date().toISOString(),
        //         is_transfer_active: false,
        //     };
        //
        //     this.connections = this.dedupeConnections(this.connections);
        // },

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