
window.AppCommandsModule = {
    methods: {
        // static/js/modules/commands.js
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
        // buildConnectionIdentityKey(item) {
        //     if (!item) return '';
        //     const hostname = String(item.hostname || '').trim().toLowerCase();
        //     const addr = String(this.formatAddress(item.addr) || '').trim().toLowerCase();
        //     const osType = String(item.os_type || '').trim().toLowerCase();
        //     return `${hostname}__${addr}__${osType}`;
        // },
        //
        // dedupeConnections(items) {
        //     const order = {online: 0, stale: 1, offline: 2};
        //     const grouped = new Map();
        //
        //     (Array.isArray(items) ? items : []).forEach((item) => {
        //         if (!item || !item.client_id) return;
        //
        //         const key = this.buildConnectionIdentityKey(item) || item.client_id;
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


        isFileReadyLine(line) {
            const text = (line?.text || '')
            return text.startsWith('[File Ready]')
        },

        isCommandFinishedLine(line) {
            const text = (line?.text || '')
            return text.startsWith('[Command finished]') || text.startsWith('[命令结束]')
        },

        getTerminalInlineActionItems(lines, index) {
            const line = lines[index]
            if (!line) return []

            if (!this.isFileReadyLine(line)) return []

            const groupItems = this.getTerminalCommandGroupActionItems(lines, index) || []
            const usedKeysBefore = this.getUsedInlineActionKeysBeforeLine(lines, index)

            const previewItem = groupItems.find(item => {
                return item.type === 'preview' && !usedKeysBefore.has(item.key)
            })

            return previewItem ? [previewItem] : []
        },

        getTerminalTailActionItems(lines, index) {
            const line = lines[index]
            if (!line || !this.isCommandFinishedLine(line)) return []

            const groupItems = this.getTerminalCommandGroupActionItems(lines, index) || []
            const usedKeysUpToCurrent = this.getUsedInlineActionKeysUpToLine(lines, index)

            return groupItems.filter(item => !usedKeysUpToCurrent.has(item.key))
        },

        getUsedInlineActionKeysBeforeLine(lines, endIndexExclusive) {
            const used = new Set()

            for (let i = 0; i < endIndexExclusive; i += 1) {
                const line = lines[i]
                if (!this.isFileReadyLine(line)) continue

                const groupItems = this.getTerminalCommandGroupActionItems(lines, i) || []
                const previewItem = groupItems.find(item => item.type === 'preview' && !used.has(item.key))

                if (previewItem) {
                    used.add(previewItem.key)
                }
            }

            return used
        },

        getUsedInlineActionKeysUpToLine(lines, endIndexInclusive) {
            const used = new Set()

            for (let i = 0; i <= endIndexInclusive; i += 1) {
                const line = lines[i]
                if (!this.isFileReadyLine(line)) continue

                const groupItems = this.getTerminalCommandGroupActionItems(lines, i) || []
                const previewItem = groupItems.find(item => item.type === 'preview' && !used.has(item.key))

                if (previewItem) {
                    used.add(previewItem.key)
                }
            }

            return used
        },


        setActiveTask(clientId, taskId) {
            if (!clientId) return;

            this.activeTaskIds = {
                ...this.activeTaskIds,
                [clientId]: taskId || ''
            };

            this.cancellingTaskIds = {
                ...this.cancellingTaskIds,
                [clientId]: false
            };
        },

        clearActiveTask(clientId, taskId = '') {
            if (!clientId) return;

            const currentTaskId = this.activeTaskIds[clientId] || '';
            if (taskId && currentTaskId && currentTaskId !== taskId) {
                return;
            }

            const nextActive = {...this.activeTaskIds};
            delete nextActive[clientId];
            this.activeTaskIds = nextActive;

            const nextCancelling = {...this.cancellingTaskIds};
            delete nextCancelling[clientId];
            this.cancellingTaskIds = nextCancelling;
        },

        markTaskCancelling(clientId, taskId = '') {
            if (!clientId) return;

            if (taskId) {
                const currentTaskId = this.activeTaskIds[clientId] || '';
                if (currentTaskId && currentTaskId !== taskId) {
                    return;
                }
            }

            this.cancellingTaskIds = {
                ...this.cancellingTaskIds,
                [clientId]: true
            };
        },

        async cancelCurrentTask() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            const taskId = this.currentActiveTaskId;
            if (!taskId) {
                ElementPlus.ElMessage.warning('No running task');
                return;
            }

            try {
                this.markTaskCancelling(this.selectedId, taskId);

                const res = await fetch(`/api/tasks/${encodeURIComponent(taskId)}/cancel`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Cancel failed');
                }

                this.appendOutput(this.selectedId, `[Cancel requested] task=${taskId}`, 'info');
                ElementPlus.ElMessage.success('Cancel request sent');
            } catch (e) {
                this.cancellingTaskIds = {
                    ...this.cancellingTaskIds,
                    [this.selectedId]: false
                };
                ElementPlus.ElMessage.error(e.message || 'Cancel failed');
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

buildCommonOpsCandidates() {
    return [
        {name: 'whoami', template: 'whoami', help: 'Show current user', source: 'common_ops', group: 'common_ops'},
        {name: 'hostname', template: 'hostname', help: 'Show host name', source: 'common_ops', group: 'common_ops'},
        {name: 'mkdir', template: 'mkdir ', help: 'Create a directory', source: 'common_ops', group: 'common_ops'},
        {name: 'rmdir', template: 'rmdir ', help: 'Remove an empty directory', source: 'common_ops', group: 'common_ops'},
    ];
},

        queryCommandCandidates(queryString, callback) {
    const keyword = String(queryString || '').trim().toLowerCase();
    const sourceList = Array.isArray(this.commandCandidates) ? this.commandCandidates : [];

    if (!keyword) {
        callback(sourceList);
        return;
    }

    const result = sourceList.filter(item => {
        const searchText = String(item.searchText || '').toLowerCase();
        return searchText.includes(keyword);
    });

    callback(result);
},

handleCommandCandidateSelect(item) {
    if (!item) return;
    this.commandText = String(item.template || item.value || '');
},

        async loadCommandCandidates(clientId) {
    if (!clientId) return;

    try {
        const [candidateRes, historyRes] = await Promise.all([
            fetch(`/api/connections/${encodeURIComponent(clientId)}/command-candidates`),
            fetch(`/api/connections/${encodeURIComponent(clientId)}/command-history`)
        ]);

        const candidateJson = await candidateRes.json();
        const historyJson = await historyRes.json();

        if (!candidateRes.ok || candidateJson.code !== 0) {
            throw new Error(candidateJson.message || 'Failed to load command candidates');
        }

        if (!historyRes.ok || historyJson.code !== 0) {
            throw new Error(historyJson.message || 'Failed to load command history');
        }

        const systemCandidates = Array.isArray(candidateJson.data) ? candidateJson.data : [];
        const historyItems = Array.isArray(historyJson.data) ? historyJson.data : [];

        const merged = [];
        const seen = new Set();

        const buildCandidateGroupLabel = (item) => {
            const groupText = String(item.group || item.source || '').trim();
            if (!groupText) return '';
            return groupText;
        };

        const normalizeCandidateItem = (item) => {
            const template = String(item.template || '').trim();
            const name = String(item.name || template || '').trim();
            const help = String(item.help || '').trim();
            const group = String(item.group || '').trim();
            const source = String(item.source || '').trim();

            return {
                ...item,
                value: template,
                name,
                template,
                help,
                group,
                source,
                groupLabel: buildCandidateGroupLabel(item),
                searchText: [
                    template,
                    name,
                    help,
                    group,
                    source,
                    buildCandidateGroupLabel(item)
                ]
                    .filter(Boolean)
                    .join(' ')
                    .toLowerCase()
            };
        };

        const pushUniqueCandidate = (item) => {
            const normalized = normalizeCandidateItem(item);
            const template = normalized.template;

            if (!template || seen.has(template)) return;
            seen.add(template);
            merged.push(normalized);
        };

        const visibleSystemCandidates = systemCandidates.filter(item => item.suggest !== false);

        const clientCandidates = visibleSystemCandidates.filter(
            item => item.source === 'client' && item.group !== 'acmd'
        );
        const acmdCandidates = visibleSystemCandidates.filter(
            item => item.source === 'client' && item.group === 'acmd'
        );
        const serverCandidates = visibleSystemCandidates.filter(item => item.source === 'server');
        const aliasCandidates = visibleSystemCandidates.filter(item => item.source === 'alias');
        const scriptCandidates = visibleSystemCandidates.filter(item => item.source === 'script');
        const commonOpsCandidates = this.buildCommonOpsCandidates();

        clientCandidates.forEach(pushUniqueCandidate);
        acmdCandidates.forEach(pushUniqueCandidate);
        serverCandidates.forEach(pushUniqueCandidate);
        commonOpsCandidates.forEach(pushUniqueCandidate);
        aliasCandidates.forEach(pushUniqueCandidate);
        scriptCandidates.forEach(pushUniqueCandidate);

        historyItems.forEach((item) => {
            const command = String(item.command || '').trim();
            if (!command || seen.has(command)) return;
            seen.add(command);
            merged.push(normalizeCandidateItem({
                name: command,
                template: command,
                help: 'Recent command',
                source: 'history',
                group: 'history'
            }));
        });

        this.commandCandidates = merged;
        this.commandCandidatesLoadedFor = clientId;
    } catch (e) {
        this.commandCandidates = [];
        this.commandCandidatesLoadedFor = '';
    }
},

        async sendCommand() {
            const command = (this.commandText || '').trim();

            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            if (!command) {
                ElementPlus.ElMessage.warning('Please enter a command');
                return;
            }

            this.sending = true;
            this.appendOutput(this.selectedId, '> ' + command, 'command');

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command`, {
                    method: 'POST',
                    headers: this.getTabScopedHeaders({'Content-Type': 'application/json'}),
                    body: JSON.stringify({command})
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Command failed');
                }

                const taskId = json.data && json.data.task_id;
                this.setActiveTask(this.selectedId, taskId || '');

                this.commandText = '';
                this.commandCandidatesLoadedFor = '';
                await this.loadCommandCandidates(this.selectedId);
            } catch (e) {
                this.appendOutput(this.selectedId, '[发送失败] ' + (e.message || 'unknown error'), 'error');
                ElementPlus.ElMessage.error(e.message || 'Command failed');
            } finally {
                this.sending = false;
            }
        },

        async killConnection() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/kill`, {
                    method: 'POST'
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Disconnect failed');
                }

                ElementPlus.ElMessage.success('Disconnect command sent');
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Disconnect failed');
            }
        },

        async openCommandHistoryDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            this.commandHistoryDialogVisible = true;
            await this.reloadCommandHistoryDialogData();
        },

        clearCommandHistorySearch() {
            this.commandHistorySearchText = '';
        },

        async reloadCommandHistoryDialogData(options = {}) {
            const silent = !!options.silent;

            if (!this.selectedId) {
                if (!silent) {
                    ElementPlus.ElMessage.warning('Please select a device');
                }
                return;
            }

            this.commandHistoryLoading = true;
            this.commandExecutionHistoryLoading = true;

            try {
                const [quickRes, fullRes] = await Promise.all([
                    fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command-history`),
                    fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command-history/full`)
                ]);

                const quickJson = await quickRes.json();
                const fullJson = await fullRes.json();

                if (!quickRes.ok || quickJson.code !== 0) {
                    throw new Error(quickJson.message || 'Failed to load command history');
                }

                if (!fullRes.ok || fullJson.code !== 0) {
                    throw new Error(fullJson.message || 'Failed to load full command history');
                }

                this.commandHistoryItems = Array.isArray(quickJson.data) ? quickJson.data : [];
                this.commandExecutionItems = Array.isArray(fullJson.data) ? fullJson.data : [];

                if (
                    this.selectedCommandExecutionEntryId
                    && !this.commandExecutionItems.some(item => item.entry_id === this.selectedCommandExecutionEntryId)
                ) {
                    this.commandExecutionDetailDialogVisible = false;
                    this.selectedCommandExecutionEntryId = '';
                }
            } catch (e) {
                this.commandHistoryItems = [];
                this.commandExecutionItems = [];
                if (!silent) {
                    ElementPlus.ElMessage.error(e.message || 'Failed to load command history');
                }
            } finally {
                this.commandHistoryLoading = false;
                this.commandExecutionHistoryLoading = false;
            }
        },

        applyHistoryCommand(row) {
            if (!row || !row.command) return;
            this.commandText = row.command;
            this.commandHistoryDialogVisible = false;

            Vue.nextTick(() => {
                const input = this.$refs.commandInputRef;
                if (input && typeof input.focus === 'function') {
                    input.focus();
                }
            });
        },

        openCommandExecutionDetail(row) {
            if (!row || !row.entry_id) return;
            this.selectedCommandExecutionEntryId = row.entry_id;
            this.commandExecutionDetailDialogVisible = true;
        },

        async toggleCommandHistoryPinned(row) {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            if (!row || !row.command) {
                return;
            }

            const commandText = String(row.command || '');
            this.commandHistoryPinningCommand = commandText;

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command-history/pin`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        command: commandText,
                        is_pinned: !row.is_pinned,
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to update pinned command');
                }

                await this.reloadCommandHistoryDialogData({ silent: true });
                ElementPlus.ElMessage.success(row.is_pinned ? 'Removed from pinned commands' : 'Pinned command updated');
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to update pinned command');
            } finally {
                this.commandHistoryPinningCommand = '';
            }
        },

        async deleteCommandExecutionItem(row) {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            if (!row || !row.entry_id) {
                return;
            }

            try {
                await ElementPlus.ElMessageBox.confirm(
                    'Delete this execution history entry?',
                    'Delete Entry',
                    {
                        type: 'warning',
                        confirmButtonText: 'Delete',
                        cancelButtonText: 'Cancel'
                    }
                );

                this.commandExecutionDeletingEntryId = row.entry_id;
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command-history/full/${encodeURIComponent(row.entry_id)}`, {
                    method: 'DELETE'
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to delete execution history entry');
                }

                await this.reloadCommandHistoryDialogData({ silent: true });
                ElementPlus.ElMessage.success('Execution history entry deleted');
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Failed to delete execution history entry');
            } finally {
                this.commandExecutionDeletingEntryId = '';
            }
        },

        async clearCommandHistory() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            try {
                await ElementPlus.ElMessageBox.confirm(
                    'Clear command history for the current host?',
                    'Clear History',
                    {
                        type: 'warning',
                        confirmButtonText: 'Clear',
                        cancelButtonText: 'Cancel'
                    }
                );

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command-history`, {
                    method: 'DELETE'
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to clear command history');
                }

                this.commandHistoryItems = [];
                this.commandExecutionItems = [];
                this.commandHistorySearchText = '';
                this.commandCandidatesLoadedFor = '';
                this.commandExecutionDetailDialogVisible = false;
                this.selectedCommandExecutionEntryId = '';
                await this.loadCommandCandidates(this.selectedId);
                ElementPlus.ElMessage.success('Command history cleared');
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Failed to clear command history');
            }
        }
    }
};









