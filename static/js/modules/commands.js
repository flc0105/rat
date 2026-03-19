window.AppCommandsModule = {
    methods: {
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
                this.connections = json.data || [];

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
                {name: 'whoami', template: 'whoami', help: 'Show current user', source: 'common_ops'},
                {name: 'hostname', template: 'hostname', help: 'Show host name', source: 'common_ops'},
                {name: 'mkdir', template: 'mkdir ', help: 'Create a directory', source: 'common_ops'},
                {name: 'rmdir', template: 'rmdir ', help: 'Remove an empty directory', source: 'common_ops'},
            ];
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

                const pushUniqueCandidate = (item) => {
                    const template = String(item.template || '').trim();
                    if (!template || seen.has(template)) return;
                    seen.add(template);
                    merged.push(item);
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
                    merged.push({
                        name: 'history',
                        template: command,
                        help: 'Recent command',
                        source: 'history'
                    });
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
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command})
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Command failed');
                }

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
            } catch (e) {
                this.commandHistoryItems = [];
                this.commandExecutionItems = [];
                ElementPlus.ElMessage.error(e.message || 'Failed to load command history');
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
                this.commandCandidatesLoadedFor = '';
                await this.loadCommandCandidates(this.selectedId);
                ElementPlus.ElMessage.success('Command history cleared');
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Failed to clear command history');
            }
        }
    }
};