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

                await this.loadCommandCandidates(this.selectedId);
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

                await this.reloadCommandHistoryDialogData({silent: true});
                ElementPlus.ElMessage.success(row.is_pinned ? 'Removed from pinned commands' : 'Pinned command updated');
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to update pinned command');
            } finally {
                this.commandHistoryPinningCommand = '';
            }
        },

        async moveCommandHistoryPinned(row, direction) {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            if (!row || !row.command || !row.is_pinned) {
                return;
            }

            const directionText = String(direction || '').trim().toLowerCase();
            if (!['up', 'down'].includes(directionText)) {
                return;
            }
            if (directionText === 'up' && !row.can_move_up) {
                return;
            }
            if (directionText === 'down' && !row.can_move_down) {
                return;
            }

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command-history/pin/move`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        command: String(row.command || ''),
                        direction: directionText,
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to move pinned command');
                }

                await this.reloadCommandHistoryDialogData({silent: true});
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to move pinned command');
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

                await this.reloadCommandHistoryDialogData({silent: true});
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