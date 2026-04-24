export default {
    data() {
        return {
            commandHistoryDialogVisible: false,
            commandHistoryLoading: false,
            commandHistoryItems: [],
            commandHistoryPinningCommand: '',
            commandExecutionHistoryLoading: false,
            commandExecutionItems: [],
            commandExecutionDeletingEntryId: '',
            commandHistoryActiveTab: 'quick',
            commandHistorySearchText: '',
            commandExecutionDetailDialogVisible: false,
            selectedCommandExecutionEntryId: '',
            commandExecutionOutputSortOrder: 'desc',
        }
    },

    methods: {
        getSelectedHistoryMachineId() {
            return String(this.currentConnection?.machine_id || '').trim();
        },

        async openCommandHistoryDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            const machine_id = this.getSelectedHistoryMachineId();
            if (!machine_id) {
                ElementPlus.ElMessage.warning('Current device identity is unavailable');
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

            const machine_id = this.getSelectedHistoryMachineId();
            if (!machine_id) {
                this.commandHistoryItems = [];
                this.commandExecutionItems = [];
                if (!silent) {
                    ElementPlus.ElMessage.warning('Current device identity is unavailable');
                }
                return;
            }

            this.commandHistoryLoading = true;
            this.commandExecutionHistoryLoading = true;

            try {
                const [quickRes, fullRes] = await Promise.all([
                    fetch(`/api/machines/${encodeURIComponent(machine_id)}/command-history`),
                    fetch(`/api/machines/${encodeURIComponent(machine_id)}/command-history/full`)
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

                try {
                    await this.loadCommandCandidates(this.selectedId);
                } catch (_error) {
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
            const machine_id = this.getSelectedHistoryMachineId();
            if (!machine_id) {
                ElementPlus.ElMessage.warning('Current device identity is unavailable');
                return;
            }
            if (!row || !row.command) {
                return;
            }

            const commandText = String(row.command || '');
            this.commandHistoryPinningCommand = commandText;

            try {
                const res = await fetch(`/api/machines/${encodeURIComponent(machine_id)}/command-history/pin`, {
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
            const machine_id = this.getSelectedHistoryMachineId();
            if (!machine_id) {
                ElementPlus.ElMessage.warning('Current device identity is unavailable');
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
                const res = await fetch(`/api/machines/${encodeURIComponent(machine_id)}/command-history/pin/move`, {
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
            const machine_id = this.getSelectedHistoryMachineId();
            if (!machine_id) {
                ElementPlus.ElMessage.warning('Current device identity is unavailable');
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
                const res = await fetch(`/api/machines/${encodeURIComponent(machine_id)}/command-history/full/${encodeURIComponent(row.entry_id)}`, {
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

            const machine_id = this.getSelectedHistoryMachineId();
            if (!machine_id) {
                ElementPlus.ElMessage.warning('Current device identity is unavailable');
                return;
            }

            try {
                await ElementPlus.ElMessageBox.confirm(
                    'Clear command history for the current device?',
                    'Clear History',
                    {
                        type: 'warning',
                        confirmButtonText: 'Clear',
                        cancelButtonText: 'Cancel'
                    }
                );

                const res = await fetch(`/api/machines/${encodeURIComponent(machine_id)}/command-history`, {
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
                try {
                    await this.loadCommandCandidates(this.selectedId);
                } catch (_error) {
                }
                ElementPlus.ElMessage.success('Command history cleared');
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Failed to clear command history');
            }
        },

        buildCommandExecutionStatusTagType(status) {
            const value = String(status || '').toLowerCase();
            if (value === 'success') return 'success';
            if (value === 'error') return 'danger';
            if (value === 'running') return 'warning';
            return 'info';
        },

        formatCommandExecutionDuration(durationMs) {
            const ms = Number(durationMs || 0);
            if (!ms) return '0ms';

            if (ms < 1000) return `${ms}ms`;

            const totalSeconds = Math.floor(ms / 1000);
            const hours = Math.floor(totalSeconds / 3600);
            const minutes = Math.floor((totalSeconds % 3600) / 60);
            const seconds = totalSeconds % 60;

            const parts = [];
            if (hours) parts.push(`${hours}h`);
            if (minutes) parts.push(`${minutes}m`);
            if (seconds || !parts.length) parts.push(`${seconds}s`);
            return parts.join(' ');
        },

        buildCommandExecutionSummary(item) {
            const summary = String(item && item.output_summary || '').trim();
            if (summary) return summary;
            if (item && item.has_files) return `Produced ${item.file_count || 0} file(s)`;
            return 'No output';
        },

        formatCommandExecutionRecordText(text) {
            return String(text || '');
        },

        getCommandExecutionDisplayCwd(item) {
            if (!item) return '-';
            return item.cwd_end || item.cwd_start || '-';
        },

        buildCommandExecutionSingleLineSummary(item) {
            return this.buildCommandExecutionSummary(item);
        },

        getCommandExecutionFileStatusText(file) {
            if (!file) return '';
            return file.is_available ? '' : (file.status_text || 'File removed');
        },

        toggleCommandExecutionOutputSort() {
            this.commandExecutionOutputSortOrder = this.commandExecutionOutputSortOrder === 'asc' ? 'desc' : 'asc';
        },
    },

    computed: {
        normalizedCommandHistorySearchText() {
            return String(this.commandHistorySearchText || '').trim().toLowerCase();
        },

        filteredCommandHistoryItems() {
            const keyword = this.normalizedCommandHistorySearchText;
            const items = Array.isArray(this.commandHistoryItems) ? this.commandHistoryItems : [];
            if (!keyword) return items;
            return items.filter(item => String(item?.command || '').toLowerCase().includes(keyword));
        },

        filteredCommandExecutionItems() {
            const keyword = this.normalizedCommandHistorySearchText;
            const items = Array.isArray(this.commandExecutionItems) ? this.commandExecutionItems : [];
            if (!keyword) return items;
            return items.filter(item => String(item?.command || '').toLowerCase().includes(keyword));
        },

        commandHistorySearchSummary() {
            return {
                quickVisible: this.filteredCommandHistoryItems.length,
                quickTotal: Array.isArray(this.commandHistoryItems) ? this.commandHistoryItems.length : 0,
                fullVisible: this.filteredCommandExecutionItems.length,
                fullTotal: Array.isArray(this.commandExecutionItems) ? this.commandExecutionItems.length : 0,
            };
        },

        selectedCommandExecutionEntry() {
            return this.commandExecutionItems.find(item => item.entry_id === this.selectedCommandExecutionEntryId) || null;
        },

        selectedCommandExecutionOutputRecordsDesc() {
            const records = this.selectedCommandExecutionEntry && Array.isArray(this.selectedCommandExecutionEntry.output_records)
                ? this.selectedCommandExecutionEntry.output_records
                : [];

            const sorted = [...records].sort((a, b) => {
                return Number(b.seq || 0) - Number(a.seq || 0);
            });

            if (this.commandExecutionOutputSortOrder === 'asc') {
                sorted.reverse();
            }

            return sorted;
        },
    },

    watch: {
        commandExecutionDetailDialogVisible(val) {
            if (!val) {
                this.selectedCommandExecutionEntryId = '';
            }
        },

        commandHistoryDialogVisible(val) {
            if (!val) {
                this.commandHistorySearchText = '';
            }
        },
    },
}