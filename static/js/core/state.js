window.AppStateModule = {
    data() {
        return {
            connections: [],
            selectedId: '',
            outputs: {},
            commandText: '',
            commandCandidates: [],
            commandCandidatesLoadedFor: '',
            commandHistoryDialogVisible: false,
            commandHistoryLoading: false,
            commandHistoryItems: [],
            commandExecutionHistoryLoading: false,
            commandExecutionItems: [],
            commandHistoryActiveTab: 'quick',
            commandExecutionDetailDialogVisible: false,
            selectedCommandExecutionEntryId: '',
            sending: false,
            uploading: false,
            eventSource: null,
            sseReady: false,

            remoteFilesDialogVisible: false,
            remoteFilesLoading: false,
            remoteFilesCurrentPath: '',
            remoteFilesParentPath: '',
            remoteFilesEntries: [],
            remoteFilesPathInput: '',
            remoteUploadLoading: false,
            showHiddenFiles: false,
            remoteSelectedPaths: [],
            remoteZipDownloading: false,

            recentFilesDialogVisible: false,
            recentFilesLoading: false,
            recentFiles: [],

            previewDialogVisible: false,
            previewLoading: false,
            previewType: '',
            previewTitle: '',
            previewUrl: '',
            previewText: '',

            pendingRemoteUploadRefresh: null,

            backgroundJobsDialogVisible: false,
            backgroundJobsLoading: false,
            backgroundJobModulesLoading: false,
            backgroundJobModules: [],
            backgroundJobs: [],
            backgroundJobsRefreshTimer: null,
            backgroundJobDetailDialogVisible: false,
            selectedBackgroundJobId: '',
            backgroundJobsActiveTab: 'modules',
            backgroundJobMessageDialogVisible: false,
            selectedBackgroundJobMessage: {},

            connectionInfoDialogVisible: false,
            connectionInfoLoading: false,
            connectionInfoJobCount: 0,
        };
    },

    computed: {
        currentConnection() {
            return this.connections.find(item => item.client_id === this.selectedId) || null;
        },

        currentOutputLines() {
            return this.outputs[this.selectedId] || [];
        },

        filteredRemoteFilesEntries() {
            if (this.showHiddenFiles) return this.remoteFilesEntries;
            return this.remoteFilesEntries.filter(item => !item.is_hidden);
        },

        selectedRemoteEntries() {
            const selectedSet = new Set(this.remoteSelectedPaths);
            return this.remoteFilesEntries.filter(item => selectedSet.has(item.path));
        },

        hasRemoteSelection() {
            return this.remoteSelectedPaths.length > 0;
        },

        selectedBackgroundJob() {
            return this.backgroundJobs.find(item => item.job_id === this.selectedBackgroundJobId) || null;
        },

        sortedBackgroundJobs() {
            return [...this.backgroundJobs].sort((a, b) => {
                const ta = String(a.updated_at || a.started_at || a.created_at || '');
                const tb = String(b.updated_at || b.started_at || b.created_at || '');
                return tb.localeCompare(ta);
            });
        },

        selectedBackgroundJobMessagesDesc() {
            const messages = this.selectedBackgroundJob && Array.isArray(this.selectedBackgroundJob.messages)
                ? this.selectedBackgroundJob.messages
                : [];

            return [...messages].sort((a, b) => {
                const ta = String(a.time || '');
                const tb = String(b.time || '');
                return tb.localeCompare(ta);
            });
        },

        selectedCommandExecutionEntry() {
            return this.commandExecutionItems.find(item => item.entry_id === this.selectedCommandExecutionEntryId) || null;
        },

        selectedCommandExecutionOutputRecordsDesc() {
    const records = this.selectedCommandExecutionEntry && Array.isArray(this.selectedCommandExecutionEntry.output_records)
        ? this.selectedCommandExecutionEntry.output_records
        : [];

    return [...records].sort((a, b) => {
        return Number(b.seq || 0) - Number(a.seq || 0);
    });
},

        connectionInfoClientCommands() {
    return (this.commandCandidates || []).filter(item => item && item.source === 'client');
},
    },

    watch: {
        previewDialogVisible(val) {
            if (!val) this.resetPreviewState();
        },

        remoteFilesDialogVisible(val) {
            if (!val) this.resetRemoteFilesState();
        },

        backgroundJobsDialogVisible(val) {
            if (!val) {
                if (this.backgroundJobsRefreshTimer) {
                    clearTimeout(this.backgroundJobsRefreshTimer);
                    this.backgroundJobsRefreshTimer = null;
                }
            }
        },

        backgroundJobDetailDialogVisible(val) {
            if (!val) {
                this.selectedBackgroundJobId = '';
            }
        },

        backgroundJobMessageDialogVisible(val) {
            if (!val) {
                this.selectedBackgroundJobMessage = {};
            }
        },

        commandExecutionDetailDialogVisible(val) {
            if (!val) {
                this.selectedCommandExecutionEntryId = '';
            }
        },
    }
};