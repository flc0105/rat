window.AppStateModule = {
    data() {
        return {
            tabId: '',
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
            commandExecutionOutputSortOrder: 'desc',
            sending: false,
            activeTaskIds: {},
            cancellingTaskIds: {},
            eventSource: null,
            sseReady: false,
            statusNowTick: Date.now(),
            statusTickTimer: null,

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

            artifactDialogVisible: false,
            artifactLoading: false,
            artifactItems: [],
            artifactHostnames: [],
            artifactActiveTab: 'files',
            artifactHostnameFilter: '',
            artifactClearing: false,

            previewDialogVisible: false,
            previewLoading: false,
            previewType: '',
            previewTitle: '',
            previewUrl: '',
            previewText: '',

            previewEditMode: false,  // 新增：是否处于编辑模式
            previewSaving: false,    // 新增：保存中状态
            previewFilePath: '',     // 新增：当前编辑的文件路径
            previewOriginalContent: '',  // 原始内容副本（用于取消编辑时恢复）
            previewTruncated: false,     // 是否被截断
            previewFileSize: '',         // 文件大小显示
            previewFileEncoding: 'UTF-8', // 文件编码
            previewSource: '',  // 'remote_file' 或 'artifact'
            previewArtifactInfo: null,


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

                    quickJumpPaths: {},
        quickJumpLoading: false,

                        terminalJsonDialogVisible: false,
            terminalJsonDialogTitle: 'JSON Viewer',
            terminalJsonText: '',
        };
    },

    computed: {
        previewSourceLabel() {
            if (this.previewSource === 'remote_file') {
                return 'Remote File';
            }
            if (this.previewSource === 'artifact') {
                return 'Artifact';
            }
            if (this.previewSource === 'server_job') {
                return 'Server Job';
            }
            return 'Unknown';
        },
        currentConnection() {
            return this.connections.find(item => item.client_id === this.selectedId) || null;
        },

        currentOutputLines() {
            return this.outputs[this.selectedId] || [];
        },

        currentActiveTaskId() {
            return this.activeTaskIds[this.selectedId] || '';
        },

        currentTaskIsCancelling() {
            return !!this.cancellingTaskIds[this.selectedId];
        },

        hasRunningWebTask() {
            return !!this.currentActiveTaskId;
        },

        filteredRemoteFilesEntries() {
            if (this.showHiddenFiles) return this.remoteFilesEntries;
            return this.remoteFilesEntries.filter(item => !item.is_hidden);
        },

        displayRemoteFilesEntries() {
            const entries = Array.isArray(this.filteredRemoteFilesEntries)
                ? [...this.filteredRemoteFilesEntries]
                : [];

            if (this.remoteFilesParentPath) {
                entries.unshift({
                    name: '..',
                    path: this.remoteFilesParentPath,
                    is_dir: true,
                    is_symlink: false,
                    is_hidden: false,
                    size: 0,
                    modified_at: '',
                    is_parent_entry: true,
                });
            }

            return entries;
        },

        selectedRemoteEntries() {
            const selectedSet = new Set(this.remoteSelectedPaths);
            return this.remoteFilesEntries.filter(item => selectedSet.has(item.path));
        },

        hasRemoteSelection() {
            return this.remoteSelectedPaths.length > 0;
        },

        filteredArtifactItems() {
            const activeType = String(this.artifactActiveTab || '').trim();
            const hostname = String(this.artifactHostnameFilter || '').trim();

            return (this.artifactItems || []).filter(item => {
                if (activeType && item.artifact_type !== activeType) return false;
                if (hostname && item.hostname !== hostname) return false;
                return true;
            });
        },

        artifactCountMap() {
            const hostname = String(this.artifactHostnameFilter || '').trim();
            const counts = {
                files: 0,
                previews: 0,
            };

            (this.artifactItems || []).forEach(item => {
                if (!item) return;
                if (hostname && item.hostname !== hostname) return false;

                const type = String(item.artifact_type || '').trim();
                if (Object.prototype.hasOwnProperty.call(counts, type)) {
                    counts[type] += 1;
                }
            });

            return counts;
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

        connectionInfoClientCommands() {
            return (this.commandCandidates || []).filter(item => item && item.source === 'client');
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

                terminalJsonDialogVisible(val) {
            if (!val) {
                this.terminalJsonDialogTitle = 'JSON Viewer';
                this.terminalJsonText = '';
            }
        },
        previewDialogVisible(val) {
            if (!val) this.resetPreviewState();
        },

        remoteFilesDialogVisible(val) {
            if (!val) this.resetRemoteFilesState();
        },

        artifactDialogVisible(val) {
            if (!val) {
                this.artifactHostnameFilter = '';
            }
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
