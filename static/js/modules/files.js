window.AppFilesModule = {
    data() {
        return {
            remoteFilesDialogVisible: false,
            remoteFilesLoading: false,
            remoteFilesCurrentPath: '',
            remoteFilesParentPath: '',
            remoteFilesEntries: [],
            remoteFilesPathInput: '',
            remoteFilesPage: 1,
            remoteFilesPageSize: 50,
            remoteFilesPageSizeOptions: [50, 100, 200],
            remoteFilesTotal: 0,
            remoteFilesTotalPages: 1,
            remoteFilesAllTotal: 0,
            remoteFilesHiddenTotal: 0,
            remoteUploadLoading: false,
            pendingRemoteUploadRefresh: null,
            showHiddenFiles: false,
            remoteSelectedPaths: [],
            remoteZipDownloading: false,
            quickJumpPaths: {},
            quickJumpLoading: false,
            remotePinnedJumpItems: [],
            remotePinnedJumpLoading: false,
            remotePinManagerDialogVisible: false,
            remoteClipboardPaths: [],
            remoteClipboardMode: '',
            remoteClipboardSourcePath: '',
        }
    },


    methods: {
        triggerRemoteUpload() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            if (!this.remoteFilesCurrentPath) {
                ElementPlus.ElMessage.warning('Current directory is empty');
                return;
            }

            const input = this.$refs.remoteUploadInputRef;
            if (input) {
                input.value = '';
                input.click();
            }
        },

        async handleRemoteUploadChange(event) {
            const file = event.target.files && event.target.files[0];
            if (!file) return;

            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            if (!this.remoteFilesCurrentPath) {
                ElementPlus.ElMessage.warning('Current directory is empty');
                return;
            }

            const formData = new FormData();
            formData.append('file', file);
            formData.append('target_path', this.remoteFilesCurrentPath);

            this.remoteUploadLoading = true;
            this.appendOutput(
                this.selectedId,
                `> [Remote Upload] ${file.name} -> ${this.remoteFilesCurrentPath}`,
                'command'
            );

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/upload`, {
                    method: 'POST',
                    headers: this.getTabScopedHeaders(),
                    body: formData
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Upload failed');
                }

                const taskId = json.data && json.data.task_id;
                this.setActiveTask(this.selectedId, taskId || '');

                this.pendingRemoteUploadRefresh = {
                    taskId: taskId || '',
                    clientId: this.selectedId,
                    path: this.remoteFilesCurrentPath || ''
                };

                ElementPlus.ElMessage.success(`Upload started: ${file.name}`);
            } catch (e) {
                this.appendOutput(this.selectedId, `[上传失败] ${e.message || 'unknown error'}`, 'error');
                ElementPlus.ElMessage.error(e.message || 'Upload failed');
            } finally {
                this.remoteUploadLoading = false;
            }
        },

        async openRemoteFilesDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            this.remoteFilesDialogVisible = true;
            this.loadQuickJumpPaths();  // 加载快速跳转路径
            this.loadPinnedQuickJumps();
            await this.loadRemoteDirectory('', 1);
        },

        async loadRemoteDirectory(path = '', page = 1) {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            this.remoteFilesLoading = true;

            try {
                const url = new URL(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files`, window.location.origin);
                if (path) url.searchParams.set('path', path);
                url.searchParams.set('page', String(page || 1));
                url.searchParams.set('page_size', String(this.remoteFilesPageSize || 50));
                url.searchParams.set('show_hidden', this.showHiddenFiles ? 'true' : 'false');

                const res = await fetch(url.pathname + url.search);
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load remote directory');
                }

                const data = json.data || {};
                const pagination = data.pagination || {};
                const summary = data.summary || {};

                this.remoteFilesCurrentPath = data.current_path || '';
                this.remoteFilesParentPath = data.parent_path || '';
                this.remoteFilesEntries = data.entries || [];
                this.remoteFilesPathInput = this.remoteFilesCurrentPath || '';
                this.remoteFilesPage = Number(pagination.page || page || 1);
                this.remoteFilesPageSize = Number(pagination.page_size || this.remoteFilesPageSize || 50);
                this.remoteFilesTotal = Number(pagination.total_visible || 0);
                this.remoteFilesTotalPages = Number(pagination.total_pages || 1);
                this.remoteFilesAllTotal = Number(summary.total_all || this.remoteFilesTotal || 0);
                this.remoteFilesHiddenTotal = Number(summary.total_hidden || 0);
                this.showHiddenFiles = !!summary.show_hidden;
                this.remoteSelectedPaths = [];
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to load remote directory');
            } finally {
                this.remoteFilesLoading = false;
            }
        },

        async refreshRemoteDirectory() {
            await this.loadRemoteDirectory(this.remoteFilesCurrentPath || '', this.remoteFilesPage || 1);
        },

        async goToRemoteParent() {
            if (!this.remoteFilesParentPath) return;
            await this.loadRemoteDirectory(this.remoteFilesParentPath, 1);
        },

        async goToRemotePathInput() {
            const path = (this.remoteFilesPathInput || '').trim();
            if (!path) {
                ElementPlus.ElMessage.warning('Please enter a path');
                return;
            }
            await this.loadRemoteDirectory(path, 1);
        },

        async enterRemoteDirectory(row) {
            if (!row || !row.is_dir) return;

            if (row.is_parent_entry) {
                await this.goToRemoteParent();
                return;
            }

            await this.loadRemoteDirectory(row.path, 1);
        },

        async handleRemotePageChange(page) {
            await this.loadRemoteDirectory(this.remoteFilesCurrentPath || '', page || 1);
        },

        async handleRemotePageSizeChange(pageSize) {
            this.remoteFilesPageSize = Number(pageSize || 50);
            await this.loadRemoteDirectory(this.remoteFilesCurrentPath || '', 1);
        },

        async toggleRemoteHiddenFiles() {
            this.showHiddenFiles = !this.showHiddenFiles;
            await this.loadRemoteDirectory(this.remoteFilesCurrentPath || '', 1);
        },

        handleRemoteRowDblClick(row) {
            if (!row) return;

            if (row.is_parent_entry) {
                this.goToRemoteParent();
                return;
            }

            if (row.is_dir) {
                this.enterRemoteDirectory(row);
            }
        },

        handleRemoteSelectionChange(rows) {
            this.remoteSelectedPaths = Array.isArray(rows)
                ? rows
                    .filter(item => item && !item.is_parent_entry)
                    .map(item => item.path)
                    .filter(Boolean)
                : [];
        },

        isRemoteEntrySelected(row) {
            if (!row || row.is_parent_entry) return false;
            return !!(row.path && this.remoteSelectedPaths.includes(row.path));
        },

        toggleRemoteSelection(row) {
            if (!row || !row.path || row.is_parent_entry) return;

            const exists = this.remoteSelectedPaths.includes(row.path);
            if (exists) {
                this.remoteSelectedPaths = this.remoteSelectedPaths.filter(item => item !== row.path);
            } else {
                this.remoteSelectedPaths = [...this.remoteSelectedPaths, row.path];
            }
        },

        clearRemoteSelection() {
            this.remoteSelectedPaths = [];
            const tableRef = this.$refs.remoteFilesTableRef;
            if (tableRef && typeof tableRef.clearSelection === 'function') {
                tableRef.clearSelection();
            }
        },

        async copyRemotePath(row) {
            if (!row || !row.path || row.is_parent_entry) {
                ElementPlus.ElMessage.warning('Invalid path');
                return;
            }

            try {
                await navigator.clipboard.writeText(row.path);
                ElementPlus.ElMessage.success('Path copied');
            } catch (e) {
                ElementPlus.ElMessage.error('Failed to copy path');
            }
        },

        // add 复制移动文件 2026-04-09 12:00
        cacheRemoteClipboard(mode) {
            const paths = [...this.remoteSelectedPaths];
            if (!paths.length) {
                ElementPlus.ElMessage.warning('Please select at least one file or folder');
                return;
            }

            this.remoteClipboardPaths = paths;
            this.remoteClipboardMode = mode === 'move' ? 'move' : 'copy';
            this.remoteClipboardSourcePath = this.remoteFilesCurrentPath || '';

            const actionText = this.remoteClipboardMode === 'move' ? 'Cut' : 'Copied';
            ElementPlus.ElMessage.success(`${actionText} ${paths.length} item(s)`);
        },

        // add 复制移动文件 2026-04-09 12:00
        copySelectedRemoteEntries() {
            this.cacheRemoteClipboard('copy');
        },

        // add 复制移动文件 2026-04-09 12:00
        cutSelectedRemoteEntries() {
            this.cacheRemoteClipboard('move');
        },

        // add 复制移动文件 2026-04-09 12:00
        clearRemoteClipboard() {
            this.remoteClipboardPaths = [];
            this.remoteClipboardMode = '';
            this.remoteClipboardSourcePath = '';
        },

        // add 复制移动文件 2026-04-09 12:00
        async pasteRemoteClipboard() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            if (!this.remoteFilesCurrentPath) {
                ElementPlus.ElMessage.warning('Current directory is empty');
                return;
            }

            const paths = [...this.remoteClipboardPaths];
            if (!paths.length || !this.remoteClipboardMode) {
                ElementPlus.ElMessage.warning('Clipboard is empty');
                return;
            }

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/paste`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        paths,
                        destination_dir: this.remoteFilesCurrentPath,
                        operation: this.remoteClipboardMode,
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Paste failed');
                }

                const actionText = this.remoteClipboardMode === 'move' ? 'Moved' : 'Copied';
                const message = json.data?.message || `${actionText} ${paths.length} item(s)`;

                ElementPlus.ElMessage.success(`${actionText} ${paths.length} item(s)`);
                await this.refreshRemoteDirectory();

                if (this.remoteClipboardMode === 'move') {
                    this.clearRemoteClipboard();
                }

                if (message && !message.startsWith(`${actionText} ${paths.length} item(s)`)) {
                    ElementPlus.ElMessage.info(message);
                }
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Paste failed');
            }
        },

        handleRemoteMoreAction(command, row) {
            if (!row || row.is_parent_entry) return;

            if (command === 'rename') {
                this.renameRemoteEntry(row);
                return;
            }
            if (command === 'copy_path') {
                this.copyRemotePath(row);
                return;
            }
            if (command === 'copy') {
                this.remoteSelectedPaths = row.path ? [row.path] : [];
                this.copySelectedRemoteEntries();
                return;
            }
            if (command === 'cut') {
                this.remoteSelectedPaths = row.path ? [row.path] : [];
                this.cutSelectedRemoteEntries();
                return;
            }
            if (command === 'delete') {
                this.deleteRemoteEntry(row);
            }
        },

        async createRemoteDirectory() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            if (!this.remoteFilesCurrentPath) {
                ElementPlus.ElMessage.warning('Current directory is empty');
                return;
            }

            try {
                const {value} = await ElementPlus.ElMessageBox.prompt(
                    'Enter the new folder name',
                    'Create Directory',
                    {
                        confirmButtonText: 'Create',
                        cancelButtonText: 'Cancel',
                        inputPattern: /.+/,
                        inputErrorMessage: 'Folder name is required'
                    }
                );

                const folderName = String(value || '').trim();
                if (!folderName) return;

                const base = this.remoteFilesCurrentPath.replace(/[\\/]+$/, '');
                const separator = base.includes('\\') ? '\\' : '/';
                const fullPath = `${base}${base ? separator : ''}${folderName}`;

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/mkdir`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({path: fullPath})
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Create directory failed');
                }

                ElementPlus.ElMessage.success('Directory created');
                await this.refreshRemoteDirectory();
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Create directory failed');
            }
        },

        async renameRemoteEntry(row) {
            if (!row || !row.path || row.is_parent_entry) {
                ElementPlus.ElMessage.warning('Invalid path');
                return;
            }

            try {
                const {value} = await ElementPlus.ElMessageBox.prompt(
                    'Enter the new name',
                    'Rename',
                    {
                        confirmButtonText: 'Rename',
                        cancelButtonText: 'Cancel',
                        inputValue: row.name || '',
                        inputPattern: /.+/,
                        inputErrorMessage: 'New name is required'
                    }
                );

                const newName = String(value || '').trim();
                if (!newName || newName === row.name) return;

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/rename`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        old_path: row.path,
                        new_name: newName
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Rename failed');
                }

                ElementPlus.ElMessage.success('Renamed');
                await this.refreshRemoteDirectory();
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Rename failed');
            }
        },

        async downloadRemoteEntry(row) {
            if (!row || !row.path || row.is_dir || row.is_parent_entry) {
                ElementPlus.ElMessage.warning('Please select a file');
                return;
            }

            try {
                const url = new URL(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/download`, window.location.origin);
                url.searchParams.set('path', row.path);

                const res = await fetch(url.pathname + url.search, {method: 'POST'});
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Download failed');
                }

                const file = (json.data && (json.data.file || json.data.artifact)) || null;
                if (!file || !file.artifact_id) {
                    throw new Error('Download finished, but artifact was not found');
                }

                const downloadUrl = file.download_url || `/api/artifacts/${encodeURIComponent(file.artifact_id)}/download`;
                window.open(downloadUrl, '_blank');

                ElementPlus.ElMessage.success(`Downloaded: ${row.name}`);

                if (this.artifactDialogVisible) {
                    await this.loadArtifacts();
                }
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Download failed');
            }
        },

        async downloadSelectedRemoteEntries() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            const paths = [...this.remoteSelectedPaths];
            if (!paths.length) {
                ElementPlus.ElMessage.warning('Please select at least one file or folder');
                return;
            }

            this.remoteZipDownloading = true;

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/download-zip`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        paths,
                        archive_name: ''
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'ZIP download failed');
                }

                const file = (json.data && (json.data.file || json.data.artifact)) || null;
                if (!file || !file.artifact_id) {
                    throw new Error('ZIP download finished, but artifact was not found');
                }

                const downloadUrl = file.download_url || `/api/artifacts/${encodeURIComponent(file.artifact_id)}/download`;
                window.open(downloadUrl, '_blank');

                ElementPlus.ElMessage.success(`ZIP ready: ${file.original_name || file.stored_name}`);

                if (this.artifactDialogVisible) {
                    await this.loadArtifacts();
                }
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'ZIP download failed');
            } finally {
                this.remoteZipDownloading = false;
            }
        },

        async deleteRemoteEntry(row) {
            if (!row || !row.path || row.is_parent_entry) {
                ElementPlus.ElMessage.warning('Invalid path');
                return;
            }

            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Delete "${row.name}"?${row.is_dir ? ' All nested contents will be removed as well.' : ''}`,
                    'Delete Confirmation',
                    {
                        type: 'warning',
                        confirmButtonText: 'Delete',
                        cancelButtonText: 'Cancel'
                    }
                );

                const url = new URL(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files`, window.location.origin);
                url.searchParams.set('path', row.path);

                const res = await fetch(url.pathname + url.search, {method: 'DELETE'});
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Delete failed');
                }

                ElementPlus.ElMessage.success('Deleted');
                await this.refreshRemoteDirectory();
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Delete failed');
            }
        },

        async deleteSelectedRemoteEntries() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            const paths = [...this.remoteSelectedPaths];
            if (!paths.length) {
                ElementPlus.ElMessage.warning('Please select at least one file or folder to delete');
                return;
            }

            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Delete ${paths.length} selected item(s)?`,
                    'Delete Multiple Items',
                    {
                        type: 'warning',
                        confirmButtonText: 'Delete',
                        cancelButtonText: 'Cancel',
                        confirmButtonClass: 'el-button--danger',
                        dangerouslyUseHTMLString: false
                    }
                );

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/batch`, {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({paths})
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Batch delete failed');
                }

                const message = json.data?.message || 'Delete completed';
                ElementPlus.ElMessage.success(`Deleted ${paths.length} item(s)`);

                // 刷新当前目录
                await this.refreshRemoteDirectory();

                // 清空选中状态
                this.clearRemoteSelection();

                // 可选：显示详细结果
                if (message && message !== 'Delete completed') {
                    ElementPlus.ElMessage.info(message);
                }
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Batch delete failed');
            }
        },

        // add hostname 收藏 quick jump 2026-04-09 15:30
        async loadPinnedQuickJumps() {
            if (!this.selectedId) return;

            this.remotePinnedJumpLoading = true;
            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/quick-jumps`);
                const json = await res.json();
                if (res.ok && json.code === 0 && json.data) {
                    this.remotePinnedJumpItems = Array.isArray(json.data.items)
                        ? json.data.items
                        : [];
                }
            } catch (e) {
                console.error('Failed to load pinned quick jumps:', e);
            } finally {
                this.remotePinnedJumpLoading = false;
            }
        },

        // add quick jump 管理编辑 2026-04-09 16:20
        async promptSavePinnedQuickJump() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            const currentPath = String(this.remoteFilesCurrentPath || '').trim();
            if (!currentPath) {
                ElementPlus.ElMessage.warning('Current directory is empty');
                return;
            }

            const currentItems = Array.isArray(this.remotePinnedJumpItems)
                ? this.remotePinnedJumpItems
                : [];
            const currentPinnedItem = this.currentPinnedQuickJumpItem;
            const currentDirectoryName = currentPath
                .replace(/[\\/]+$/, '')
                .split(/[\\/]/)
                .filter(Boolean)
                .pop() || 'Pinned Path';

            try {
                const {value} = await ElementPlus.ElMessageBox.prompt(
                    `Current path:<br><span style="word-break: break-all; color: var(--muted);">${this.escapeRemoteHtml(currentPath)}</span>`,
                    currentPinnedItem ? 'Edit Pinned Quick Jump' : 'Pin Quick Jump',
                    {
                        confirmButtonText: currentPinnedItem ? 'Update' : 'Save',
                        cancelButtonText: 'Cancel',
                        dangerouslyUseHTMLString: true,
                        inputValue: currentPinnedItem?.display_name || currentDirectoryName,
                        inputPattern: /.+/,
                        inputErrorMessage: 'Display name is required'
                    }
                );

                const displayName = String(value || '').trim();
                if (!displayName) return;

                const exists = currentItems.find(item => (item?.display_name || '').trim() === displayName);
                if (exists && (!currentPinnedItem || (exists.display_name || '').trim() !== (currentPinnedItem.display_name || '').trim())) {
                    await ElementPlus.ElMessageBox.confirm(
                        `A pinned quick jump named "${this.escapeRemoteHtml(displayName)}" already exists. Update it to the current path?`,
                        'Overwrite Quick Jump',
                        {
                            confirmButtonText: 'Overwrite',
                            cancelButtonText: 'Cancel',
                            type: 'warning',
                            dangerouslyUseHTMLString: true,
                        }
                    );
                }

                const method = currentPinnedItem ? 'PUT' : 'POST';
                const body = currentPinnedItem
                    ? {
                        original_display_name: currentPinnedItem.display_name,
                        display_name: displayName,
                        path: currentPath,
                    }
                    : {
                        display_name: displayName,
                        path: currentPath,
                    };

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/quick-jumps`, {
                    method,
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(body)
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to save quick jump');
                }

                this.remotePinnedJumpItems = Array.isArray(json.data?.items)
                    ? json.data.items
                    : [];
                ElementPlus.ElMessage.success(json.data?.message || 'Quick jump saved');
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Failed to save quick jump');
            }
        },

        // add quick jump 管理编辑 2026-04-09 16:20
        async deletePinnedQuickJump(item, options = {}) {
            if (!this.selectedId || !item?.display_name) return false;

            const shouldConfirm = options.confirm !== false;
            try {
                if (shouldConfirm) {
                    await ElementPlus.ElMessageBox.confirm(
                        `Remove pinned quick jump "${this.escapeRemoteHtml(item.display_name)}"?`,
                        'Delete Quick Jump',
                        {
                            confirmButtonText: 'Delete',
                            cancelButtonText: 'Cancel',
                            type: 'warning',
                            dangerouslyUseHTMLString: true,
                        }
                    );
                }

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/quick-jumps`, {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({display_name: item.display_name})
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to delete quick jump');
                }

                this.remotePinnedJumpItems = Array.isArray(json.data?.items) ? json.data.items : [];
                if (options.toast !== false) {
                    ElementPlus.ElMessage.success(json.data?.message || 'Quick jump removed');
                }
                return true;
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return false;
                ElementPlus.ElMessage.error(e.message || 'Failed to delete quick jump');
                return false;
            }
        },

        // add quick jump 管理编辑 2026-04-09 16:20
        async promptEditPinnedQuickJump(item) {
            if (!this.selectedId || !item?.display_name) return;

            try {
                const {value: displayNameValue} = await ElementPlus.ElMessageBox.prompt(
                    `Edit display name for:<br><span style="word-break: break-all; color: var(--muted);">${this.escapeRemoteHtml(item.path || '')}</span>`,
                    'Edit Pinned Quick Jump',
                    {
                        confirmButtonText: 'Next',
                        cancelButtonText: 'Cancel',
                        dangerouslyUseHTMLString: true,
                        inputValue: item.display_name || '',
                        inputPattern: /.+/,
                        inputErrorMessage: 'Display name is required'
                    }
                );

                const displayName = String(displayNameValue || '').trim();
                if (!displayName) return;

                const {value: pathValue} = await ElementPlus.ElMessageBox.prompt(
                    'Edit target path',
                    'Edit Pinned Quick Jump',
                    {
                        confirmButtonText: 'Save',
                        cancelButtonText: 'Cancel',
                        inputValue: item.path || '',
                        inputPattern: /.+/,
                        inputErrorMessage: 'Path is required'
                    }
                );

                const path = String(pathValue || '').trim();
                if (!path) return;

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/quick-jumps`, {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        original_display_name: item.display_name,
                        display_name: displayName,
                        path,
                    })
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to update quick jump');
                }

                this.remotePinnedJumpItems = Array.isArray(json.data?.items) ? json.data.items : [];
                ElementPlus.ElMessage.success(json.data?.message || 'Quick jump updated');
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Failed to update quick jump');
            }
        },

        // add quick jump 管理编辑 2026-04-09 16:20
        async toggleCurrentPinnedQuickJump() {
            const currentItem = this.currentPinnedQuickJumpItem;
            if (currentItem) {
                await this.deletePinnedQuickJump(currentItem);
                return;
            }
            await this.promptSavePinnedQuickJump();
        },

        // add quick jump 管理编辑 2026-04-09 16:20
        openPinnedQuickJumpManager() {
            this.remotePinManagerDialogVisible = true;
        },

        // add hostname 收藏 quick jump 2026-04-09 15:30
        escapeRemoteHtml(text) {
            return String(text || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        },

        async loadQuickJumpPaths() {
            if (!this.selectedId) return;

            this.quickJumpLoading = true;
            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/system-paths`);
                const json = await res.json();
                if (res.ok && json.code === 0 && json.data) {
                    this.quickJumpPaths = json.data;
                }
            } catch (e) {
                console.error('Failed to load quick jump paths:', e);
            } finally {
                this.quickJumpLoading = false;
            }
        },

        async jumpToPath(command) {
            if (command === 'input_navigate') {
                await this.promptRemotePathNavigate();
                return;
            }

            if (command && typeof command === 'object') {
                if (command.type === 'pinned_jump') {
                    const path = String(command.path || '').trim();
                    if (!path) {
                        ElementPlus.ElMessage.warning('Path not available');
                        return;
                    }
                    await this.loadRemoteDirectory(path, 1);
                    return;
                }

                if (command.type === 'manage_pins') {
                    this.openPinnedQuickJumpManager();
                    return;
                }
            }

            const path = this.quickJumpPaths[command];
            if (!path) {
                ElementPlus.ElMessage.warning('Path not available');
                return;
            }
            await this.loadRemoteDirectory(path, 1);
        },

        // add 面包糠导航优化 2026-04-09 12:00
        async promptRemotePathNavigate() {
            try {
                const {value} = await ElementPlus.ElMessageBox.prompt(
                    'Enter the target path',
                    'Input Navigate',
                    {
                        confirmButtonText: 'Go',
                        cancelButtonText: 'Cancel',
                        inputValue: this.remoteFilesCurrentPath || this.remoteFilesPathInput || '',
                        inputPattern: /.+/,
                        inputErrorMessage: 'Path is required'
                    }
                );

                const path = String(value || '').trim();
                if (!path) return;

                this.remoteFilesPathInput = path;
                await this.loadRemoteDirectory(path, 1);
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Navigate failed');
            }
        },

        // add 面包糠导航优化 2026-04-09 12:00
        buildRemoteBreadcrumbItems(path) {
            const currentPath = String(path || '').trim();
            if (!currentPath) return [];

            const windowsMatch = currentPath.match(/^([A-Za-z]:)([\\/].*)?$/);
            if (windowsMatch) {
                const drive = windowsMatch[1];
                const rest = String(windowsMatch[2] || '').replace(/^[\\/]+/, '');
                const parts = rest ? rest.split(/[\\/]+/).filter(Boolean) : [];
                const items = [{label: drive, path: `${drive}\\`}];
                let accumulated = `${drive}\\`;

                parts.forEach(part => {
                    accumulated = accumulated.replace(/[\\/]+$/, '') + '\\' + part;
                    items.push({label: part, path: accumulated});
                });

                return items;
            }

            const isAbsolute = currentPath.startsWith('/');
            const parts = currentPath.split('/').filter(Boolean);
            const items = [];

            if (isAbsolute) {
                items.push({label: 'Root', path: '/'});
            }

            let accumulated = '';
            parts.forEach(part => {
                if (isAbsolute) {
                    accumulated += `/${part}`;
                } else {
                    accumulated = accumulated ? `${accumulated}/${part}` : part;
                }
                items.push({label: part, path: accumulated});
            });

            if (!items.length && isAbsolute) {
                items.push({label: 'Root', path: '/'});
            }

            return items;
        },

        // add 面包糠导航优化 2026-04-09 12:00
        async goToRemoteBreadcrumb(item) {
            if (!item || !item.path || item.isCurrent) return;
            await this.loadRemoteDirectory(item.path, 1);
        },

        resetRemoteFilesState() {
            this.remoteFilesCurrentPath = '';
            this.remoteFilesParentPath = '';
            this.remoteFilesEntries = [];
            this.remoteFilesPathInput = '';
            this.remoteFilesPage = 1;
            this.remoteFilesPageSize = 50;
            this.remoteFilesTotal = 0;
            this.remoteFilesTotalPages = 1;
            this.remoteFilesAllTotal = 0;
            this.remoteFilesHiddenTotal = 0;
            this.showHiddenFiles = false;
            this.remoteSelectedPaths = [];
            this.remoteZipDownloading = false;
            this.remotePinnedJumpItems = [];
            this.remotePinnedJumpLoading = false;
            this.remotePinManagerDialogVisible = false;
            this.clearRemoteClipboard();
        },
    },

    computed: {
        displayRemoteFilesEntries() {
            const entries = Array.isArray(this.remoteFilesEntries)
                ? [...this.remoteFilesEntries]
                : [];

            if (this.remoteFilesParentPath && this.remoteFilesPage === 1) {
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

        hasRemoteClipboard() {
            return this.remoteClipboardPaths.length > 0 && !!this.remoteClipboardMode;
        },

        remoteClipboardActionText() {
            return this.remoteClipboardMode === 'move' ? 'Cut' : 'Copy';
        },

        // add 面包糠导航优化 2026-04-09 12:00
        remoteBreadcrumbItems() {
            const items = this.buildRemoteBreadcrumbItems(this.remoteFilesCurrentPath || '');
            return items.map(item => ({
                ...item,
                isCurrent: item.path === (this.remoteFilesCurrentPath || '')
            }));
        },

        // add hostname 收藏 quick jump 2026-04-09 15:30
        hasPinnedQuickJumps() {
            return Array.isArray(this.remotePinnedJumpItems) && this.remotePinnedJumpItems.length > 0;
        },

        // add quick jump 管理编辑 2026-04-09 16:20
        currentPinnedQuickJumpItem() {
            const currentPath = String(this.remoteFilesCurrentPath || '').trim();
            if (!currentPath) return null;
            return (this.remotePinnedJumpItems || []).find(item => String(item?.path || '').trim() === currentPath) || null;
        },

        // add quick jump 管理编辑 2026-04-09 16:20
        remotePinButtonText() {
            return this.currentPinnedQuickJumpItem ? 'Unpin' : 'Pin';
        },
    },

    watch: {
         remoteFilesDialogVisible(val) {
            if (!val) this.resetRemoteFilesState();
        },
    }
};
