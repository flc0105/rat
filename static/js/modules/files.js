window.AppFilesModule = {
    methods: {
        async loadPreviewPayload(fetcher, fallbackTitle = 'File Preview') {
            this.previewDialogVisible = true;
            this.previewLoading = true;
            this.resetPreviewState();

            try {
                const res = await fetcher();
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Preview failed');
                }

                const data = json.data || {};
                this.previewType = data.type || 'unsupported';
                this.previewTitle = data.name || fallbackTitle;

                if (this.previewType === 'image') {
                    this.previewUrl = data.url || '';
                } else if (this.previewType === 'text') {
                    this.previewText = data.content || '';
                }
            } catch (e) {
                this.previewDialogVisible = false;
                ElementPlus.ElMessage.error(e.message || 'Preview failed');
            } finally {
                this.previewLoading = false;
            }
        },

        async copyPreviewText() {
            if (!this.previewText) {
                ElementPlus.ElMessage.warning('No preview text available');
                return;
            }

            try {
                await navigator.clipboard.writeText(this.previewText);
                ElementPlus.ElMessage.success('Content copied');
            } catch (e) {
                ElementPlus.ElMessage.error('Failed to copy content');
            }
        },

        openPreviewOriginal() {
            if (!this.previewUrl) {
                ElementPlus.ElMessage.warning('No image available');
                return;
            }
            window.open(this.previewUrl, '_blank');
        },

        async previewArtifact(row) {
            if (!row || !row.artifact_id) {
                ElementPlus.ElMessage.warning('Invalid artifact');
                return;
            }

            await this.loadPreviewPayload(
                () => fetch(`/api/artifacts/${encodeURIComponent(row.artifact_id)}/preview`),
                row.original_name || row.stored_name || 'Artifact Preview'
            );
        },

        async deleteArtifact(row) {
            if (!row || !row.artifact_id) {
                ElementPlus.ElMessage.warning('Invalid artifact');
                return;
            }

            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Delete "${row.original_name || row.stored_name}"?`,
                    'Delete Confirmation',
                    {
                        type: 'warning',
                        confirmButtonText: 'Delete',
                        cancelButtonText: 'Cancel'
                    }
                );

                const res = await fetch(`/api/artifacts/${encodeURIComponent(row.artifact_id)}`, {
                    method: 'DELETE'
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Delete failed');
                }

                ElementPlus.ElMessage.success('Deleted');
                await this.loadArtifacts();
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Delete failed');
            }
        },

        async openArtifactDialog() {
            this.artifactDialogVisible = true;
            await this.loadArtifacts();
        },

        async loadArtifacts() {
            this.artifactLoading = true;

            try {
                const url = new URL('/api/artifacts', window.location.origin);
                const hostname = String(this.artifactHostnameFilter || '').trim();

                if (hostname) url.searchParams.set('hostname', hostname);

                const res = await fetch(url.pathname + url.search);
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load artifacts');
                }

                const data = json.data || {};
                this.artifactItems = Array.isArray(data.items) ? data.items : [];
                this.artifactHostnames = Array.isArray(data.hostnames) ? data.hostnames : [];
            } catch (e) {
                this.artifactItems = [];
                this.artifactHostnames = [];
                ElementPlus.ElMessage.error(e.message || 'Failed to load artifacts');
            } finally {
                this.artifactLoading = false;
            }
        },

        async clearArtifactCategory() {
            const activeType = String(this.artifactActiveTab || '').trim();
            if (!activeType) {
                ElementPlus.ElMessage.warning('Please select a category');
                return;
            }

            try {
                const hostnameText = this.artifactHostnameFilter ? ` for ${this.artifactHostnameFilter}` : '';
                await ElementPlus.ElMessageBox.confirm(
                    `Clear all ${activeType}${hostnameText}?`,
                    'Clear Artifacts',
                    {
                        type: 'warning',
                        confirmButtonText: 'Clear',
                        cancelButtonText: 'Cancel'
                    }
                );

                this.artifactClearing = true;
                const res = await fetch('/api/artifacts/clear', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        type: activeType,
                        hostname: this.artifactHostnameFilter || ''
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Clear failed');
                }

                ElementPlus.ElMessage.success(`Cleared ${json.data?.deleted_count || 0} item(s)`);
                await this.loadArtifacts();
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Clear failed');
            } finally {
                this.artifactClearing = false;
            }
        },

        async previewRemoteEntry(row) {
            if (!row || !row.path || row.is_dir || row.is_parent_entry) {
                ElementPlus.ElMessage.warning('Please select a file');
                return;
            }

            await this.loadPreviewPayload(
                () => fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/preview`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({path: row.path})
                }),
                row.name || 'File Preview'
            );
        },

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
            await this.loadRemoteDirectory('');
        },

        async loadRemoteDirectory(path = '') {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            this.remoteFilesLoading = true;

            try {
                const url = new URL(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files`, window.location.origin);
                if (path) url.searchParams.set('path', path);

                const res = await fetch(url.pathname + url.search);
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load remote directory');
                }

                const data = json.data || {};
                this.remoteFilesCurrentPath = data.current_path || '';
                this.remoteFilesParentPath = data.parent_path || '';
                this.remoteFilesEntries = data.entries || [];
                this.remoteFilesPathInput = this.remoteFilesCurrentPath || '';
                this.remoteSelectedPaths = [];
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to load remote directory');
            } finally {
                this.remoteFilesLoading = false;
            }
        },

        async refreshRemoteDirectory() {
            await this.loadRemoteDirectory(this.remoteFilesCurrentPath || '');
        },

        async goToRemoteParent() {
            if (!this.remoteFilesParentPath) return;
            await this.loadRemoteDirectory(this.remoteFilesParentPath);
        },

        async goToRemotePathInput() {
            const path = (this.remoteFilesPathInput || '').trim();
            if (!path) {
                ElementPlus.ElMessage.warning('Please enter a path');
                return;
            }
            await this.loadRemoteDirectory(path);
        },

        async enterRemoteDirectory(row) {
            if (!row || !row.is_dir) return;

            if (row.is_parent_entry) {
                await this.goToRemoteParent();
                return;
            }

            await this.loadRemoteDirectory(row.path);
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

        async previewBackgroundJobFile(file) {
            if (!file) {
                ElementPlus.ElMessage.warning('No preview available');
                return;
            }

            if (file.artifact_id) {
                await this.loadPreviewPayload(
                    () => fetch(`/api/artifacts/${encodeURIComponent(file.artifact_id)}/preview`),
                    file.original_name || file.stored_name || 'Job File Preview'
                );
                return;
            }

            if (!file.preview_url) {
                ElementPlus.ElMessage.warning('No preview available');
                return;
            }

            await this.loadPreviewPayload(
                () => fetch(file.preview_url),
                file.original_name || file.stored_name || 'Job File Preview'
            );
        }
    }
};