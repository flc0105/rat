export default {
    data() {
        return {
            scriptLibraryDialogVisible: false,
            scriptLibraryLoading: false,
            scriptCatalogItems: [],
            scriptCatalogDirectories: [],
            selectedScriptDirectory: '',
            scriptRunSubmitting: false,
            scriptRunDialogVisible: false,
            pendingRunScriptName: '',
            scriptParamForm: {},
            serverScriptUploadLoading: false,
        };
    },

    computed: {
        // scriptDirectoryTreeData() {
        //     const root = [];
        //     const ensureNode = (children, key, label, path) => {
        //         const existing = children.find(node => node.key === key);
        //         if (existing) return existing;
        //         const node = {key, label, path, children: []};
        //         children.push(node);
        //         return node;
        //     };
        //
        //     const directories = Array.isArray(this.scriptCatalogDirectories) && this.scriptCatalogDirectories.length
        //         ? this.scriptCatalogDirectories
        //         : [{key: 'dir:.', label: 'root', path: ''}];
        //
        //     directories.forEach((directory) => {
        //         const path = String(directory?.path || '').trim().replace(/^\/+/, '');
        //         const parts = path.split('/').filter(Boolean);
        //         let currentChildren = root;
        //         let currentPath = '';
        //
        //         if (!parts.length) {
        //             ensureNode(root, 'dir:.', 'root', '');
        //             return;
        //         }
        //
        //         parts.forEach((part) => {
        //             currentPath = currentPath ? `${currentPath}/${part}` : part;
        //             const node = ensureNode(currentChildren, `dir:${currentPath}`, part, currentPath);
        //             currentChildren = node.children;
        //         });
        //     });
        //
        //     const sortNodes = (nodes) => {
        //         nodes.sort((a, b) => String(a.label || '').localeCompare(String(b.label || '')));
        //         nodes.forEach(node => sortNodes(node.children || []));
        //         return nodes;
        //     };
        //
        //     return sortNodes(root);
        // },

        scriptDirectoryTreeData() {
    const ensureNode = (children, key, label, path) => {
        const existing = children.find(node => node.key === key);
        if (existing) return existing;
        const node = {key, label, path, children: []};
        children.push(node);
        return node;
    };

    const rootNode = {key: 'dir:.', label: 'root', path: '', children: []};

    const directories = Array.isArray(this.scriptCatalogDirectories) && this.scriptCatalogDirectories.length
        ? this.scriptCatalogDirectories
        : [{key: 'dir:.', label: 'root', path: ''}];

    directories.forEach((directory) => {
        const path = String(directory?.path || '').trim().replace(/^\/+/, '');
        const parts = path.split('/').filter(Boolean);
        let currentChildren = rootNode.children;
        let currentPath = '';

        if (!parts.length) return;

        parts.forEach((part) => {
            currentPath = currentPath ? `${currentPath}/${part}` : part;
            const node = ensureNode(currentChildren, `dir:${currentPath}`, part, currentPath);
            currentChildren = node.children;
        });
    });

    const sortNodes = (nodes) => {
        nodes.sort((a, b) => String(a.label || '').localeCompare(String(b.label || '')));
        nodes.forEach(node => sortNodes(node.children || []));
        return nodes;
    };

    sortNodes(rootNode.children);
    return [rootNode];
},

        currentScriptDirectoryItems() {
            const currentDir = String(this.selectedScriptDirectory || '').trim();
            const items = (this.scriptCatalogItems || []).filter(item => {
                const path = String(item.path || `${item.script_name || ''}.py`).replace(/^\/+/, '');
                const parts = path.split('/').filter(Boolean);
                const dirPath = parts.slice(0, -1).join('/');
                return dirPath === currentDir;
            });

            return items.sort((a, b) => {
                const da = String(a.display_name || a.script_name || '').toLowerCase();
                const db = String(b.display_name || b.script_name || '').toLowerCase();
                return da.localeCompare(db);
            });
        },

        pendingRunScriptItem() {
            const target = String(this.pendingRunScriptName || '').trim();
            return (this.scriptCatalogItems || []).find(item => String(item.script_name || '').trim() === target) || null;
        },

        pendingRunScriptMetadata() {
            const item = this.pendingRunScriptItem;
            if (!item) {
                return {name: '', display_name: '', description: '', platforms: [], params: [], category: '', tags: []};
            }
            return this.normalizeScriptMetadata(item.metadata || {});
        },

        pendingRunScriptParamSpecs() {
            return Array.isArray(this.pendingRunScriptMetadata.params) ? this.pendingRunScriptMetadata.params : [];
        },
    },

    methods: {
        async openScriptLibraryDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            this.scriptLibraryDialogVisible = true;
            await this.loadScriptCatalog();
        },

        normalizeServerScriptFilename(scriptName, fallbackName = 'new_script.py') {
            let normalized = String(scriptName || '').trim().replace(/\\/g, '/').replace(/^\/+/, '');
            if (!normalized) normalized = fallbackName;
            if (!/\.py$/i.test(normalized)) normalized = `${normalized}.py`;
            return normalized;
        },

        async loadScriptCatalog() {
            this.scriptLibraryLoading = true;
            try {
                const res = await fetch('/api/scripts/catalog');
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load script catalog');
                }

                const catalog = json.data || {};
                this.scriptCatalogItems = Array.isArray(catalog.items) ? catalog.items : [];
                this.scriptCatalogDirectories = Array.isArray(catalog.directories) ? catalog.directories : [{key: 'dir:.', label: 'root', path: ''}];

                if (!this.selectedScriptDirectory) {
                    this.selectedScriptDirectory = this.getFirstAvailableScriptDirectory();
                } else {
                    const hasCurrentDir = this.scriptCatalogDirectories.some(item => String(item?.path || '').trim() === this.selectedScriptDirectory);
                    if (!hasCurrentDir) this.selectedScriptDirectory = this.getFirstAvailableScriptDirectory();
                }
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to load script catalog');
            } finally {
                this.scriptLibraryLoading = false;
            }
        },

        getScriptDirectoryPath(item) {
            const path = String(item?.path || `${item?.script_name || ''}.py`).replace(/^\/+/, '');
            const parts = path.split('/').filter(Boolean);
            return parts.slice(0, -1).join('/');
        },

        getFirstAvailableScriptDirectory() {
            const dirs = (this.scriptCatalogDirectories || []).map(item => String(item?.path || '').trim());
            return dirs.length ? dirs.sort()[0] : '';
        },

        getParentScriptDirectory(directory) {
    const normalized = String(directory || '').trim().replace(/^\/+/, '').replace(/\/+$/, '');
    if (!normalized) return '';
    const parts = normalized.split('/').filter(Boolean);
    return parts.slice(0, -1).join('/');
},

        async renameRemoteScriptFolder() {
    const currentDirectory = String(this.selectedScriptDirectory || '').trim();
    if (!currentDirectory) {
        ElementPlus.ElMessage.warning('Root folder cannot be renamed');
        return;
    }

    try {
        const {value} = await ElementPlus.ElMessageBox.prompt(
            'Enter the new folder path',
            'Rename Folder',
            {
                confirmButtonText: 'Rename',
                cancelButtonText: 'Cancel',
                inputValue: currentDirectory,
                inputPlaceholder: 'folder/subfolder',
            }
        );

        const newDirectory = String(value || '').trim().replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
        if (!newDirectory) {
            ElementPlus.ElMessage.warning('New folder path is required');
            return;
        }

        const res = await fetch('/api/scripts/folders/rename', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                directory: currentDirectory,
                new_directory: newDirectory
            })
        });
        const json = await res.json();
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to rename folder');

        this.selectedScriptDirectory = newDirectory;
        ElementPlus.ElMessage.success(`Folder renamed: ${newDirectory}`);
        await this.loadScriptCatalog();
    } catch (e) {
        if (e === 'cancel' || e === 'close') return;
        ElementPlus.ElMessage.error(e.message || 'Failed to rename folder');
    }
},

        async deleteRemoteScriptFolder() {
    const currentDirectory = String(this.selectedScriptDirectory || '').trim();
    if (!currentDirectory) {
        ElementPlus.ElMessage.warning('Root folder cannot be deleted');
        return;
    }

    try {
        await ElementPlus.ElMessageBox.confirm(
            `Delete folder "${currentDirectory}" and all files/subfolders in it? This action cannot be undone.`,
            'Delete Folder',
            {
                type: 'warning',
                confirmButtonText: 'Delete',
                cancelButtonText: 'Cancel'
            }
        );

        const parentDirectory = this.getParentScriptDirectory(currentDirectory);

        const res = await fetch('/api/scripts/folders', {
            method: 'DELETE',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({directory: currentDirectory})
        });
        const json = await res.json();
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to delete folder');

        this.selectedScriptDirectory = parentDirectory;
        ElementPlus.ElMessage.success(`Folder deleted: ${currentDirectory}`);
        await this.loadScriptCatalog();
    } catch (e) {
        if (e === 'cancel' || e === 'close') return;
        ElementPlus.ElMessage.error(e.message || 'Failed to delete folder');
    }
},

        handleScriptTreeNodeClick(node) {
            if (!node) return;
            this.selectedScriptDirectory = String(node.path || '').trim();
        },

        normalizeScriptMetadata(metadata = {}) {
            if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
                return {name: '', display_name: '', description: '', platforms: [], params: [], category: '', tags: []};
            }

            const normalizeParam = (item = {}) => {
                const name = String(item.name || '').trim();
                if (!name) return null;
                return {
                    ...item,
                    name,
                    type: String(item.type || 'string').trim().toLowerCase() || 'string',
                    required: !!item.required,
                    description: String(item.description || '').trim(),
                    options: Array.isArray(item.options) ? item.options : [],
                };
            };

            return {
                ...metadata,
                name: String(metadata.name || '').trim(),
                display_name: String(metadata.display_name || '').trim(),
                description: String(metadata.description || '').trim(),
                category: String(metadata.category || '').trim(),
                tags: Array.isArray(metadata.tags) ? metadata.tags : [],
                platforms: typeof this.normalizeJobPlatforms === 'function' ? this.normalizeJobPlatforms(metadata.platforms) : [],
                params: Array.isArray(metadata.params) ? metadata.params.map(normalizeParam).filter(Boolean) : [],
            };
        },

        buildScriptParamDefaults(item) {
            const metadata = this.normalizeScriptMetadata(item?.metadata || {});
            const result = {};
            for (const param of metadata.params || []) {
                const defaultValue = Object.prototype.hasOwnProperty.call(param, 'default') ? param.default : '';
                if ((param.type || '').toLowerCase() === 'boolean') {
                    result[param.name] = defaultValue === true || String(defaultValue).toLowerCase() === 'true';
                } else {
                    result[param.name] = defaultValue === null || defaultValue === undefined ? '' : String(defaultValue);
                }
            }
            return result;
        },

        isScriptSupportedForCurrentConnection(item) {
            const metadata = this.normalizeScriptMetadata(item?.metadata || {});
            const platforms = metadata.platforms || [];
            if (!platforms.length || platforms.includes('*') || platforms.includes('common')) return true;

            const current = typeof this.normalizeClientPlatform === 'function'
                ? this.normalizeClientPlatform(
                    this.currentConnection?.os_type ||
                    this.currentConnection?.platform ||
                    this.currentConnection?.system ||
                    this.currentConnection?.os ||
                    ''
                )
                : '';

            if (!current) return true;
            return platforms.includes(current);
        },

        formatScriptPlatformLabel(item) {
            const metadata = this.normalizeScriptMetadata(item?.metadata || {});
            const platforms = metadata.platforms || [];
            if (!platforms.length || platforms.includes('*') || platforms.includes('common')) return 'All OS';
            if (typeof this.formatJobPlatformLabel === 'function') return this.formatJobPlatformLabel(platforms);
            return platforms.join(' / ');
        },

        scriptHasParams(item) {
            const metadata = this.normalizeScriptMetadata(item?.metadata || {});
            return Array.isArray(metadata.params) && metadata.params.length > 0;
        },

        coerceScriptParamValue(param, rawValue) {
            const type = String(param?.type || 'string').trim().toLowerCase();
            if (type === 'boolean') return !!rawValue;

            const value = rawValue === null || rawValue === undefined ? '' : String(rawValue).trim();
            if (type === 'integer') {
                if (!/^-?\d+$/.test(value)) throw new Error(`Param "${param.name}" must be an integer`);
                const parsed = parseInt(value, 10);
                if (param.min !== undefined && parsed < Number(param.min)) throw new Error(`Param "${param.name}" must be >= ${param.min}`);
                if (param.max !== undefined && parsed > Number(param.max)) throw new Error(`Param "${param.name}" must be <= ${param.max}`);
                return parsed;
            }
            if (type === 'number') {
                const parsed = Number(value);
                if (Number.isNaN(parsed)) throw new Error(`Param "${param.name}" must be a number`);
                if (param.min !== undefined && parsed < Number(param.min)) throw new Error(`Param "${param.name}" must be >= ${param.min}`);
                if (param.max !== undefined && parsed > Number(param.max)) throw new Error(`Param "${param.name}" must be <= ${param.max}`);
                return parsed;
            }
            if (type === 'select') {
                if (Array.isArray(param.options) && param.options.length && !param.options.includes(value)) {
                    throw new Error(`Param "${param.name}" has invalid option`);
                }
                return value;
            }
            return value;
        },

        buildScriptRunParams(item) {
            const metadata = this.normalizeScriptMetadata(item?.metadata || {});
            const params = {};
            for (const param of metadata.params || []) {
                const rawValue = this.scriptParamForm[param.name];
                const type = String(param.type || 'string').toLowerCase();
                const textValue = type === 'boolean' ? rawValue : String(rawValue === null || rawValue === undefined ? '' : rawValue).trim();

                if ((type !== 'boolean' && !textValue) || (type === 'boolean' && rawValue === undefined)) {
                    if (param.required && (param.default === undefined || param.default === null || String(param.default).trim() === '')) {
                        throw new Error(`Missing required param: ${param.name}`);
                    }
                    if (param.default !== undefined && param.default !== null && String(param.default).trim() !== '') {
                        params[param.name] = this.coerceScriptParamValue(param, param.default);
                    }
                    continue;
                }
                params[param.name] = this.coerceScriptParamValue(param, rawValue);
            }
            return params;
        },

        openScriptRunDialog(item) {
            if (!item) return;
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            if (!this.isScriptSupportedForCurrentConnection(item)) {
                ElementPlus.ElMessage.warning(`${item.display_name || item.script_name} only supports: ${this.formatScriptPlatformLabel(item)}`);
                return;
            }
            this.pendingRunScriptName = String(item.script_name || '').trim();
            this.scriptParamForm = this.buildScriptParamDefaults(item);
            this.scriptRunDialogVisible = true;
        },

        closeScriptRunDialog() {
            this.scriptRunDialogVisible = false;
            this.scriptRunSubmitting = false;
            this.pendingRunScriptName = '';
            this.scriptParamForm = {};
        },

        async confirmRunScript() {
            const item = this.pendingRunScriptItem;
            if (!item) {
                this.closeScriptRunDialog();
                return;
            }
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            try {
                this.scriptRunSubmitting = true;
                const params = this.buildScriptRunParams(item);

                const commandText = `> [Run Script] ${item.display_name || item.script_name}`;
this.appendOutput(this.selectedId, commandText, 'command');

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/scripts/run`, {
                    method: 'POST',
                    headers: this.getTabScopedHeaders({'Content-Type': 'application/json'}),
                    body: JSON.stringify({script_name: item.script_name, params})
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to run script');
                const taskId = json.data && json.data.task_id;
                this.setActiveTask(this.selectedId, taskId || '');
                ElementPlus.ElMessage.success(`Run request submitted: ${item.display_name || item.script_name}`);
                this.closeScriptRunDialog();
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to run script');
            } finally {
                this.scriptRunSubmitting = false;
            }
        },

        async openRemoteScriptEditor(scriptName) {
            if (typeof this.openRemoteScriptEditorInternal === 'function') {
                await this.openRemoteScriptEditorInternal(scriptName);
            }
        },

        async createRemoteScriptPrompt() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            try {
                const baseDir = this.selectedScriptDirectory ? `${this.selectedScriptDirectory}/` : '';
                const {value} = await ElementPlus.ElMessageBox.prompt(
                    'Enter the new script filename',
                    'New Script',
                    {
                        confirmButtonText: 'Create',
                        cancelButtonText: 'Cancel',
                        inputValue: `${baseDir}new_script.py`,
                        inputPlaceholder: 'folder/new_script.py',
                    }
                );
                if (typeof this.openNewRemoteScriptEditor === 'function') {
                    this.openNewRemoteScriptEditor(value || `${baseDir}new_script.py`);
                }
            } catch (e) {
                if (e === 'cancel' || e === 'close') return;
            }
        },

        async createRemoteScriptFolderPrompt() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            try {
                const baseDir = this.selectedScriptDirectory ? `${this.selectedScriptDirectory}/` : '';
                const {value} = await ElementPlus.ElMessageBox.prompt(
                    'Enter the new folder path',
                    'New Folder',
                    {
                        confirmButtonText: 'Create',
                        cancelButtonText: 'Cancel',
                        inputValue: `${baseDir}new_folder`,
                        inputPlaceholder: 'folder/subfolder',
                    }
                );
                const directory = String(value || '').trim().replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
                if (!directory) {
                    ElementPlus.ElMessage.warning('Folder path is required');
                    return;
                }

                const res = await fetch('/api/scripts/folders', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({directory})
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to create folder');

                this.selectedScriptDirectory = directory;
                ElementPlus.ElMessage.success(`Folder created: ${directory}`);
                await this.loadScriptCatalog();
            } catch (e) {
                if (e === 'cancel' || e === 'close') return;
                ElementPlus.ElMessage.error(e.message || 'Failed to create folder');
            }
        },

        async renameServerScript(scriptName) {
            const normalized = String(scriptName || '').trim().replace(/\\/g, '/').replace(/^\/+/, '');
            if (!normalized) {
                ElementPlus.ElMessage.warning('Invalid script name');
                return;
            }

            try {
                const {value} = await ElementPlus.ElMessageBox.prompt(
                    'Enter the new file name (.py path)',
                    'Rename Script',
                    {
                        confirmButtonText: 'Rename',
                        cancelButtonText: 'Cancel',
                        inputValue: `${normalized}.py`,
                        inputPlaceholder: 'folder/new_name.py',
                    }
                );

                const newName = String(value || '').trim().replace(/\\/g, '/').replace(/^\/+/, '');
                if (!newName) {
                    ElementPlus.ElMessage.warning('New file name is required');
                    return;
                }

                const res = await fetch('/api/scripts/rename', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name: normalized, new_name: newName})
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to rename script');

                const renamedName = this.normalizeServerScriptFilename(json.data?.name || newName);
                ElementPlus.ElMessage.success(`Script renamed: ${renamedName}`);
                await this.loadScriptCatalog();
            } catch (e) {
                if (e === 'cancel' || e === 'close') return;
                ElementPlus.ElMessage.error(e.message || 'Failed to rename script');
            }
        },

        triggerScriptUpload() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            const input = document.getElementById('server-script-upload-input');
            if (input) {
                input.value = '';
                input.click();
            }
        },

async handleServerScriptUpload(event) {
    const input = event && event.target;
    const file = input && input.files && input.files[0];
    if (!file) return;

    if (!/\.py$/i.test(file.name || '')) {
        ElementPlus.ElMessage.warning('Only .py files are supported');
        input.value = '';
        return;
    }

    this.serverScriptUploadLoading = true;

    try {
        const formData = new FormData();
        formData.append('file', file, file.name);
        formData.append('directory', this.selectedScriptDirectory || '');

        const res = await fetch('/api/scripts/upload', {
            method: 'POST',
            body: formData
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
            throw new Error(json.message || 'Failed to upload script');
        }

        const uploadedName = this.normalizeServerScriptFilename(json.data?.name || file.name);
        ElementPlus.ElMessage.success(`Script uploaded: ${uploadedName}`);

        await this.loadScriptCatalog();

        if (typeof this.openRemoteScriptEditorInternal === 'function') {
            await this.openRemoteScriptEditorInternal(uploadedName);
        }
    } catch (e) {
        ElementPlus.ElMessage.error(e.message || 'Failed to upload script');
    } finally {
        this.serverScriptUploadLoading = false;
        if (input) input.value = '';
    }
},
        async deleteServerScript(scriptName) {
            const normalized = String(scriptName || '').trim().replace(/\\/g, '/').replace(/^\/+/, '').replace(/\.py$/i, '');
            if (!normalized) {
                ElementPlus.ElMessage.warning('Invalid script name');
                return;
            }
            try {
                await ElementPlus.ElMessageBox.confirm(`Delete "${normalized}.py"? This action cannot be undone.`, 'Delete Script', {
                    type: 'warning', confirmButtonText: 'Delete', cancelButtonText: 'Cancel'
                });
                const res = await fetch('/api/scripts/delete', {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name: normalized})
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to delete script');
                ElementPlus.ElMessage.success(`Deleted: ${normalized}.py`);
                await this.loadScriptCatalog();
            } catch (e) {
                if (e === 'cancel' || e === 'close') return;
                ElementPlus.ElMessage.error(e.message || 'Failed to delete script');
            }
        },

        async handleResourcesCommand(command) {
            if (command === 'jobs') {
                await this.openBackgroundJobsDialog();
                return;
            }
            if (command === 'scripts') {
                await this.openScriptLibraryDialog();
            }
        },
    },

    watch: {
        scriptRunDialogVisible(val) {
            if (!val) this.closeScriptRunDialog();
        },
    },
};