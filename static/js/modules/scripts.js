window.AppScriptsModule = {
    data() {
        return {
            scriptLibraryDialogVisible: false,
            scriptLibraryLoading: false,
            scriptCatalogItems: [],
            selectedScriptName: '',
            scriptRunSubmitting: false,
            scriptParamForm: {},
        };
    },

    computed: {
        scriptTreeData() {
            const root = [];
            const ensureNode = (children, key, label, path, isScript = false, item = null) => {
                const existing = children.find(node => node.key === key);
                if (existing) return existing;
                const node = {key, label, path, children: [], isScript, item};
                children.push(node);
                return node;
            };

            for (const item of this.scriptCatalogItems || []) {
                const path = String(item.path || `${item.script_name || ''}.py`).replace(/^\/+/, '');
                const parts = path.split('/').filter(Boolean);
                let currentChildren = root;
                let currentPath = '';
                parts.forEach((part, index) => {
                    currentPath = currentPath ? `${currentPath}/${part}` : part;
                    const isLeaf = index === parts.length - 1;
                    const key = isLeaf ? `script:${item.script_name}` : `dir:${currentPath}`;
                    const label = isLeaf ? (item.display_name || part.replace(/\.py$/i, '')) : part;
                    const node = ensureNode(currentChildren, key, label, currentPath, isLeaf, isLeaf ? item : null);
                    currentChildren = node.children;
                });
            }

            const sortNodes = (nodes) => {
                nodes.sort((a, b) => {
                    if (!!a.isScript !== !!b.isScript) return a.isScript ? 1 : -1;
                    return String(a.label || '').localeCompare(String(b.label || ''));
                });
                nodes.forEach(node => sortNodes(node.children || []));
                return nodes;
            };

            return sortNodes(root);
        },

        selectedScriptItem() {
            const target = String(this.selectedScriptName || '').trim();
            return (this.scriptCatalogItems || []).find(item => String(item.script_name || '').trim() === target) || null;
        },

        selectedScriptMetadata() {
            const item = this.selectedScriptItem;
            if (!item) {
                return {name: '', display_name: '', description: '', platforms: [], params: [], category: '', tags: []};
            }
            return this.normalizeScriptMetadata(item.metadata || {});
        },

        selectedScriptParamSpecs() {
            return Array.isArray(this.selectedScriptMetadata.params) ? this.selectedScriptMetadata.params : [];
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

        async loadScriptCatalog() {
            this.scriptLibraryLoading = true;
            try {
                const res = await fetch('/api/scripts/catalog');
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load script catalog');
                }
                this.scriptCatalogItems = Array.isArray(json.data) ? json.data : [];
                if (!this.selectedScriptName && this.scriptCatalogItems.length > 0) {
                    this.selectScriptItem(this.scriptCatalogItems[0]);
                } else if (this.selectedScriptName) {
                    const found = this.scriptCatalogItems.find(item => item.script_name === this.selectedScriptName);
                    if (found) {
                        this.selectScriptItem(found);
                    } else if (this.scriptCatalogItems.length > 0) {
                        this.selectScriptItem(this.scriptCatalogItems[0]);
                    }
                }
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to load script catalog');
            } finally {
                this.scriptLibraryLoading = false;
            }
        },

        handleScriptTreeNodeClick(node) {
            if (node && node.isScript && node.item) {
                this.selectScriptItem(node.item);
            }
        },

        selectScriptItem(item) {
            if (!item) return;
            this.selectedScriptName = String(item.script_name || '').trim();
            this.scriptParamForm = this.buildScriptParamDefaults(item);
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
                ? this.normalizeClientPlatform(this.currentConnection?.os_type || this.currentConnection?.platform || this.currentConnection?.system || this.currentConnection?.os || '')
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

        async runSelectedScript() {
            const item = this.selectedScriptItem;
            if (!item) {
                ElementPlus.ElMessage.warning('Please select a script');
                return;
            }
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            if (!this.isScriptSupportedForCurrentConnection(item)) {
                ElementPlus.ElMessage.warning(`${item.display_name || item.script_name} only supports: ${this.formatScriptPlatformLabel(item)}`);
                return;
            }
            try {
                this.scriptRunSubmitting = true;
                const params = this.buildScriptRunParams(item);
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/scripts/run`, {
                    method: 'POST',
                    headers: this.getTabScopedHeaders({'Content-Type': 'application/json'}),
                    body: JSON.stringify({script_name: item.script_name, params})
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to run script');
                }
                const taskId = json.data && json.data.task_id;
                this.setActiveTask(this.selectedId, taskId || '');
                ElementPlus.ElMessage.success(`Run request submitted: ${item.display_name || item.script_name}`);
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
    },

    watch: {},
};
