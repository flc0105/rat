export default {
    data() {
        return {
            previewDialogVisible: false,
            previewLoading: false,
            previewType: '',
            previewTitle: '',
            previewUrl: '',
            previewText: '',
            previewEditMode: false,  // 是否处于编辑模式
            previewSaving: false,    // 保存中状态
            previewFilePath: '',     // 当前编辑的文件路径
            previewOriginalContent: '',  // 原始内容副本（用于取消编辑时恢复）
            previewTruncated: false,     // 是否被截断
            previewFileSize: '',         // 文件大小显示
            previewFileEncoding: 'UTF-8', // 文件编码
            previewSource: '',  // 'remote_file' 或 'artifact'
            previewArtifactInfo: null,
            previewImageInfo: null,
            previewImageInfoDialogVisible: false,
            previewDetectedLanguage: 'Plain Text', // Monaco 识别语言

        }
    },
    methods: {
        monacoEditor: null,

        initMonacoEditor(content, readOnly = true) {
            if (this.monacoEditor) {
                this.monacoEditor.dispose();
                this.monacoEditor = null;
            }

            const container = document.getElementById('monaco-editor-container');
            if (!container) return;

            // 等待容器渲染完成
            this.$nextTick(() => {
                require.config({paths: {vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs'}});
                require(['vs/editor/editor.main'], () => {
                    // 根据文件扩展名推断语言
                    const lang = this.getLanguageFromFilename(this.previewTitle);
                    this.previewDetectedLanguage = this.getLanguageDisplayName(lang);

                    this.monacoEditor = monaco.editor.create(container, {
                        value: content,
                        language: lang,
                        theme: 'vs',
                        readOnly: readOnly,
                        automaticLayout: true,
                        fontSize: 13,
                        fontFamily: 'Monaco, Menlo, "Ubuntu Mono", Consolas, monospace',
                        lineNumbers: 'on',
                        minimap: {enabled: false},
                        scrollBeyondLastLine: false,
                        wordWrap: 'on',
                        renderWhitespace: 'boundary',
                        tabSize: 4,
                        insertSpaces: true,
                    });
                });
            });
        },

        // 根据文件名获取语言
        getLanguageFromFilename(filename) {
            if (!filename) return 'plaintext';

            const ext = filename.split('.').pop().toLowerCase();
            const langMap = {
                'py': 'python',
                'js': 'javascript',
                'ts': 'typescript',
                'html': 'html',
                'css': 'css',
                'json': 'json',
                'xml': 'xml',
                'yaml': 'yaml',
                'yml': 'yaml',
                'md': 'markdown',
                'sh': 'shell',
                'bash': 'shell',
                'sql': 'sql',
                'java': 'java',
                'c': 'c',
                'cpp': 'cpp',
                'h': 'cpp',
                'go': 'go',
                'rs': 'rust',
                'php': 'php',
                'rb': 'ruby',
                'pl': 'perl',
                'lua': 'lua',
                'ini': 'ini',
                'conf': 'ini',
                'log': 'log',
                'txt': 'plaintext',
                'ps1': 'powershell',
            };

            return langMap[ext] || 'plaintext';
        },

        getLanguageDisplayName(language) {
            const langNameMap = {
                plaintext: 'Plain Text',
                python: 'Python',
                javascript: 'JavaScript',
                typescript: 'TypeScript',
                html: 'HTML',
                css: 'CSS',
                json: 'JSON',
                xml: 'XML',
                yaml: 'YAML',
                markdown: 'Markdown',
                shell: 'Shell',
                sql: 'SQL',
                java: 'Java',
                c: 'C',
                cpp: 'C++',
                go: 'Go',
                rust: 'Rust',
                php: 'PHP',
                ruby: 'Ruby',
                perl: 'Perl',
                lua: 'Lua',
                ini: 'INI',
                log: 'Log',
                powershell: 'Powershell'
            };

            const key = String(language || '').trim().toLowerCase();
            return langNameMap[key] || key || 'Plain Text';
        },

        // 获取编辑器内容
        getMonacoEditorContent() {
            if (this.monacoEditor) {
                return this.monacoEditor.getValue();
            }
            return this.previewText;
        },

        // 设置编辑器只读状态
        setMonacoEditorReadOnly(readOnly) {
            if (this.monacoEditor) {
                this.monacoEditor.updateOptions({readOnly: readOnly});
            }
        },

        enterEditMode() {
            this.previewOriginalContent = this.previewText;
            this.previewEditMode = true;
            // 切换编辑器为可编辑模式
            this.setMonacoEditorReadOnly(false);
        },

        cancelEditMode() {
            this.previewEditMode = false;
            // 恢复原始内容
            if (this.monacoEditor) {
                this.monacoEditor.setValue(this.previewOriginalContent);
            }
            this.previewText = this.previewOriginalContent;
            this.previewOriginalContent = '';
            // 切换编辑器为只读模式
            this.setMonacoEditorReadOnly(true);
        },

        clearPreviewContent() {
            if (this.previewType !== 'text') {
                ElementPlus.ElMessage.warning('Only text content can be cleared');
                return;
            }
            if (!this.previewEditMode) {
                ElementPlus.ElMessage.warning('Please enter edit mode first');
                return;
            }
            if (this.monacoEditor) {
                this.monacoEditor.setValue('');
            }
            this.previewText = '';
        },

        async previewRemoteEntry(row) {
            if (!row || !row.path || row.is_dir || row.is_parent_entry) {
                ElementPlus.ElMessage.warning('Please select a file');
                return;
            }

            // 记录文件路径
            this.previewFilePath = row.path;
            this.previewSource = 'remote_file';  // 标记来源


            await this.loadPreviewPayload(
                () => fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/preview`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({path: row.path})
                }),
                row.name || 'File Preview'
            );

            // 重置编辑模式
            this.previewEditMode = false;
        },

        async previewArtifact(row) {
            if (!row || !row.artifact_id) {
                ElementPlus.ElMessage.warning('Invalid artifact');
                return;
            }

            this.previewSource = 'artifact';  // 标记来源
            this.previewFilePath = row.artifact_id;  // 存储 artifact_id 而不是路径
            this.previewArtifactInfo = row;  // 保存 artifact 信息，用于后续刷新


            await this.loadPreviewPayload(
                () => fetch(`/api/artifacts/${encodeURIComponent(row.artifact_id)}/preview`),
                row.original_name || row.stored_name || 'Artifact Preview'
            );

            this.previewEditMode = false;

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
        },

        async saveEditedContent() {
            const currentContent = this.getMonacoEditorContent();

            // 根据来源选择不同的保存方式
            if (this.previewSource === 'remote_file') {
                await this.saveToRemoteFile(currentContent);
            } else if (this.previewSource === 'artifact') {
                await this.saveToArtifact(currentContent);
            } else if (this.previewSource === 'background_job') {
                await this.saveToBackgroundJob(currentContent);
            } else if (this.previewSource === 'server_script') {
                await this.saveToServerScript(currentContent);
            } else {
                ElementPlus.ElMessage.warning('Unknown preview source');
            }
        },

        async saveToServerScript(content) {
            if (!this.previewFilePath) {
                ElementPlus.ElMessage.warning('Invalid script name');
                return;
            }

            this.previewSaving = true;

            try {
                const res = await fetch('/api/scripts/save', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        name: this.previewFilePath,
                        content: content
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to save script');
                }

                ElementPlus.ElMessage.success('Script saved successfully');

                this.previewOriginalContent = content;
                this.previewText = content;
                this.previewEditMode = false;
                this.setMonacoEditorReadOnly(true);

                if (this.scriptLibraryDialogVisible && typeof this.loadScriptCatalog === 'function') {
                    await this.loadScriptCatalog();
                }
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to save script');
            } finally {
                this.previewSaving = false;
            }
        },

        async saveToBackgroundJob(content) {
            if (!this.previewFilePath) {
                ElementPlus.ElMessage.warning('Invalid job name');
                return;
            }

            this.previewSaving = true;

            try {
                const res = await fetch('/api/jobs/save', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        name: this.previewFilePath,
                        content: content
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to save job');
                }

                ElementPlus.ElMessage.success('Job saved successfully');

                this.previewOriginalContent = content;
                this.previewText = content;
                this.previewEditMode = false;
                this.setMonacoEditorReadOnly(true);

                // 刷新 Jobs 列表
                if (this.backgroundJobsDialogVisible) {
                    await this.loadBackgroundJobModules();
                }

            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to save job');
            } finally {
                this.previewSaving = false;
            }
        },

        async saveToRemoteFile(content) {
            if (!this.selectedId || !this.previewFilePath) {
                ElementPlus.ElMessage.warning('Invalid file path');
                return;
            }

            this.previewSaving = true;

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/save`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        path: this.previewFilePath,
                        content: content,
                        encoding: 'utf-8'
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to save file');
                }

                ElementPlus.ElMessage.success('File saved successfully');

                this.previewOriginalContent = content;
                this.previewText = content;
                this.previewEditMode = false;
                this.setMonacoEditorReadOnly(true);

                if (this.remoteFilesDialogVisible) {
                    await this.refreshRemoteDirectory();
                }

            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to save file');
            } finally {
                this.previewSaving = false;
            }
        },

        async saveToArtifact(content) {
            if (!this.previewFilePath) {
                ElementPlus.ElMessage.warning('Invalid artifact');
                return;
            }

            this.previewSaving = true;

            try {
                const res = await fetch(`/api/artifacts/${encodeURIComponent(this.previewFilePath)}/content`, {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        content: content,
                        encoding: this.previewFileEncoding || 'utf-8'
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to save artifact');
                }

                ElementPlus.ElMessage.success('Artifact saved successfully');

                // 更新本地内容
                this.previewOriginalContent = content;
                this.previewText = content;
                this.previewEditMode = false;
                this.setMonacoEditorReadOnly(true);

                // 更新文件大小显示
                if (json.data && json.data.size) {
                    this.previewFileSize = this.formatBytes(json.data.size);
                }

                // 刷新 Artifact 列表
                if (this.artifactDialogVisible) {
                    await this.loadArtifacts();
                }

                // 触发 artifact_created 事件，通知其他组件
                if (this.previewArtifactInfo) {
                    // 更新本地 artifact 信息
                    this.previewArtifactInfo.size = json.data?.size || this.previewArtifactInfo.size;
                }

            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to save artifact');
            } finally {
                this.previewSaving = false;
            }
        },

        async loadPreviewPayload(fetcher, fallbackTitle = 'File Preview') {
            this.previewDialogVisible = true;
            this.previewLoading = true;
            this.resetPreviewState();
            this.previewEditMode = false;
            this.previewSaving = false;
            this.previewOriginalContent = '';
            this.previewImageInfo = null;
            this.previewImageInfoDialogVisible = false;

            try {
                const res = await fetcher();
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Preview failed');
                }

                const data = json.data || {};
                this.previewType = data.type || 'unsupported';
                this.previewTitle = data.name || fallbackTitle;
                this.previewImageInfo = data.image_info || null;

                if (this.previewType === 'image') {
                    this.previewUrl = data.url || '';
                } else if (this.previewType === 'text') {
                    this.previewText = data.content || '';
                    this.previewTruncated = data.truncated || false;
                    this.previewOriginalContent = this.previewText;
                    this.previewFileSize = this.formatBytes(data.size || this.previewText.length);
                    this.previewFileEncoding = this.detectEncoding(this.previewText);
                    this.previewDetectedLanguage = this.getLanguageDisplayName(this.getLanguageFromFilename(this.previewTitle));


                    // 等待 DOM 渲染完成后初始化编辑器
                    this.$nextTick(() => {
                        this.initMonacoEditor(this.previewText, true);
                    });
                }
            } catch (e) {
                this.previewDialogVisible = false;
                ElementPlus.ElMessage.error(e.message || 'Preview failed');
            } finally {
                this.previewLoading = false;
            }
        },

        detectEncoding(text) {
            // 简单的编码检测
            if (!text) return 'UTF-8';

            // 检测是否包含常见的中文字符
            if (/[\u4e00-\u9fa5]/.test(text)) {
                // 简单判断：如果内容看起来正常，就是 UTF-8
                return 'UTF-8';
            }

            // 检测是否包含 BOM
            if (text.charCodeAt(0) === 0xFEFF) {
                return 'UTF-8 with BOM';
            }

            return 'UTF-8';
        },

        async copyPreviewText() {
            const content = this.getMonacoEditorContent();
            if (!content) {
                ElementPlus.ElMessage.warning('No content to copy');
                return;
            }

            try {
                await navigator.clipboard.writeText(content);
                ElementPlus.ElMessage.success('Content copied');
            } catch (e) {
                ElementPlus.ElMessage.error('Failed to copy content');
            }
        },

        openPreviewImageInfoDialog() {
            if (!this.previewImageInfo) {
                ElementPlus.ElMessage.warning('No image info available');
                return;
            }
            this.previewImageInfoDialogVisible = true;
        },

        formatPreviewImageInfo(info) {
            if (!info || typeof info !== 'object') {
                return {
                    basic: [],
                    exif: [],
                    other: [],
                };
            }

            const basicFieldOrder = [
                ['name', 'Name'],
                ['width', 'Width'],
                ['height', 'Height'],
                ['size', 'Dimensions'],
                ['format', 'Format'],
                ['mode', 'Color Mode'],
                ['file_size_bytes', 'File Size (Bytes)'],
                ['artifact_id', 'Artifact ID'],
            ];

            const exifFieldOrder = [
                ['make', 'Camera Make'],
                ['model', 'Camera Model'],
                ['lens_model', 'Lens Model'],
                ['datetime_original', 'Date Taken'],
                ['exposure_time', 'Exposure Time'],
                ['f_number', 'F Number'],
                ['iso', 'ISO'],
                ['focal_length', 'Focal Length'],
                ['color_space', 'Color Space'],
                ['software', 'Software'],
                ['user_comment', 'User Comment'],
            ];

            const formatValue = (value) => {
                if (value === null || value === undefined || value === '') return '-';
                if (Array.isArray(value)) return value.join(', ');
                if (typeof value === 'object') {
                    try {
                        return JSON.stringify(value);
                    } catch (e) {
                        return String(value);
                    }
                }
                return String(value);
            };

            const usedKeys = new Set();
            const basic = [];
            const exif = [];
            const other = [];

            basicFieldOrder.forEach(([key, label]) => {
                if (key in info) {
                    basic.push({
                        key,
                        label,
                        value: formatValue(info[key]),
                    });
                    usedKeys.add(key);
                }
            });

            exifFieldOrder.forEach(([key, label]) => {
                if (key in info) {
                    exif.push({
                        key,
                        label,
                        value: formatValue(info[key]),
                    });
                    usedKeys.add(key);
                }
            });

            Object.keys(info).forEach((key) => {
                if (usedKeys.has(key)) return;
                other.push({
                    key,
                    label: key,
                    value: formatValue(info[key]),
                });
            });

            return {
                basic,
                exif,
                other,
            };
        },

        openPreviewOriginal() {
            if (!this.previewUrl) {
                ElementPlus.ElMessage.warning('No image available');
                return;
            }
            window.open(this.previewUrl, '_blank');
        },

        buildServerScriptTemplate(scriptName = 'new_script.py') {
            const normalizedScriptName = String(scriptName || 'new_script.py').trim().replace(/\\/g, '/').replace(/^\/+/, '') || 'new_script.py';
            const classBaseName = normalizedScriptName
                .replace(/\.py$/i, '')
                .split('/')
                .pop()
                .split(/[^a-zA-Z0-9]+/)
                .filter(Boolean)
                .map(part => part.charAt(0).toUpperCase() + part.slice(1))
                .join('') || 'NewScript';

            return `SCRIPT_METADATA = {
    "name": "${normalizedScriptName.replace(/\.py$/i, '')}",
    "display_name": "${classBaseName}",
    "description": "Describe what this script does",
    "platforms": ["common"],
    "category": "General",
    "params": [
        {
            "name": "example",
            "type": "string",
            "required": False,
            "default": "",
            "description": "Example parameter"
        }
    ]
}

value = kwargs.get('example', '')
print(value)

# kwargs will be injected by the script runner.
# Example:
# value = kwargs.get('example', '')
`;
        },

        openNewRemoteScriptEditor(scriptName = 'new_script.py') {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            let normalizedScriptName = String(scriptName || '').trim().replace(/\\/g, '/').replace(/^\/+/, '');
            if (!normalizedScriptName) {
                normalizedScriptName = 'new_script.py';
            }
            if (!/\.py$/i.test(normalizedScriptName)) {
                normalizedScriptName = `${normalizedScriptName}.py`;
            }

            const content = this.buildServerScriptTemplate(normalizedScriptName);

            this.previewSource = 'server_script';
            this.previewFilePath = normalizedScriptName;
            this.previewTitle = normalizedScriptName;
            this.previewText = content;
            this.previewOriginalContent = content;
            this.previewType = 'text';
            this.previewTruncated = false;
            this.previewFileSize = this.formatBytes(content.length);
            this.previewFileEncoding = 'UTF-8';
            this.previewEditMode = true;
            this.previewDialogVisible = true;

            this.$nextTick(() => {
                this.initMonacoEditor(content, false);
            });
        },

        openNewRemoteJobEditor(scriptName = 'new_job.py') {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            const normalizedScriptName = this.normalizeServerJobFilename(scriptName);
            const content = this.buildServerJobTemplate(normalizedScriptName);

            this.previewSource = 'background_job';
            this.previewFilePath = normalizedScriptName;
            this.previewTitle = normalizedScriptName;
            this.previewText = content;
            this.previewOriginalContent = content;
            this.previewType = 'text';
            this.previewTruncated = false;
            this.previewFileSize = this.formatBytes(content.length);
            this.previewFileEncoding = 'UTF-8';
            this.previewDetectedLanguage = this.getLanguageDisplayName(this.getLanguageFromFilename(this.previewTitle));

            this.previewEditMode = true;
            this.previewDialogVisible = true;

            this.$nextTick(() => {
                this.initMonacoEditor(content, false);
            });
        },

        async openRemoteScriptEditorInternal(scriptName) {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            let normalizedScriptName = String(scriptName || '').trim().replace(/\\/g, '/').replace(/^\/+/, '');
            if (!normalizedScriptName) {
                ElementPlus.ElMessage.warning('Invalid script name');
                return;
            }
            if (!/\.py$/i.test(normalizedScriptName)) {
                normalizedScriptName = `${normalizedScriptName}.py`;
            }

            try {
                const res = await fetch(`/api/scripts/download?name=${encodeURIComponent(normalizedScriptName)}`);
                if (!res.ok) {
                    throw new Error(`Failed to load script: ${res.statusText}`);
                }
                const content = await res.text();

                this.previewSource = 'server_script';
                this.previewFilePath = normalizedScriptName;
                this.previewTitle = normalizedScriptName;
                this.previewText = content;
                this.previewOriginalContent = content;
                this.previewType = 'text';
                this.previewTruncated = false;
                this.previewFileSize = this.formatBytes(content.length);
                this.previewFileEncoding = 'UTF-8';
                this.previewDetectedLanguage = this.getLanguageDisplayName(this.getLanguageFromFilename(this.previewTitle));

                this.previewEditMode = true;

                this.previewDialogVisible = true;

                this.$nextTick(() => {
                    this.initMonacoEditor(content, false);
                });
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to load script');
            }
        },

        async openRemoteJobEditor(scriptName) {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            let normalizedScriptName = this.normalizeServerJobFilename(scriptName, 'new_job.py');
            if (!normalizedScriptName) {
                ElementPlus.ElMessage.warning('Invalid script name');
                return;
            }

            try {
                const res = await fetch(`/api/jobs/download?name=${encodeURIComponent(normalizedScriptName)}`);
                if (!res.ok) {
                    throw new Error(`Failed to load job: ${res.statusText}`);
                }
                const content = await res.text();

                this.previewSource = 'background_job';
                this.previewFilePath = normalizedScriptName;
                this.previewTitle = normalizedScriptName;
                this.previewText = content;
                this.previewOriginalContent = content;
                this.previewType = 'text';
                this.previewTruncated = false;
                this.previewFileSize = this.formatBytes(content.length);
                this.previewFileEncoding = 'UTF-8';
                this.previewDetectedLanguage = this.getLanguageDisplayName(this.getLanguageFromFilename(this.previewTitle));

                this.previewEditMode = true;

                this.previewDialogVisible = true;

                this.$nextTick(() => {
                    this.initMonacoEditor(content, false);
                });
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to load job');
            }
        },

        resetPreviewState() {
            this.previewType = '';
            this.previewTitle = '';
            this.previewUrl = '';
            this.previewText = '';
            this.previewOriginalContent = '';
            this.previewEditMode = false;
            this.previewSaving = false;
            this.previewArtifactInfo = null;
            this.previewImageInfo = null;
            this.previewImageInfoDialogVisible = false;
            this.previewDetectedLanguage = 'Plain Text';
        },
    },

    computed: {
        previewSourceLabel() {
            if (this.previewSource === 'remote_file') {
                return 'Remote File';
            }
            if (this.previewSource === 'artifact') {
                return 'Artifact';
            }
            if (this.previewSource === 'background_job') {
                return 'Background Job';
            }
            if (this.previewSource === 'server_script') {
                return 'Server Script';
            }
            return 'Unknown';
        },
    },

    watch: {
        previewDialogVisible(val) {
            if (!val) this.resetPreviewState();
        },

    }
}