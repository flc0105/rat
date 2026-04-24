export default {
    data() {
        return {
            outputs: {},
            terminalJsonDialogVisible: false,
            terminalJsonDialogTitle: 'JSON Viewer',
            terminalJsonText: '',
            terminalJsonDisplayMode: 'raw',
            terminalJsonTableColumns: [],
            terminalJsonTableRows: [],
            terminalJsonFlatRows: [],
        }
    },


    methods: {
        isFileReadyLine(line) {
            const text = (line?.text || '')
            return text.startsWith('[File Ready]')
        },

        isCommandFinishedLine(line) {
            const text = (line?.text || '')
            return text.startsWith('[Command finished]') || text.startsWith('[命令结束]')
        },

        getTerminalInlineActionItems(lines, index) {
            const line = lines[index]
            if (!line) return []

            if (!this.isFileReadyLine(line)) return []

            const groupItems = this.getTerminalCommandGroupActionItems(lines, index) || []
            const usedKeysBefore = this.getUsedInlineActionKeysBeforeLine(lines, index)

            const previewItem = groupItems.find(item => {
                return item.type === 'preview' && !usedKeysBefore.has(item.key)
            })

            return previewItem ? [previewItem] : []
        },

        getTerminalTailActionItems(lines, index) {
            const line = lines[index]
            if (!line || !this.isCommandFinishedLine(line)) return []

            const groupItems = this.getTerminalCommandGroupActionItems(lines, index) || []
            const usedKeysUpToCurrent = this.getUsedInlineActionKeysUpToLine(lines, index)

            return groupItems.filter(item => !usedKeysUpToCurrent.has(item.key))
        },

        getUsedInlineActionKeysBeforeLine(lines, endIndexExclusive) {
            const used = new Set()

            for (let i = 0; i < endIndexExclusive; i += 1) {
                const line = lines[i]
                if (!this.isFileReadyLine(line)) continue

                const groupItems = this.getTerminalCommandGroupActionItems(lines, i) || []
                const previewItem = groupItems.find(item => item.type === 'preview' && !used.has(item.key))

                if (previewItem) {
                    used.add(previewItem.key)
                }
            }

            return used
        },

        getUsedInlineActionKeysUpToLine(lines, endIndexInclusive) {
            const used = new Set()

            for (let i = 0; i <= endIndexInclusive; i += 1) {
                const line = lines[i]
                if (!this.isFileReadyLine(line)) continue

                const groupItems = this.getTerminalCommandGroupActionItems(lines, i) || []
                const previewItem = groupItems.find(item => item.type === 'preview' && !used.has(item.key))

                if (previewItem) {
                    used.add(previewItem.key)
                }
            }

            return used
        },

        isTerminalJsonText(text) {
            const raw = String(text ?? '').trim();
            if (!raw) return false;

            if (
                (raw.startsWith('{') && raw.endsWith('}')) ||
                (raw.startsWith('[') && raw.endsWith(']'))
            ) {
                try {
                    JSON.parse(raw);
                    return true;
                } catch (e) {
                    return false;
                }
            }

            return false;
        },

        isTerminalJsonStartLine(text) {
            const raw = String(text ?? '').trim();
            return raw === '{' || raw === '[';
        },

        tryParseTerminalJsonBuffer(lines) {
            if (!Array.isArray(lines) || !lines.length) return null;

            const jsonText = lines.join('\n').trim();
            if (!jsonText) return null;

            try {
                JSON.parse(jsonText);
                return jsonText;
            } catch (e) {
                return null;
            }
        },

        inferLineKind(text) {
            const value = String(text ?? '');
            if (value.startsWith('> ')) return 'command';
            // if (value.startsWith('[发送失败]') || value.startsWith('[上传失败]')) return 'error';
            if (value.startsWith('[异步消息]') || value.startsWith('[Background]')) return 'info';
            if (value.startsWith('[命令结束]') || value.startsWith('[Command finished]')) {
                return /成功|Success/i.test(value) ? 'success' : 'error';
            }
            if (/failed|error|not found|denied|unable/i.test(value)) return 'error';
            if (/completed|success|saved|started|uploaded|downloaded|created|renamed|copied/i.test(value)) return 'success';
            if (/preparing|loading|refresh|connected|disconnected|warning/i.test(value)) return 'info';
            return 'default';
        },

        calculateTerminalJsonDelta(text) {
            const raw = String(text ?? '');
            let delta = 0;
            let inString = false;
            let escaped = false;

            for (let i = 0; i < raw.length; i++) {
                const ch = raw[i];

                if (escaped) {
                    escaped = false;
                    continue;
                }

                if (ch === '\\') {
                    if (inString) {
                        escaped = true;
                    }
                    continue;
                }

                if (ch === '"') {
                    inString = !inString;
                    continue;
                }

                if (inString) {
                    continue;
                }

                if (ch === '{' || ch === '[') {
                    delta += 1;
                } else if (ch === '}' || ch === ']') {
                    delta -= 1;
                }
            }

            return delta;
        },

        isTerminalCommandBoundaryLine(text) {
            const raw = String(text ?? '');
            return raw.startsWith('> ') || raw.startsWith('[Command finished]') || raw.startsWith('[命令结束]');
        },

        buildTerminalOutputLine(segment, kind = '', meta = {}) {
            const lineText = segment === '' ? ' ' : segment;
            const line = {
                text: lineText,
                kind: kind || this.inferLineKind(segment),
                isMultiline: false,
                isArtifactMessage: false,
                artifactInfo: null,
                isJsonMessage: false,
                jsonText: ''
            };

            if (meta && typeof meta === 'object') {
                if (meta.artifactInfo && meta.artifactInfo.artifact_id) {
                    line.isArtifactMessage = true;
                    line.artifactInfo = {...meta.artifactInfo};
                }

                if (meta.forceJson === true) {
                    line.isJsonMessage = true;
                    line.jsonText = String(meta.jsonText || '');
                }
            }

            return line;
        },

        isTerminalJsonPlainObject(value) {
            return !!value && typeof value === 'object' && !Array.isArray(value);
        },

        tryBuildTerminalJsonTableModel(jsonText) {
            const raw = String(jsonText || '').trim();
            if (!raw) return null;

            let parsed;
            try {
                parsed = JSON.parse(raw);
            } catch (e) {
                return null;
            }

            if (!Array.isArray(parsed) || !parsed.length) {
                return null;
            }

            if (!parsed.every(item => this.isTerminalJsonPlainObject(item))) {
                return null;
            }

            const firstKeys = Object.keys(parsed[0]);
            if (!firstKeys.length) {
                return null;
            }

            const sortedFirstKeys = [...firstKeys].sort();

            const hasSameStructure = parsed.every((item) => {
                const keys = Object.keys(item);
                if (keys.length !== firstKeys.length) return false;

                const sortedKeys = [...keys].sort();
                for (let i = 0; i < sortedFirstKeys.length; i++) {
                    if (sortedKeys[i] !== sortedFirstKeys[i]) return false;
                }
                return true;
            });

            if (!hasSameStructure) {
                return null;
            }

            return {
                columns: firstKeys.map((key) => ({
                    prop: key,
                    label: key
                })),
                rows: parsed.map((item) => {
                    const row = {};
                    firstKeys.forEach((key) => {
                        const value = item[key];
                        if (value === null || value === undefined) {
                            row[key] = '';
                        } else if (typeof value === 'object') {
                            row[key] = JSON.stringify(value);
                        } else {
                            row[key] = String(value);
                        }
                    });
                    return row;
                })
            };
        },

        tryBuildTerminalJsonFlatModel(jsonText) {
            const raw = String(jsonText || '').trim();
            if (!raw) return null;

            let parsed;
            try {
                parsed = JSON.parse(raw);
            } catch (e) {
                return null;
            }

            if (!this.isTerminalJsonPlainObject(parsed)) {
                return null;
            }

            const formatValue = (value) => {
                if (value === null || value === undefined) {
                    return '';
                }
                if (typeof value === 'object') {
                    try {
                        return JSON.stringify(value);
                    } catch (e) {
                        return String(value);
                    }
                }
                return String(value);
            };

            return Object.keys(parsed).map((key) => ({
                key,
                label: key,
                value: formatValue(parsed[key]),
            }));
        },

        openTerminalJsonDialog(line) {
            if (!line || !line.isJsonMessage) return;

            const jsonText = String(line.jsonText || '').trim();
            const tableModel = this.tryBuildTerminalJsonTableModel(jsonText);
            const flatModel = tableModel ? null : this.tryBuildTerminalJsonFlatModel(jsonText);

            this.terminalJsonDialogTitle = 'JSON Viewer';
            this.terminalJsonText = jsonText;

            if (tableModel) {
                this.terminalJsonDisplayMode = 'table';
                this.terminalJsonTableColumns = tableModel.columns;
                this.terminalJsonTableRows = tableModel.rows;
                this.terminalJsonFlatRows = [];
            } else if (flatModel) {
                this.terminalJsonDisplayMode = 'flat';
                this.terminalJsonTableColumns = [];
                this.terminalJsonTableRows = [];
                this.terminalJsonFlatRows = flatModel;
            } else {
                this.terminalJsonDisplayMode = 'raw';
                this.terminalJsonTableColumns = [];
                this.terminalJsonTableRows = [];
                this.terminalJsonFlatRows = [];
            }

            this.terminalJsonDialogVisible = true;
        },

        previewTerminalArtifact(line) {
            if (!line || !line.artifactInfo || !line.artifactInfo.artifact_id) {
                ElementPlus.ElMessage.warning('No preview available');
                return;
            }

            this.previewArtifact(line.artifactInfo);
        },

        // getTerminalCommandGroupStartIndex(lines, endIndex) {
        //     const safeLines = Array.isArray(lines) ? lines : [];
        //     for (let i = endIndex; i >= 0; i--) {
        //         if (safeLines[i] && safeLines[i].kind === 'command') {
        //             return i;
        //         }
        //     }
        //     return 0;
        // },

        getTerminalCommandGroupStartIndex(lines, endIndex) {
            const safeLines = Array.isArray(lines) ? lines : [];
            for (let i = endIndex; i >= 0; i--) {
                const line = safeLines[i];
                if (!line) continue;

                if (line.kind === 'command') {
                    return i;
                }

                if (i < endIndex && this.isCommandFinishedLine(line)) {
                    return i + 1;
                }
            }
            return 0;
        },

        getTerminalCommandGroupLines(lines, endIndex) {
            const safeLines = Array.isArray(lines) ? lines : [];
            if (!safeLines.length || endIndex < 0) return [];

            const startIndex = this.getTerminalCommandGroupStartIndex(safeLines, endIndex);
            return safeLines.slice(startIndex, endIndex + 1);
        },

        getTerminalCommandGroupActionItems(lines, endIndex) {
            const groupLines = this.getTerminalCommandGroupLines(lines, endIndex);
            const result = [];

            groupLines.forEach((item, itemIndex) => {
                if (!item) return;

                if (item.isArtifactMessage && item.artifactInfo && item.artifactInfo.artifact_id) {
                    result.push({
                        type: 'preview',
                        key: `preview:${item.artifactInfo.artifact_id}:${itemIndex}`,
                        line: item
                    });
                }

                if (item.isJsonMessage) {
                    result.push({
                        type: 'json',
                        key: `json:${endIndex}:${itemIndex}`,
                        line: item
                    });
                }
            });

            return result;
        },

        handleTerminalActionClick(actionItem) {
            if (!actionItem || !actionItem.line) return;

            if (actionItem.type === 'preview') {
                this.previewTerminalArtifact(actionItem.line);
                return;
            }

            if (actionItem.type === 'json') {
                this.openTerminalJsonDialog(actionItem.line);
            }
        },

        ensureOutputBucket(clientId) {
            if (!clientId) return;
            if (!this.outputs[clientId]) this.outputs[clientId] = [];
        },

        appendOutput(clientId, text, kind = '', meta = null) {
            if (!clientId) return;
            this.ensureOutputBucket(clientId);

            if (!this._terminalJsonBuffers) {
                this._terminalJsonBuffers = {};
            }

            const raw = String(text ?? '');
            const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

            if (this.isTerminalJsonText(normalized.trim())) {
                const line = this.buildTerminalOutputLine(normalized.trim(), kind, {
                    ...(meta || {}),
                    forceJson: true,
                    jsonText: normalized.trim()
                });
                this.outputs[clientId].push(line);
                this.scrollToBottom();
                return;
            }

            const segments = normalized.split('\n');

            const pushNormalLine = (segment, lineKind = kind, lineMeta = meta) => {
                this.outputs[clientId].push(
                    this.buildTerminalOutputLine(segment, lineKind, lineMeta)
                );
            };

            const flushJsonBuffer = (buffer) => {
                const jsonText = this.tryParseTerminalJsonBuffer(buffer.lines);

                if (!jsonText) {
                    buffer.lines.forEach((line) => pushNormalLine(line, buffer.kind, buffer.meta));
                    return;
                }

                buffer.lines.forEach((line, index) => {
                    const isLast = index === buffer.lines.length - 1;
                    this.outputs[clientId].push(
                        this.buildTerminalOutputLine(line, buffer.kind || kind, {
                            ...(buffer.meta || {}),
                            forceJson: isLast,
                            jsonText: isLast ? jsonText : ''
                        })
                    );
                });
            };

            segments.forEach((segment) => {
                const trimmed = String(segment ?? '').trim();
                let buffer = this._terminalJsonBuffers[clientId];

                if (buffer) {
                    if (this.isTerminalCommandBoundaryLine(segment)) {
                        flushJsonBuffer(buffer);
                        this._terminalJsonBuffers[clientId] = null;
                        pushNormalLine(segment);
                        return;
                    }

                    buffer.lines.push(segment);
                    buffer.depth += this.calculateTerminalJsonDelta(segment);

                    if (buffer.depth <= 0) {
                        flushJsonBuffer(buffer);
                        this._terminalJsonBuffers[clientId] = null;
                    }
                    return;
                }

                if (this.isTerminalJsonStartLine(trimmed)) {
                    this._terminalJsonBuffers[clientId] = {
                        kind: kind || '',
                        meta: meta ? {...meta} : null,
                        lines: [segment],
                        depth: this.calculateTerminalJsonDelta(segment)
                    };

                    if (this._terminalJsonBuffers[clientId].depth <= 0) {
                        flushJsonBuffer(this._terminalJsonBuffers[clientId]);
                        this._terminalJsonBuffers[clientId] = null;
                    }
                    return;
                }

                pushNormalLine(segment);
            });

            this.scrollToBottom();
        },

        clearOutput() {
            if (this.selectedId) this.outputs[this.selectedId] = [];
        },

        scrollToBottom() {
            this.$nextTick(() => {
                const terminalOutput = this.$refs.terminalOutputRef;

                if (
                    terminalOutput &&
                    typeof terminalOutput.scrollToBottom === 'function'
                ) {
                    terminalOutput.scrollToBottom();
                }
            });
        },
    },

    computed: {
        currentOutputLines() {
            return this.outputs[this.selectedId] || [];
        },
    },

    watch: {
        terminalJsonDialogVisible(val) {
            if (!val) {
                this.terminalJsonDialogTitle = 'JSON Viewer';
                this.terminalJsonText = '';
                this.terminalJsonDisplayMode = 'raw';
                this.terminalJsonTableColumns = [];
                this.terminalJsonTableRows = [];
                this.terminalJsonFlatRows = [];
            }
        },
    },
}