window.AppUtilsModule = {
    methods: {
        ensureTabId() {
            const key = 'rat_web_tab_id';
            let tabId = '';

            try {
                tabId = String(sessionStorage.getItem(key) || '').trim();
            } catch (e) {
                tabId = '';
            }

            if (!tabId) {
                if (window.crypto && typeof window.crypto.randomUUID === 'function') {
                    tabId = window.crypto.randomUUID();
                } else {
                    tabId = `tab_${Date.now()}_${Math.random().toString(16).slice(2)}`;
                }

                try {
                    sessionStorage.setItem(key, tabId);
                } catch (e) {
                }
            }

            this.tabId = tabId;
            return tabId;
        },

        getTabScopedHeaders(extra = {}) {
            const headers = {...extra};
            if (this.tabId) {
                headers['X-Tab-Id'] = this.tabId;
            }
            return headers;
        },

        toggleCommandExecutionOutputSort() {
            this.commandExecutionOutputSortOrder = this.commandExecutionOutputSortOrder === 'asc' ? 'desc' : 'asc';
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
        },

        formatOsLabel(osType, osVer) {
            const type = osType || 'Unknown';
            return osVer ? `${type}` : type;
        },

        formatAddress(addr) {
            if (!addr) return '-';
            const raw = String(addr);
            const parts = raw.split(':');
            if (parts.length >= 2) return parts.slice(0, -1).join(':') || raw;
            return raw;
        },

        buildPromptLabel(conn) {
            if (!conn) return '$';
            return conn.hostname || 'host';
        },

        ensureOutputBucket(clientId) {
            if (!clientId) return;
            if (!this.outputs[clientId]) this.outputs[clientId] = [];
        },

        inferLineKind(text) {
            const value = String(text ?? '');
            if (value.startsWith('> ')) return 'command';
            if (value.startsWith('[发送失败]') || value.startsWith('[上传失败]')) return 'error';
            if (value.startsWith('[异步消息]') || value.startsWith('[Background]')) return 'info';
            if (value.startsWith('[命令结束]') || value.startsWith('[Command finished]')) {
                return /成功|Success/i.test(value) ? 'success' : 'error';
            }
            if (/failed|error|not found|denied|unable/i.test(value)) return 'error';
            if (/completed|success|saved|started|uploaded|downloaded|created|renamed|copied/i.test(value)) return 'success';
            if (/preparing|loading|refresh|connected|disconnected|warning/i.test(value)) return 'info';
            return 'default';
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

            // const hasSameStructure = parsed.every((item) => {
            //     const keys = Object.keys(item);
            //     if (keys.length !== firstKeys.length) return false;
            //     for (let i = 0; i < firstKeys.length; i++) {
            //         if (keys[i] !== firstKeys[i]) return false;
            //     }
            //     return true;
            // });

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

        getTerminalCommandGroupStartIndex(lines, endIndex) {
            const safeLines = Array.isArray(lines) ? lines : [];
            for (let i = endIndex; i >= 0; i--) {
                if (safeLines[i] && safeLines[i].kind === 'command') {
                    return i;
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

        shouldRenderTerminalCommandActions(lines, index) {
            const safeLines = Array.isArray(lines) ? lines : [];
            if (!safeLines.length || index < 0 || index >= safeLines.length) return false;

            const isLastLine = index === safeLines.length - 1;
            const nextIsCommand = !isLastLine && safeLines[index + 1] && safeLines[index + 1].kind === 'command';

            if (!isLastLine && !nextIsCommand) {
                return false;
            }

            return this.getTerminalCommandGroupActionItems(safeLines, index).length > 0;
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
            Vue.nextTick(() => {
                const el = this.$refs.terminalRef;
                if (el) el.scrollTop = el.scrollHeight;
            });
        },

        formatBytes(size) {
            const value = Number(size || 0);
            if (value < 1024) return `${value} B`;
            if (value < 1024 * 1024) return `${(value / 1024).toFixed(2)} KB`;
            if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(2)} MB`;
            return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`;
        },

        buildBackgroundJobStateTagType(state) {
            const value = String(state || '').toLowerCase();
            if (value === 'running') return 'success';
            if (value === 'stopping') return 'warning';
            if (value === 'error') return 'danger';
            return 'info';
        },

        formatBackgroundJobDuration(totalSeconds) {
            const seconds = Number(totalSeconds || 0);
            if (!seconds) return '0s';

            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const remain = seconds % 60;

            const parts = [];
            if (hours) parts.push(`${hours}h`);
            if (minutes) parts.push(`${minutes}m`);
            if (remain || !parts.length) parts.push(`${remain}s`);

            return parts.join(' ');
        },

        formatBackgroundJobMessageText(text) {
            const raw = String(text || '').trim();
            return raw.replace(/^\[[^\]]*?client=[^\]]*?\]\s*/, '');
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

        buildArtifactTypeLabel(item) {
            const artifactType = String(item && item.artifact_type || '').trim();
            if (artifactType === 'http_uploads') return 'http_uploads';
            if (artifactType === 'downloads') return 'downloads';
            if (artifactType === 'previews') return 'previews';
            return artifactType || '-';
        },

        formatDateTimeStandard(value) {
            const text = String(value || '').trim();
            if (!text) return '-';

            const normalized = text.replace('T', ' ').split('.')[0];
            return normalized || '-';
        },

        formatArtifactSourceLabel(item) {
            if (!item) return '-';

            const sourceType = String(item.source_type || '').trim();
            const category = String(item.category || '').trim();

            if (category && sourceType) {
                return `${sourceType} / ${category}`;
            }

            if (category) {
                return category;
            }

            return sourceType || '-';
        },

        getConnectionDisplayState(conn) {
            const state = String(conn && conn.connection_state || '').trim();
            if (state === 'offline') return 'offline';

            if (conn && conn.is_transfer_active) {
                return 'online';
            }

            const disconnectedAt = String(conn && conn.disconnected_at || '').trim();
            if (disconnectedAt) return 'offline';

            const lastSeenAt = String(conn && conn.last_seen_at || '').trim();
            if (!lastSeenAt) return state || 'online';

            const staleAfterSeconds = Number(conn && conn.stale_after_seconds || 45);
            const seenMs = Date.parse(lastSeenAt);
            if (!Number.isFinite(seenMs)) return state || 'online';

            const ageMs = Math.max(this.statusNowTick - seenMs, 0);
            if (ageMs > staleAfterSeconds * 1000) return 'stale';

            return 'online';
        },

        getConnectionStatusDotClass(conn) {
            const state = this.getConnectionDisplayState(conn);
            if (state === 'online') return 'device-dot-online';
            if (state === 'stale') return 'device-dot-stale';
            return 'device-dot-offline';
        },

        getConnectionStatusText(conn) {
            const state = this.getConnectionDisplayState(conn);
            if (state === 'online') return 'online';
            if (state === 'stale') return 'stale';
            return 'offline';
        },

        formatConnectionLastSeen(conn) {
            if (!conn) return '-';

            const state = this.getConnectionDisplayState(conn);
            if (state === 'offline') {
                return this.formatDateTimeStandard(conn.disconnected_at) || '-';
            }

            return this.formatDateTimeStandard(conn.last_seen_at) || '-';
        },

        formatConnectionLastSeenRelative(conn) {
            if (!conn) return '-';

            const state = this.getConnectionDisplayState(conn);
            const baseText = state === 'offline'
                ? String(conn.disconnected_at || '').trim()
                : String(conn.last_seen_at || '').trim();

            if (!baseText) return '-';

            const ts = Date.parse(baseText);
            if (!Number.isFinite(ts)) return '-';

            const diffMs = Math.max(this.statusNowTick - ts, 0);
            const diffSec = Math.floor(diffMs / 1000);

            if (diffSec < 5) return 'just now';
            if (diffSec < 60) return `${diffSec}s ago`;

            const diffMin = Math.floor(diffSec / 60);
            if (diffMin < 60) return `${diffMin}m ago`;

            const diffHour = Math.floor(diffMin / 60);
            if (diffHour < 24) return `${diffHour}h ago`;

            const diffDay = Math.floor(diffHour / 24);
            return `${diffDay}d ago`;
        },

        formatConnectionRtt(conn) {
            const value = conn && conn.last_rtt_ms;
            if (value === null || value === undefined || value === '') return '-';
            return `${value} ms`;
        },
    }
};








