window.AppUtilsModule = {
    methods: {

        toggleCommandExecutionOutputSort() {
            this.commandExecutionOutputSortOrder = this.commandExecutionOutputSortOrder === 'asc' ? 'desc' : 'asc';
        },

        resetPreviewState() {
            this.previewType = '';
            this.previewTitle = '';
            this.previewUrl = '';
            this.previewText = '';
        },

        resetRemoteFilesState() {
            this.remoteFilesCurrentPath = '';
            this.remoteFilesParentPath = '';
            this.remoteFilesEntries = [];
            this.remoteFilesPathInput = '';
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

        appendOutput(clientId, text, kind = '') {
            if (!clientId) return;
            this.ensureOutputBucket(clientId);

            const raw = String(text ?? '');
            const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
            const segments = normalized.split('\n');

            segments.forEach((segment) => {
                this.outputs[clientId].push({
                    text: segment === '' ? ' ' : segment,
                    kind: kind || this.inferLineKind(segment),
                    isMultiline: segments.length > 1
                });
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

            if (sourceType === 'http_upload' && category) {
                return `http_upload / ${category}`;
            }

            if (category && item.artifact_type === 'http_uploads') {
                return `${sourceType || 'http_upload'} / ${category}`;
            }

            if (category) {
                return `${sourceType || 'artifact'} / ${category}`;
            }

            return sourceType || '-';
        },

        getConnectionDisplayState(conn) {
            const state = String(conn && conn.connection_state || '').trim();
            if (state === 'offline') return 'offline';

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

        formatConnectionRtt(conn) {
            const value = conn && conn.last_rtt_ms;
            if (value === null || value === undefined || value === '') return '-';
            return `${value} ms`;
        },
    }
};