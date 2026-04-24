window.AppPtyModule = {
    data() {
        return {
            ptyDialogVisible: false,
            ptyLoading: false,
            ptySessionId: '',
            ptySeq: 0,
            ptyStatus: '',
            ptyError: '',
            ptyShellPath: '',
            ptyTerm: null,
            ptyFitAddon: null,
            ptyInputQueue: '',
            ptyFlushTimer: null,
            ptyLastCols: 0,
            ptyLastRows: 0,
            ptyWs: null,
            ptyWsPath: '',
            ptyUserClosing: false,
            ptyWsConnectedOnce: false,
            _ptyResizeTimer: null,
            _ptyWindowResizeHandler: null,
        };
    },

    methods: {
        async openPtyDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            if (this.ptyLoading) return;
            if (!window.Terminal || !window.FitAddon || !window.FitAddon.FitAddon) {
                ElementPlus.ElMessage.error('xterm.js failed to load');
                return;
            }

            this.ptyLoading = true;
            this.ptyDialogVisible = true;
            this.ptySessionId = '';
            this.ptySeq = 0;
            this.ptyStatus = 'opening';
            this.ptyError = '';
            this.ptyUserClosing = false;
            this.ptyWsConnectedOnce = false;
            this.closePtySocket();
            this.resetPtyInputQueue();

            try {
                await this.$nextTick();
                this.initPtyTerminal();
                this.clearPtyTerminal();
                this.writePtySystemLine('[opening PTY...]\r\n');
                ElementPlus.ElMessage({ type: 'info', message: 'Opening PTY session...', duration: 1200 });

                const dims = this.fitPtyTerminalAndGetSize();
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/pty/open`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...this.getTabScopedHeaders(),
                    },
                    body: JSON.stringify({
                        cols: dims.cols,
                        rows: dims.rows,
                        shell: this.ptyShellPath || '',
                    }),
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to open PTY');
                }

                this.ptySessionId = json.data?.pty_session_id || '';
                this.ptyStatus = json.data?.status || 'opening';
                this.ptyLastCols = dims.cols;
                this.ptyLastRows = dims.rows;
                this.ptyWsPath = json.data?.ws_path || '';

                this.openPtySocket();
                this.focusPtyInput();
                this.schedulePtyResize();
            } catch (e) {
                this.ptyStatus = 'error';
                this.ptyError = e?.message || String(e);
                // this.writePtySystemLine(`\r\n[PTY error] ${this.ptyError}\r\n`);

                ElementPlus.ElMessage.error(this.ptyError || 'Failed to open PTY');
            } finally {
                this.ptyStatus = 'error';
                this.ptyLoading = false;
            }
        },

        async closePtyDialog() {
            this.resetPtyInputQueue();
            this.clearPtyResizeTimer();
            this.ptyUserClosing = true;
            this.sendPtyWs({ type: 'close' });
            this.closePtySocket();

            const ptyId = this.ptySessionId;
            this.ptyDialogVisible = false;
            this.ptySessionId = '';
            this.ptyStatus = 'closed';

            if (!ptyId) {
                this.disposePtyTerminal();
                return;
            }

            try {
                await fetch(`/api/pty/${encodeURIComponent(ptyId)}/close`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...this.getTabScopedHeaders(),
                    },
                    body: '{}',
                });
            } catch (_) {
            } finally {
                this.disposePtyTerminal();
            }
        },

        initPtyTerminal() {
            if (this.ptyTerm) return;
            const host = this.$refs.ptyTerminalRef;
            if (!host) return;

            const term = new window.Terminal({
                cursorBlink: true,
                convertEol: false,
                scrollback: 5000,
                fontSize: 12,
                lineHeight: 1.32,
                fontFamily: "'JetBrains Mono', 'SFMono-Regular', 'Cascadia Mono', 'Menlo', 'Consolas', monospace",
                theme: {
                    background: '#000000',
                    foreground: '#e5e7eb',
                    cursor: '#e5e7eb',
                    cursorAccent: '#000000',
                    selectionBackground: 'rgba(148, 163, 184, 0.28)',
                },
                allowTransparency: false,
            });

            const fitAddon = new window.FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            term.open(host);

            try { fitAddon.fit(); } catch (_) {}

            term.onData((data) => {
                this.queuePtyInput(data);
            });

            term.onTitleChange((title) => {
                if (title) this.ptyStatus = this.ptyStatus || 'open';
            });

            this.ptyTerm = term;
            this.ptyFitAddon = fitAddon;

            this._ptyWindowResizeHandler = () => {
                this.schedulePtyResize();
            };
            window.addEventListener('resize', this._ptyWindowResizeHandler, { passive: true });
        },

        disposePtyTerminal() {
            if (this._ptyWindowResizeHandler) {
                window.removeEventListener('resize', this._ptyWindowResizeHandler);
                this._ptyWindowResizeHandler = null;
            }

            this.clearPtyResizeTimer();

            if (this.ptyTerm) {
                try { this.ptyTerm.dispose(); } catch (_) {}
                this.ptyTerm = null;
            }

            this.ptyFitAddon = null;
            this.ptyLastCols = 0;
            this.ptyLastRows = 0;
        },

        clearPtyResizeTimer() {
            if (this._ptyResizeTimer) {
                clearTimeout(this._ptyResizeTimer);
                this._ptyResizeTimer = null;
            }
        },

        clearPtyTerminal() {
            if (this.ptyTerm) {
                try { this.ptyTerm.clear(); } catch (_) {}
                try { this.ptyTerm.reset(); } catch (_) {}
            }
        },

        writePtyOutput(text) {
            if (!text) return;
            if (this.ptyTerm) {
                this.ptyTerm.write(text);
            }
        },

        writePtySystemLine(text) {
            if (this.ptyTerm) {
                this.ptyTerm.write(text);
            }
        },

        focusPtyInput() {
            if (this.ptyTerm) {
                try { this.ptyTerm.focus(); } catch (_) {}
            }
        },

        refocusPtyInput() {
            if (!this.ptyDialogVisible) return;
            setTimeout(() => this.focusPtyInput(), 0);
        },

        fitPtyTerminalAndGetSize() {
            if (this.ptyFitAddon) {
                try { this.ptyFitAddon.fit(); } catch (_) {}
            }
            const cols = Math.max(20, Number(this.ptyTerm?.cols || 120));
            const rows = Math.max(5, Number(this.ptyTerm?.rows || 32));
            return { cols, rows };
        },

        schedulePtyResize() {
            if (!this.ptyDialogVisible || !this.ptySessionId || !this.ptyWs || this.ptyWs.readyState !== WebSocket.OPEN) return;

            this.clearPtyResizeTimer();
            this._ptyResizeTimer = setTimeout(() => {
                this._ptyResizeTimer = null;
                if (!this.ptyDialogVisible || !this.ptySessionId) return;
                const size = this.fitPtyTerminalAndGetSize();
                this.sendPtyResize(size.cols, size.rows);
            }, 80);
        },

        sendPtyResize(cols, rows) {
            if (!this.ptySessionId) return;
            cols = Math.max(20, Number(cols || 0));
            rows = Math.max(5, Number(rows || 0));
            if (!cols || !rows) return;
            if (this.ptyLastCols === cols && this.ptyLastRows === rows) return;
            this.ptyLastCols = cols;
            this.ptyLastRows = rows;
            this.sendPtyWs({ type: 'resize', cols, rows });
        },

               openPtySocket() {
            this.closePtySocket();
            if (!this.ptyWsPath) return;
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const url = `${protocol}//${window.location.host}${this.ptyWsPath}`;
            const ws = new WebSocket(url);
            this.ptyWs = ws;

            const applyChunks = (chunks) => {
                if (!Array.isArray(chunks)) return;
                chunks.forEach((chunk) => {
                    const seq = Number(chunk?.seq || 0);
                    if (seq > this.ptySeq) this.ptySeq = seq;
                    const text = String(chunk?.text || '');
                    if (text) this.writePtyOutput(text);
                });
            };

            ws.onopen = () => {
                this.ptyStatus = this.ptyStatus === 'error' ? this.ptyStatus : 'open';
                this.ptyWsConnectedOnce = true;
                this.focusPtyInput();
                this.schedulePtyResize();
                ElementPlus.ElMessage({ type: 'success', message: 'PTY connected', duration: 1200 });
            };

            ws.onmessage = (event) => {
                try {
                    const payload = JSON.parse(String(event.data || '{}'));
                    console.log('PTY WS payload:', payload);

                    // asgi websocket: output/status
                    if (payload.type === 'output') {
                        applyChunks(payload.chunks);
                    }

                    // legacy websocket server: snapshot/pty_update
                    if (payload.type === 'snapshot' || payload.type === 'pty_update') {
                        applyChunks(payload.chunks);
                    }

                    if (payload.status) this.ptyStatus = payload.status;
                    if (payload.error) this.ptyError = payload.error;
                    if (payload.seq) this.ptySeq = Math.max(this.ptySeq, Number(payload.seq || 0));

                    if (
                        payload.type === 'status' ||
                        payload.type === 'snapshot' ||
                        payload.type === 'pty_update'
                    ) {
                        if (payload.status === 'closed' || payload.status === 'error') {
                            this.closePtySocket();
                        }
                    }
                } catch (e) {
                    console.error('PTY ws message parse failed', e);
                }
            };

            ws.onerror = () => {
                this.ptyError = this.ptyError || 'PTY websocket error';
            };

            ws.onclose = () => {
                const unexpected = !this.ptyUserClosing && this.ptyDialogVisible && this.ptyStatus !== 'error';
                if (this.ptyDialogVisible && this.ptyStatus !== 'closed' && this.ptyStatus !== 'error') {
                    this.ptyStatus = 'closed';
                }
                this.ptyWs = null;
                if (unexpected) {
                    ElementPlus.ElMessage({
                        type: 'warning',
                        message: this.ptyWsConnectedOnce ? 'PTY disconnected' : 'PTY connection closed',
                        duration: 1800,
                    });
                }
            };
        },

        closePtySocket() {
            if (this.ptyWs) {
                try { this.ptyWs.close(); } catch (_) {}
                this.ptyWs = null;
            }
        },

        sendPtyWs(payload) {
            if (!this.ptyWs || this.ptyWs.readyState !== WebSocket.OPEN) return;
            try {
                this.ptyWs.send(JSON.stringify(payload || {}));
            } catch (_) {}
        },

        queuePtyInput(raw) {
            if (!this.ptySessionId || !raw) return;
            this.ptyInputQueue = `${this.ptyInputQueue || ''}${raw}`;
            if (this.ptyFlushTimer) return;
            this.ptyFlushTimer = setTimeout(() => this.flushPtyInputQueue(), 10);
        },

        resetPtyInputQueue() {
            this.ptyInputQueue = '';
            if (this.ptyFlushTimer) {
                clearTimeout(this.ptyFlushTimer);
                this.ptyFlushTimer = null;
            }
        },

        flushPtyInputQueue() {
            const payload = this.ptyInputQueue || '';
            this.ptyInputQueue = '';
            this.ptyFlushTimer = null;
            if (!this.ptySessionId || !payload) return;
            const encoded = this.encodePtyInput(payload);
            this.sendPtyWs({ type: 'input', data: encoded });
        },

        encodePtyInput(raw) {
            const bytes = new TextEncoder().encode(String(raw || ''));
            let binary = '';
            const chunkSize = 0x8000;
            for (let i = 0; i < bytes.length; i += chunkSize) {
                const chunk = bytes.subarray(i, i + chunkSize);
                binary += String.fromCharCode(...chunk);
            }
            return btoa(binary);
        },

        handlePtyDialogClosed() {
            this.resetPtyInputQueue();
            this.clearPtyResizeTimer();
            this.closePtySocket();
            this.ptySessionId = '';
            this.disposePtyTerminal();
        },
    },
};
