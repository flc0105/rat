window.AppPtyModule = {
    data() {
        return {
            ptyDialogVisible: false,
            ptyLoading: false,
            ptySessionId: '',
            ptyStatus: '',
            ptyError: '',
            ptyShellPath: '',
            ptyTerm: null,
            ptyFitAddon: null,
            ptyWs: null,
            ptyInputQueue: '',
            ptyFlushTimer: null,
            ptyLastCols: 0,
            ptyLastRows: 0,
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
            this.ptyStatus = 'opening';
            this.ptyError = '';
            this.resetPtyInputQueue();

            try {
                await this.$nextTick();
                this.initPtyTerminal();
                this.clearPtyTerminal();
                this.writePtySystemLine('[opening PTY...]\r\n');

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

                await this.connectPtyWebSocket(json.data?.ws_url || '');
                this.focusPtyInput();
                this.schedulePtyResize();
            } catch (e) {
                this.ptyStatus = 'error';
                this.ptyError = e?.message || String(e);
                this.writePtySystemLine(`\r\n[PTY error] ${this.ptyError}\r\n`);
                ElementPlus.ElMessage.error(this.ptyError || 'Failed to open PTY');
            } finally {
                this.ptyLoading = false;
            }
        },

        async connectPtyWebSocket(url) {
            if (!url) throw new Error('PTY websocket url missing');
            this.closePtyWebSocket();
            await new Promise((resolve, reject) => {
                const ws = new WebSocket(url);
                let settled = false;
                ws.onopen = () => {
                    this.ptyWs = ws;
                    settled = true;
                    resolve();
                };
                ws.onmessage = (event) => this.handlePtyWsMessage(event.data);
                ws.onerror = () => {
                    if (!settled) {
                        settled = true;
                        reject(new Error('PTY websocket connection failed'));
                    }
                };
                ws.onclose = () => {
                    if (this.ptyWs === ws) {
                        this.ptyWs = null;
                    }
                    if (!settled) {
                        settled = true;
                        reject(new Error('PTY websocket closed before ready'));
                        return;
                    }
                    if (this.ptyDialogVisible && this.ptyStatus !== 'closed') {
                        this.ptyStatus = 'closed';
                        this.writePtySystemLine('\r\n[PTY disconnected]\r\n');
                    }
                };
            });
        },

        handlePtyWsMessage(raw) {
            let payload = {};
            try {
                payload = JSON.parse(raw || '{}');
            } catch (_) {
                return;
            }
            const type = String(payload.type || '');
            if (type === 'snapshot' || type === 'pty_update') {
                this.ptyStatus = payload.status || this.ptyStatus || '';
                this.ptyError = payload.error || this.ptyError || '';
                const chunks = Array.isArray(payload.chunks) ? payload.chunks : [];
                chunks.forEach((chunk) => {
                    const text = String(chunk?.text || '');
                    if (text) this.writePtyOutput(text);
                });
                if (this.ptyStatus === 'closed' || this.ptyStatus === 'error') {
                    this.closePtyWebSocket();
                }
                return;
            }
            if (type === 'error') {
                this.ptyError = String(payload.message || 'PTY error');
                this.ptyStatus = 'error';
                this.writePtySystemLine(`\r\n[PTY error] ${this.ptyError}\r\n`);
                return;
            }
        },

        sendPtyWsMessage(payload) {
            if (!this.ptyWs || this.ptyWs.readyState !== WebSocket.OPEN) return;
            try {
                this.ptyWs.send(JSON.stringify(payload || {}));
            } catch (_) {}
        },

        async closePtyDialog() {
            this.resetPtyInputQueue();
            this.clearPtyResizeTimer();

            if (this.ptySessionId && this.ptyWs && this.ptyWs.readyState === WebSocket.OPEN) {
                this.sendPtyWsMessage({ type: 'close' });
            }

            this.ptyDialogVisible = false;
            this.ptySessionId = '';
            this.ptyStatus = 'closed';
            this.closePtyWebSocket();
            this.disposePtyTerminal();
        },

        closePtyWebSocket() {
            const ws = this.ptyWs;
            this.ptyWs = null;
            if (ws) {
                try { ws.close(); } catch (_) {}
            }
        },

        initPtyTerminal() {
            if (this.ptyTerm) return;
            const host = this.$refs.ptyTerminalRef;
            if (!host) return;

            const term = new window.Terminal({
                cursorBlink: true,
                convertEol: false,
                scrollback: 2000,
                fontSize: 15,
                lineHeight: 1.25,
                theme: { background: '#03142d' },
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
            this._ptyWindowResizeHandler = () => this.schedulePtyResize();
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
            if (!text || !this.ptyTerm) return;
            this.ptyTerm.write(text);
        },

        writePtySystemLine(text) {
            if (this.ptyTerm) this.ptyTerm.write(text);
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
            if (!this.ptyDialogVisible || !this.ptySessionId || !this.ptyWs) return;
            this.clearPtyResizeTimer();
            this._ptyResizeTimer = setTimeout(() => {
                this._ptyResizeTimer = null;
                if (!this.ptyDialogVisible || !this.ptySessionId || !this.ptyWs) return;
                const size = this.fitPtyTerminalAndGetSize();
                this.sendPtyResize(size.cols, size.rows);
            }, 80);
        },

        sendPtyResize(cols, rows) {
            cols = Math.max(20, Number(cols || 0));
            rows = Math.max(5, Number(rows || 0));
            if (!cols || !rows) return;
            if (this.ptyLastCols === cols && this.ptyLastRows === rows) return;
            this.ptyLastCols = cols;
            this.ptyLastRows = rows;
            this.sendPtyWsMessage({ type: 'resize', cols, rows });
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
            this.sendPtyWsMessage({ type: 'input', data: this.encodePtyInput(payload) });
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
            this.ptySessionId = '';
            this.closePtyWebSocket();
            this.disposePtyTerminal();
        },
    },
};
