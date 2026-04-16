window.AppPtyModule = {
    data() {
        return {
            ptyDialogVisible: false,
            ptyLoading: false,
            ptySessionId: '',
            ptyOutput: '',
            ptySeq: 0,
            ptyStatus: '',
            ptyError: '',
            ptyPollTimer: null,
            ptyShellPath: '',
        };
    },

    methods: {
        async openPtyDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }
            if (this.ptyLoading) return;

            this.ptyLoading = true;
            this.ptyDialogVisible = true;
            this.ptySessionId = '';
            this.ptyOutput = '';
            this.ptySeq = 0;
            this.ptyStatus = 'opening';
            this.ptyError = '';

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/pty/open`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...this.getTabScopedHeaders(),
                    },
                    body: JSON.stringify({
                        cols: 120,
                        rows: 32,
                        shell: this.ptyShellPath || '',
                    }),
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to open PTY');
                }
                this.ptySessionId = json.data?.pty_session_id || '';
                this.ptyStatus = json.data?.status || 'opening';
                this.startPtyPolling();
                this.$nextTick(() => this.focusPtyInput());
            } catch (e) {
                this.ptyStatus = 'error';
                this.ptyError = e?.message || String(e);
                ElementPlus.ElMessage.error(this.ptyError || 'Failed to open PTY');
            } finally {
                this.ptyLoading = false;
            }
        },

        async closePtyDialog() {
            this.stopPtyPolling();
            const ptyId = this.ptySessionId;
            this.ptyDialogVisible = false;
            this.ptySessionId = '';
            this.ptyStatus = 'closed';
            if (!ptyId) return;
            try {
                await fetch(`/api/pty/${encodeURIComponent(ptyId)}/close`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...this.getTabScopedHeaders(),
                    },
                    body: '{}',
                });
            } catch (_) {}
        },

        startPtyPolling() {
            this.stopPtyPolling();
            const tick = async () => {
                if (!this.ptyDialogVisible || !this.ptySessionId) return;
                try {
                    const url = new URL(`/api/pty/${encodeURIComponent(this.ptySessionId)}/poll`, window.location.origin);
                    url.searchParams.set('after_seq', String(this.ptySeq || 0));
                    const res = await fetch(url.toString(), {headers: this.getTabScopedHeaders()});
                    const json = await res.json();
                    if (!res.ok || json.code !== 0) {
                        throw new Error(json.message || 'PTY poll failed');
                    }
                    const payload = json.data || {};
                    this.ptyStatus = payload.status || this.ptyStatus || '';
                    this.ptyError = payload.error || this.ptyError || '';
                    if (Array.isArray(payload.chunks)) {
                        payload.chunks.forEach((chunk) => {
                            const seq = Number(chunk?.seq || 0);
                            if (seq > this.ptySeq) this.ptySeq = seq;
                            const text = String(chunk?.text || '');
                            if (text) this.appendPtyOutput(text);
                        });
                    }
                    if (this.ptyStatus === 'closed' || this.ptyStatus === 'error') {
                        this.stopPtyPolling();
                    }
                } catch (e) {
                    this.ptyError = e?.message || String(e);
                    this.ptyStatus = 'error';
                    this.stopPtyPolling();
                }
                if (this.ptyDialogVisible && this.ptySessionId && this.ptyStatus !== 'closed' && this.ptyStatus !== 'error') {
                    this.ptyPollTimer = setTimeout(tick, 250);
                }
            };
            tick();
        },

        stopPtyPolling() {
            if (this.ptyPollTimer) {
                clearTimeout(this.ptyPollTimer);
                this.ptyPollTimer = null;
            }
        },

        appendPtyOutput(text) {
            this.ptyOutput = `${this.ptyOutput || ''}${text}`;
            if (this.ptyOutput.length > 200000) {
                this.ptyOutput = this.ptyOutput.slice(-200000);
            }
            this.$nextTick(() => this.scrollPtyToBottom());
        },

        scrollPtyToBottom() {
            const el = this.$refs.ptyOutputRef;
            if (el) {
                el.scrollTop = el.scrollHeight;
            }
        },

        focusPtyInput() {
            const el = this.$refs.ptyInputCaptureRef;
            if (el) {
                el.focus();
                try { el.setSelectionRange(0, 0); } catch (_) {}
            }
        },

        refocusPtyInput() {
            if (!this.ptyDialogVisible) return;
            setTimeout(() => this.focusPtyInput(), 0);
        },

        async sendPtyData(raw) {
            if (!this.ptySessionId || !raw) return;
            try {
                const encoded = btoa(unescape(encodeURIComponent(raw)));
                await fetch(`/api/pty/${encodeURIComponent(this.ptySessionId)}/input`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...this.getTabScopedHeaders(),
                    },
                    body: JSON.stringify({data: encoded}),
                });
            } catch (_) {}
        },

        async handlePtyKeydown(event) {
            if (!this.ptySessionId) return;
            let payload = '';
            if (event.ctrlKey && !event.altKey && !event.metaKey) {
                const key = (event.key || '').toLowerCase();
                if (key === 'c') payload = '\u0003';
                else if (key === 'd') payload = '\u0004';
                else if (key === 'l') payload = '\u000c';
            } else if (event.key === 'Enter') payload = '\r';
            else if (event.key === 'Backspace') payload = '\u007f';
            else if (event.key === 'Tab') payload = '\t';
            else if (event.key === 'ArrowUp') payload = '\u001b[A';
            else if (event.key === 'ArrowDown') payload = '\u001b[B';
            else if (event.key === 'ArrowRight') payload = '\u001b[C';
            else if (event.key === 'ArrowLeft') payload = '\u001b[D';
            else if (event.key === 'Escape') payload = '\u001b';
            else if ((event.key || '').length === 1 && !event.metaKey && !event.altKey) payload = event.key;

            if (!payload) return;
            event.preventDefault();
            await this.sendPtyData(payload);
        },

        async handlePtyPaste(event) {
            if (!this.ptySessionId) return;
            const text = event?.clipboardData?.getData('text') || '';
            if (!text) return;
            event.preventDefault();
            await this.sendPtyData(text);
        },

        handlePtyDialogClosed() {
            this.stopPtyPolling();
            this.ptySessionId = '';
        },
    },
};
