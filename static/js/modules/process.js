// static/js/modules/process.js

window.AppProcessModule = {
    data() {
        return {
            processDialogVisible: false,
            processes: [],
            processesLoading: false,
            processFilterText: '',
            refreshTimer: null,
            loadingTimeout: null,
        };
    },

    computed: {
        filteredProcesses() {
            const list = this.processes || [];
            if (!this.processFilterText) return list;
            const kw = this.processFilterText.toLowerCase();
            return list.filter(p =>
                String(p.pid).includes(kw) ||
                (p.name || '').toLowerCase().includes(kw) ||
                (p.username || '').toLowerCase().includes(kw)
            );
        }
    },

    methods: {
        openProcessDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device first');
                return;
            }
            this.processDialogVisible = true;
            this.loadProcesses();

            if (this.refreshTimer) clearInterval(this.refreshTimer);
            this.refreshTimer = setInterval(() => {
                if (this.processDialogVisible) {
                    this.loadProcessesSilent();
                }
            }, 3000);
        },

        async loadProcesses() {
            if (!this.selectedId) return;
            this.processesLoading = true;
            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/processes`);
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    this.processes = json.data || [];
                }
            } catch (e) {
                console.error(e);
            } finally {
                // 延迟关闭 loading，避免闪烁
                setTimeout(() => {
                    this.processesLoading = false;
                }, 200);
            }
        },

        async loadProcessesSilent() {
            if (!this.selectedId || this.processesLoading) return;
            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/processes`);
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    this.processes = json.data || [];
                }
            } catch (e) {
                console.error(e);
            }
        },

        async killProcess(pid, name) {
            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Kill process "${name}" (PID: ${pid})?`,
                    'Confirm',
                    { type: 'warning', confirmButtonText: 'Kill', cancelButtonText: 'Cancel' }
                );

                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/processes/${pid}/kill`, {
                    method: 'POST'
                });
                const json = await res.json();

                if (res.ok && json.code === 0) {
                    ElementPlus.ElMessage.success(`Process ${pid} killed`);
                    await this.loadProcesses();
                } else {
                    throw new Error(json.message || 'Kill failed');
                }
            } catch (e) {
                if (e !== 'cancel') {
                    ElementPlus.ElMessage.error(e.message || 'Kill failed');
                }
            }
        },

        closeProcessDialog() {
            this.processDialogVisible = false;
            if (this.refreshTimer) {
                clearInterval(this.refreshTimer);
                this.refreshTimer = null;
            }
        }
    },

    beforeUnmount() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
    }
};