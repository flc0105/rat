window.AppProcessModule = {
    data() {
        return {
            processDialogVisible: false,
            processActiveTab: 'processes',
            // 进程数据
            processes: [],
            processesLoading: false,
            // 应用数据
            apps: [],
            appsLoading: false,
            // 过滤
            processFilterText: '',
            refreshTimer: null,
            processDetailDialogVisible: false,
            processDetailLoading: false,
            processDetail: null,
        };
    },

    computed: {
        filteredProcesses() {
            if (!this.processes.length) return [];
            if (!this.processFilterText) return this.processes;
            const kw = this.processFilterText.toLowerCase();
            return this.processes.filter(p =>
                String(p.pid).includes(kw) ||
                (p.name || '').toLowerCase().includes(kw) ||
                (p.username || '').toLowerCase().includes(kw)
            );
        },
        filteredApps() {
            if (!this.apps.length) return [];
            if (!this.processFilterText) return this.apps;
            const kw = this.processFilterText.toLowerCase();
            return this.apps.filter(a =>
                String(a.pid).includes(kw) ||
                (a.name || '').toLowerCase().includes(kw) ||
                (a.username || '').toLowerCase().includes(kw)
            );
        },
        processDetailBasicRows() {
            const detail = this.processDetail || {};
            const fieldMap = [
                ['pid', 'PID'],
                ['name', 'Name'],
                ['username', 'User'],
                ['status', 'Status'],
                ['ppid', 'Parent PID'],
                ['exe', 'Executable Path'],
                ['cwd', 'Working Directory'],
                ['create_time', 'Create Time'],
                ['cpu_percent', 'CPU %'],
                ['memory_percent', 'Memory %'],
                ['num_threads', 'Threads'],
                ['num_fds', 'FD Count'],
                ['num_handles', 'Handle Count'],
            ];
            return fieldMap
                .filter(([key]) => detail[key] !== undefined && detail[key] !== null && detail[key] !== '')
                .map(([key, label]) => ({ key, label, value: this.formatProcessDetailValue(detail[key]) }));
        },
        processDetailCommandLineText() {
            const cmdline = (this.processDetail && this.processDetail.cmdline) || [];
            if (!Array.isArray(cmdline) || !cmdline.length) return '';
            return cmdline.join(' ');
        },
    },

    methods: {
        openProcessDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device first');
                return;
            }
            this.processDialogVisible = true;
            // 串行加载
            this.loadProcesses().then(() => {
                this.loadApps();
            });
            if (this.refreshTimer) clearInterval(this.refreshTimer);
            this.refreshTimer = setInterval(() => {
                if (this.processDialogVisible) {
                    this.loadProcessesSilent().then(() => {
                        this.loadAppsSilent();
                    });
                }
            }, 5000); //5秒刷新一次
        },

        async loadProcesses() {
            if (!this.selectedId) return;
            this.processesLoading = true;
            try {
                const res = await fetch(`/api/connections/${this.selectedId}/processes`);
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    this.processes = json.data || [];
                }
            } catch (e) {
                console.error(e);
            } finally {
                this.processesLoading = false;
            }
        },

        async loadProcessesSilent() {
            if (!this.selectedId || this.processesLoading) return;
            try {
                const res = await fetch(`/api/connections/${this.selectedId}/processes`);
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    this.processes = json.data || [];
                }
            } catch (e) {
                console.error(e);
            }
        },

        async loadApps() {
            if (!this.selectedId) return;
            this.appsLoading = true;
            try {
                const res = await fetch(`/api/connections/${this.selectedId}/apps`);
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    this.apps = json.data || [];
                }
            } catch (e) {
                console.error(e);
            } finally {
                this.appsLoading = false;
            }
        },

        async loadAppsSilent() {
            if (!this.selectedId || this.appsLoading) return;
            try {
                const res = await fetch(`/api/connections/${this.selectedId}/apps`);
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    this.apps = json.data || [];
                }
            } catch (e) {
                console.error(e);
            }
        },

        async openProcessDetail(pid) {
            if (!this.selectedId || !pid) return;
            this.processDetailDialogVisible = true;
            this.processDetailLoading = true;
            this.processDetail = null;

            try {
                const res = await fetch(`/api/connections/${this.selectedId}/processes/${pid}/detail`);
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    this.processDetail = json.data || {};
                } else {
                    throw new Error(json.message || 'Failed to load process detail');
                }
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Failed to load process detail');
                this.processDetailDialogVisible = false;
            } finally {
                this.processDetailLoading = false;
            }
        },

        formatProcessDetailValue(value) {
            if (value === null || value === undefined || value === '') return '-';
            if (typeof value === 'number') return String(value);
            return String(value);
        },

        async killProcess(pid, name) {
            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Kill "${name}" (PID: ${pid})?`,
                    'Confirm',
                    { type: 'warning' }
                );
                const res = await fetch(`/api/connections/${this.selectedId}/processes/${pid}/kill`, { method: 'POST' });
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    ElementPlus.ElMessage.success(`Process ${pid} killed`);
                    this.loadProcesses();
                } else {
                    throw new Error(json.message);
                }
            } catch (e) {
                if (e !== 'cancel') ElementPlus.ElMessage.error(e.message || 'Kill failed');
            }
        },

        async killApp(pid, name) {
            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Force quit "${name}" (PID: ${pid})?`,
                    'Confirm',
                    { type: 'warning' }
                );
                const res = await fetch(`/api/connections/${this.selectedId}/apps/${pid}/kill`, { method: 'POST' });
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    ElementPlus.ElMessage.success(`${name} force quit`);
                    this.loadApps();
                } else {
                    throw new Error(json.message);
                }
            } catch (e) {
                if (e !== 'cancel') ElementPlus.ElMessage.error(e.message || 'Force quit failed');
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
