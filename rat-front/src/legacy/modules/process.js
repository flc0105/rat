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
        processManagerVisibleCount() {
            return this.processActiveTab === 'apps'
                ? this.filteredApps.length
                : this.filteredProcesses.length;
        },
        processManagerTotalCount() {
            return this.processActiveTab === 'apps'
                ? this.apps.length
                : this.processes.length;
        },
        processManagerSummaryText() {
            if (this.processActiveTab === 'apps') {
                return `Showing ${this.processManagerVisibleCount} / ${this.processManagerTotalCount} applications`;
            }
            return `Showing ${this.processManagerVisibleCount} / ${this.processManagerTotalCount} processes`;
        },
        processTabLabel() {
            return `All Processes (${this.filteredProcesses.length})`;
        },
        appTabLabel() {
            return `Applications (${this.filteredApps.length})`;
        },


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
                .map(([key, label]) => ({key, label, value: this.formatProcessDetailValue(detail[key])}));
        },
        processDetailCommandLineText() {
            const cmdline = (this.processDetail && this.processDetail.cmdline) || [];
            if (!Array.isArray(cmdline) || !cmdline.length) return '';
            return cmdline.join(' ');
        },
    },

    methods: {

        async refreshProcessManager() {
            if (this.processActiveTab === 'apps') {
                await this.loadApps();
                return;
            }
            await this.loadProcesses();
        },


        openProcessDialog() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device first');
                return;
            }
            this.processDialogVisible = true;
            this.processes = [];
            this.apps = [];
            this.processDetail = null;
            this.processFilterText = '';
            // 串行加载
            this.loadProcesses().then(() => {
                this.loadApps();
            });
            if (this.refreshTimer) clearInterval(this.refreshTimer);
            this.refreshTimer = setInterval(() => {
                if (!this.processDialogVisible || this.processDetailDialogVisible || this.processDetailLoading) {
                    return;
                }

                // 只刷新当前 tab，避免无意义地同时抢占前台查询槽。
                if (this.processActiveTab === 'apps') {
                    this.loadAppsSilent();
                    return;
                }

                this.loadProcessesSilent();
            }, 5000); // 5秒刷新一次
        },

        async loadProcesses() {
            if (!this.selectedId) return;
            this.processesLoading = true;
            try {
                const res = await fetch(`/api/connections/${this.selectedId}/processes`);
                const json = await res.json();

                if (res.ok && json.code === 0) {
                    this.processes = json.data || [];
                    return;
                }
                this.processes = [];
                ElementPlus.ElMessage.error(
                    json?.message || `Error while fetching processes (HTTP ${res.status})`
                );
            } catch (e) {
                this.processes = [];
                ElementPlus.ElMessage.error('Error while fetching processes: ' + e.message);
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
                ElementPlus.ElMessage.error('Error while fetching processes: ' + e.message);
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
                    return;
                }
                this.apps = [];
                ElementPlus.ElMessage.error(
                    json?.message || `Error while fetching processes (HTTP ${res.status})`
                );
            } catch (e) {
                console.error(e);
                this.apps = [];
                ElementPlus.ElMessage.error('Error while fetching processes: ' + e.message);
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
                ElementPlus.ElMessage.error('Error while fetching processes: ' + e.message);
            }
        },

        async openProcessDetail(pid) {
            // if (!this.selectedId || !pid) return;
            if (!this.selectedId) return;
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
                    {type: 'warning'}
                );
                const res = await fetch(`/api/connections/${this.selectedId}/processes/${pid}/kill`, {method: 'POST'});
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    ElementPlus.ElMessage.success(`Process ${pid} killed`);
                    this.loadProcesses();
                    this.loadAppsSilent();
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
                    {type: 'warning'}
                );
                const res = await fetch(`/api/connections/${this.selectedId}/apps/${pid}/kill`, {method: 'POST'});
                const json = await res.json();
                if (res.ok && json.code === 0) {
                    ElementPlus.ElMessage.success(`${name} force quit`);
                    this.loadApps();
                    this.loadProcessesSilent();
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
