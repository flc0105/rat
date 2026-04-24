window.AppTaskModule = {
    data() {
        return {
            activeTaskIds: {},
            cancellingTaskIds: {},
        }
    },

    methods: {
        setActiveTask(clientId, taskId) {
            if (!clientId) return;

            this.activeTaskIds = {
                ...this.activeTaskIds,
                [clientId]: taskId || ''
            };

            this.cancellingTaskIds = {
                ...this.cancellingTaskIds,
                [clientId]: false
            };
        },

        clearActiveTask(clientId, taskId = '') {
            if (!clientId) return;

            const currentTaskId = this.activeTaskIds[clientId] || '';
            if (taskId && currentTaskId && currentTaskId !== taskId) {
                return;
            }

            const nextActive = {...this.activeTaskIds};
            delete nextActive[clientId];
            this.activeTaskIds = nextActive;

            const nextCancelling = {...this.cancellingTaskIds};
            delete nextCancelling[clientId];
            this.cancellingTaskIds = nextCancelling;
        },

        markTaskCancelling(clientId, taskId = '') {
            if (!clientId) return;

            if (taskId) {
                const currentTaskId = this.activeTaskIds[clientId] || '';
                if (currentTaskId && currentTaskId !== taskId) {
                    return;
                }
            }

            this.cancellingTaskIds = {
                ...this.cancellingTaskIds,
                [clientId]: true
            };
        },

        async cancelCurrentTask() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            const taskId = this.currentActiveTaskId;
            if (!taskId) {
                ElementPlus.ElMessage.warning('No running task');
                return;
            }

            try {
                this.markTaskCancelling(this.selectedId, taskId);

                const res = await fetch(`/api/tasks/${encodeURIComponent(taskId)}/cancel`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Cancel failed');
                }

                this.appendOutput(this.selectedId, `[Cancel requested] task=${taskId}`, 'info');
                ElementPlus.ElMessage.success('Cancel request sent');
            } catch (e) {
                this.cancellingTaskIds = {
                    ...this.cancellingTaskIds,
                    [this.selectedId]: false
                };
                ElementPlus.ElMessage.error(e.message || 'Cancel failed');
            }
        },
    },

    computed: {
        currentActiveTaskId() {
            return this.activeTaskIds[this.selectedId] || '';
        },

        currentTaskIsCancelling() {
            return !!this.cancellingTaskIds[this.selectedId];
        },

        hasRunningWebTask() {
            return !!this.currentActiveTaskId;
        },
    },
}