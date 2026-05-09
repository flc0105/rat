export default {
    data() {
        return {
            activeTaskIds: {},
            completedTaskIds: {},
        }
    },

    methods: {
        setActiveTask(clientId, taskId) {
            if (!clientId) return;

            const normalizedTaskId = String(taskId || '').trim();

            if (!normalizedTaskId) {
                this.clearActiveTask(clientId);
                return;
            }

            // 处理极短命令 race：complete SSE 可能早于 POST 返回。
            // 如果 task 已经完成过，不允许它再被迟到的 setActiveTask 写回 Busy。
            if (this.completedTaskIds[normalizedTaskId]) {
                this.clearActiveTask(clientId, normalizedTaskId);
                return;
            }

            this.activeTaskIds = {
                ...this.activeTaskIds,
                [clientId]: normalizedTaskId
            };
        },

        markTaskCompleted(clientId, taskId = '') {
            const normalizedTaskId = String(taskId || '').trim();

            if (normalizedTaskId) {
                const nextCompletedTaskIds = {
                    ...this.completedTaskIds,
                    [normalizedTaskId]: Date.now(),
                };

                // 只保留少量 tombstone，避免长期运行时无限增长。
                const entries = Object.entries(nextCompletedTaskIds)
                    .sort((a, b) => Number(a[1] || 0) - Number(b[1] || 0));

                while (entries.length > 300) {
                    const [oldestTaskId] = entries.shift();
                    delete nextCompletedTaskIds[oldestTaskId];
                }

                this.completedTaskIds = nextCompletedTaskIds;
            }

            this.clearActiveTask(clientId, normalizedTaskId);
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
        },
    },

    computed: {
        currentActiveTaskId() {
            return this.activeTaskIds[this.selectedId] || '';
        },
    },
}