export default {
    data() {
        return {
            activeTaskIds: {},
        }
    },

    methods: {
        setActiveTask(clientId, taskId) {
            if (!clientId) return;

            this.activeTaskIds = {
                ...this.activeTaskIds,
                [clientId]: taskId || ''
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
        },
    },

    computed: {
        currentActiveTaskId() {
            return this.activeTaskIds[this.selectedId] || '';
        },
    },
}