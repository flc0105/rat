const { createApp } = Vue;

createApp({
    data() {
        return window.AppStateModule.data();
    },

    computed: {
        ...window.AppStateModule.computed,
    },

    watch: {
        ...window.AppStateModule.watch,
    },

    mounted() {
        this.loadConnections();
        this.initSSE();
    },

    beforeUnmount() {
        if (this.eventSource) this.eventSource.close();
        if (this.backgroundJobsRefreshTimer) {
            clearTimeout(this.backgroundJobsRefreshTimer);
            this.backgroundJobsRefreshTimer = null;
        }
    },

    methods: {
        ...window.AppUtilsModule.methods,
        ...window.AppCommandsModule.methods,
        ...window.AppFilesModule.methods,
        ...window.AppJobsModule.methods,
        ...window.AppSseModule.methods,
    }
}).use(ElementPlus).mount('#app');