const {createApp} = Vue;

createApp({
    data() {
        return {
            ...window.AppStateModule.data(),
            ...window.AppAgentModule.data(),

        }
    },

    computed: {
        ...window.AppStateModule.computed,
    },

    watch: {
        ...window.AppStateModule.watch,
    },

    mounted() {
        this.ensureTabId();
        this.loadConnections();
        this.initSSE();

        this.statusTickTimer = setInterval(() => {
            this.statusNowTick = Date.now();
        }, 30 * 1000);
    },

    beforeUnmount() {
        if (this.eventSource) this.eventSource.close();
        if (this.backgroundJobsRefreshTimer) {
            clearTimeout(this.backgroundJobsRefreshTimer);
            this.backgroundJobsRefreshTimer = null;
        }
        if (this.statusTickTimer) {
            clearInterval(this.statusTickTimer);
            this.statusTickTimer = null;
        }
    },

    methods: {
        ...window.AppUtilsModule.methods,
        ...window.AppCommandsModule.methods,
        ...window.AppFilesModule.methods,
        ...window.AppJobsModule.methods,
        ...window.AppSseModule.methods,
        ...window.AppAgentModule.methods,

    }
}).use(ElementPlus).mount('#app');