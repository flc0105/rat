const {createApp} = Vue;

createApp({
    data() {
        return {
            ...window.AppStateModule.data(),
            ...window.AppArtifactsModule.data(),
            ...window.AppAgentModule.data(),
            ...window.AppProcessModule.data(),
        }
    },

    computed: {
        ...window.AppStateModule.computed,
        ...window.AppProcessModule.computed,
        ...window.AppAgentModule.computed,
    },

    watch: {
        ...window.AppStateModule.watch,
        ...window.AppAgentModule.watch,
        ...window.AppProcessModule.watch,
    },

    methods: {
        ...window.AppUtilsModule.methods,
        ...window.AppCommandsModule.methods,
        ...window.AppFilesModule.methods,
        ...window.AppJobsModule.methods,
        ...window.AppSseModule.methods,
        ...window.AppAgentModule.methods,
        ...window.AppProcessModule.methods,
        ...window.AppConnectionModule.methods,
        ...window.AppTaskModule.methods,
        ...window.AppTerminalModule.methods,
        ...window.AppCandidatesModule.methods,
        ...window.AppHistoryModule.methods,
        ...window.AppArtifactsModule.methods,
        ...window.AppPreviewModule.methods,

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


}).use(ElementPlus).mount('#app');








