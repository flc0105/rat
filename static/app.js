const {createApp} = Vue;

createApp({
    data() {
        return {
            ...window.AppStateModule.data(),
            ...window.AppArtifactsModule.data(),
            ...window.AppAgentModule.data(),
            ...window.AppProcessModule.data(),
            ...window.AppFilesModule.data(),
            ...window.AppPreviewModule.data(),
            ...window.AppJobsModule.data(),
            ...window.AppScriptsModule.data(),
            ...window.AppCandidatesModule.data(),
            ...window.AppHistoryModule.data(),
            ...window.AppTerminalModule.data(),
            ...window.AppConnectionModule.data(),
            ...window.AppCommandsModule.data(),
            ...window.AppTaskModule.data(),
            ...window.AppSseModule.data(),
        }
    },

    computed: {
        ...window.AppStateModule.computed,
        ...window.AppProcessModule.computed,
        ...window.AppAgentModule.computed,
        ...window.AppPreviewModule.computed,
        ...window.AppConnectionModule.computed,
        ...window.AppTerminalModule.computed,
        ...window.AppTaskModule.computed,
        ...window.AppHistoryModule.computed,
        ...window.AppFilesModule.computed,
        ...window.AppArtifactsModule.computed,
        ...window.AppJobsModule.computed,
        ...window.AppScriptsModule.computed,
    },

    watch: {
        ...window.AppStateModule.watch,
        ...window.AppAgentModule.watch,
        ...window.AppProcessModule.watch,
        ...window.AppTerminalModule.watch,
        ...window.AppPreviewModule.watch,
        ...window.AppFilesModule.watch,
        ...window.AppArtifactsModule.watch,
        ...window.AppJobsModule.watch,
        ...window.AppScriptsModule.watch,
        ...window.AppHistoryModule.watch,
    },

    methods: {
        ...window.AppUtilsModule.methods,
        ...window.AppCommandsModule.methods,
        ...window.AppFilesModule.methods,
        ...window.AppJobsModule.methods,
        ...window.AppScriptsModule.methods,
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








