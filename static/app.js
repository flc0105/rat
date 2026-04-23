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
            ...window.AppPtyModule.data(),
            ...window.AppConnectionModule.data(),
            ...window.AppCommandsModule.data(),
            ...window.AppTaskModule.data(),
            ...window.AppSseModule.data(),
            scrollTop: 0

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
        remoteFilesDialogVisible: 'updateBodyDialogLock',
        artifactDialogVisible: 'updateBodyDialogLock',
        scriptLibraryDialogVisible: 'updateBodyDialogLock',
        backgroundJobsDialogVisible: 'updateBodyDialogLock',
        previewDialogVisible: 'updateBodyDialogLock',
        commandHistoryDialogVisible: 'updateBodyDialogLock',
        processDialogVisible: 'updateBodyDialogLock',
        ptyDialogVisible: 'updateBodyDialogLock',
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
        ...window.AppPtyModule.methods,
        ...window.AppCandidatesModule.methods,
        ...window.AppHistoryModule.methods,
        ...window.AppArtifactsModule.methods,
        ...window.AppPreviewModule.methods,
        lockBody() {
            this.scrollTop = window.scrollY || document.documentElement.scrollTop;
            document.body.classList.add('dialog-open');
            document.body.style.top = `-${this.scrollTop}px`;
        },
        unlockBody() {
            document.body.classList.remove('dialog-open');
            document.body.style.top = '';
            window.scrollTo(0, this.scrollTop);
        },
        updateBodyDialogLock() {
            // 所有 dialog 的 visible
            const anyDialogOpen =
                this.remoteFilesDialogVisible ||
                this.artifactDialogVisible ||
                this.scriptLibraryDialogVisible ||
                this.backgroundJobsDialogVisible ||
                this.previewDialogVisible ||
                this.commandHistoryDialogVisible ||
                this.processDialogVisible ||
                this.ptyDialogVisible;

            anyDialogOpen ? this.lockBody() : this.unlockBody();
        }

    },
    mounted() {
        this.ensureTabId();
        this.loadConnections();
        this.initSSE();

        this.statusTickTimer = setInterval(() => {
            this.statusNowTick = Date.now();
        }, 30 * 1000);

        this.updateBodyDialogLock();
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

        document.body.classList.remove('dialog-open');
    },


}).use(ElementPlus).mount('#app');








