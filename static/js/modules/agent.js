window.AppAgentModule = {
    data() {
        return {
            agentBuilderDialogVisible: false,
            agentBuilding: false,
            agentForm: {
                server_host: window.location.hostname || '127.0.0.1',
                server_port: 9999,
                web_port: 8085,
                target_os: 'mac',
                builder: 'pyinstaller',
                target_arch: 'auto',
            }
        };
    },

    computed: {
        // agentBuilderAlertType() {
        //     return this.agentForm.builder === 'pyinstaller' ? 'warning' : 'info';
        // },
        //
        // agentBuilderAlertTitle() {
        //     return this.agentForm.builder === 'pyinstaller'
        //         ? 'PyInstaller 限制说明'
        //         : 'Go（基础版）说明';
        // },

        agentBuilderAlertText() {
            if (this.agentForm.builder === 'pyinstaller') {
                return 'PyInstaller only builds for the current server platform. Architecture selection applies only to Go.';
            }

            return 'Windows defaults to amd64, Linux defaults to amd64, and macOS uses the best-matching server architecture by default.';
        },

        isGoBuilder() {
            return this.agentForm.builder === 'go';
        }
    },

    methods: {
        openAgentBuilderDialog() {
            this.agentBuilderDialogVisible = true;
            this.agentForm.server_host = window.location.hostname || '127.0.0.1';
            this.agentForm.server_port = 9999;
            this.agentForm.web_port = 8085;
            this.applyRecommendedAgentArch();
        },

        applyRecommendedAgentArch() {
            if (this.agentForm.builder !== 'go') {
                this.agentForm.target_arch = 'auto';
                return;
            }

            if (this.agentForm.target_os === 'win') {
                this.agentForm.target_arch = 'amd64';
                return;
            }

            if (this.agentForm.target_os === 'linux') {
                this.agentForm.target_arch = 'amd64';
                return;
            }

            this.agentForm.target_arch = 'auto';
        },

        async buildAgent() {
            if (!this.agentForm.server_host) {
                ElementPlus.ElMessage.warning('Please enter server IP');
                return;
            }
            if (!this.agentForm.server_port) {
                ElementPlus.ElMessage.warning('Please enter server port');
                return;
            }
            if (!this.agentForm.web_port) {
                ElementPlus.ElMessage.warning('Please enter web port');
                return;
            }

            this.agentBuilding = true;

            try {
                const res = await fetch('/api/agent/build', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(this.agentForm)
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Build failed');
                }

                const data = json.data;
                const downloadUrl = `/api/agent/download/${encodeURIComponent(data.file_name)}`;

                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = data.file_name;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);

                if (Array.isArray(data.warnings) && data.warnings.length > 0) {
                    data.warnings.forEach(msg => {
                        if (msg) {
                            ElementPlus.ElMessage.warning(msg);
                        }
                    });
                }

                ElementPlus.ElMessage.success(`Agent built: ${data.file_name} (${this.formatBytes(data.size)})`);
                this.agentBuilderDialogVisible = false;

            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Build failed');
            } finally {
                this.agentBuilding = false;
            }
        }
    },

    watch: {
        'agentForm.builder'() {
            this.applyRecommendedAgentArch();
        },

        'agentForm.target_os'() {
            this.applyRecommendedAgentArch();
        }
    }
};
