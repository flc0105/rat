window.AppAgentModule = {
    data() {
        return {
            agentBuilderDialogVisible: false,
            agentBuilding: false,
            agentServerTargetOs: 'mac',
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
        agentBuilderAlertText() {
            if (this.agentForm.builder === 'pyinstaller') {
                return 'PyInstaller builds only for the current server platform. Target OS is locked to the server platform and architecture selection is disabled.';
            }

            if (this.agentForm.builder === 'bundle') {
                return 'Bundle outputs a source zip that contains client/, core/ and ratclient.py. Target OS and architecture are not applicable.';
            }

            return 'Go builder supports Windows, macOS and Linux targets. Architecture can be selected manually.';
        },

        isGoBuilder() {
            return this.agentForm.builder === 'go';
        },

        isBundleBuilder() {
            return this.agentForm.builder === 'bundle';
        },

        isPyInstallerBuilder() {
            return this.agentForm.builder === 'pyinstaller';
        },

        isAgentTargetOsDisabled() {
            return this.isBundleBuilder || this.isPyInstallerBuilder;
        },

        isAgentTargetArchDisabled() {
            return this.isBundleBuilder || this.isPyInstallerBuilder;
        }
    },

    methods: {
        async loadAgentServerPlatform() {
            try {
                const res = await fetch('/api/agent/platform');
                const json = await res.json();
                if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load server platform');
                const targetOs = String(json.data?.target_os || 'mac').trim() || 'mac';
                this.agentServerTargetOs = targetOs;
            } catch (_error) {
                this.agentServerTargetOs = 'mac';
            }
        },

        async openAgentBuilderDialog() {
            this.agentBuilderDialogVisible = true;
            this.agentForm.server_host = window.location.hostname || '127.0.0.1';
            this.agentForm.server_port = 9999;
            this.agentForm.web_port = 8085;
            await this.loadAgentServerPlatform();
            this.applyAgentBuilderRules();
        },

        applyAgentBuilderRules() {
            if (this.agentForm.builder === 'bundle') {
                this.agentForm.target_arch = 'auto';
                return;
            }

            if (this.agentForm.builder === 'pyinstaller') {
                this.agentForm.target_os = this.agentServerTargetOs || 'mac';
                this.agentForm.target_arch = 'auto';
                return;
            }

            if (this.agentForm.target_os === 'win') {
                if (this.agentForm.target_arch === 'auto') {
                    this.agentForm.target_arch = 'amd64';
                }
                return;
            }

            if (this.agentForm.target_os === 'linux') {
                if (this.agentForm.target_arch === 'auto') {
                    this.agentForm.target_arch = 'amd64';
                }
                return;
            }
        },

        buildAgentPayload() {
            const payload = {
                ...this.agentForm,
                server_web_scheme: window.location.protocol.replace(':', '') || 'http',
                server_web_host: window.location.hostname || this.agentForm.server_host,
            };

            if (this.agentForm.builder === 'bundle') {
                payload.target_os = 'bundle';
                payload.target_arch = 'auto';
            } else if (this.agentForm.builder === 'pyinstaller') {
                payload.target_os = this.agentServerTargetOs || this.agentForm.target_os || 'mac';
                payload.target_arch = 'auto';
            }

            return payload;
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
                    body: JSON.stringify(this.buildAgentPayload())
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Build failed');
                }

                const data = json.data;
                const downloadUrl = data.download_url || `/api/agent/download/${encodeURIComponent(data.file_name)}`;

                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = data.file_name;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);

                if (Array.isArray(data.warnings) && data.warnings.length > 0) {
                    data.warnings.forEach(msg => {
                        if (msg) ElementPlus.ElMessage.warning(msg);
                    });
                }

                const buildVersionText = data.build_version ? `, ${data.build_version}` : '';
                ElementPlus.ElMessage.success(`Agent built: ${data.file_name} (${this.formatBytes(data.size)})${buildVersionText}`);
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
            this.applyAgentBuilderRules();
        },

        'agentForm.target_os'() {
            this.applyAgentBuilderRules();
        }
    }
};
