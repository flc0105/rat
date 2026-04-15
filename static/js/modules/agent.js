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
                builder: 'bundle',
                target_arch: 'arm64',
            }
        };
    },

    computed: {
        agentBuilderAlertText() {
            if (this.agentForm.builder === 'pyinstaller') {
                return `Standalone executable. Can only build for the same OS as the current server (${this.describeAgentTargetOs(this.agentServerTargetOs)}).`;
            }

            if (this.agentForm.builder === 'bundle') {
                return 'Source ZIP bundle. Includes the Python client source files.';
            }

            if (this.agentForm.builder === 'go_loader') {
                return 'Small Go loader. Downloads the bundle ZIP and runs it with Python.';
            }

            return 'Lightweight Go client for basic commands.';
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
        describeAgentTargetOs(targetOs) {
            const mapping = {
                win: 'Windows',
                mac: 'macOS',
                linux: 'Linux',
                bundle: 'Bundle',
            };
            return mapping[targetOs] || targetOs || 'macOS';
        },

        getDefaultAgentTargetArch(targetOs) {
            const normalizedTargetOs = String(targetOs || '').trim().toLowerCase();

            if (normalizedTargetOs === 'win') return 'amd64';
            if (normalizedTargetOs === 'mac') return 'arm64';
            return 'amd64';
        },

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
                this.agentForm.target_os = 'mac';
                this.agentForm.target_arch = 'arm64';
                return;
            }

            if (this.agentForm.builder === 'pyinstaller') {
                this.agentForm.target_os = this.agentServerTargetOs || 'mac';
                this.agentForm.target_arch = this.getDefaultAgentTargetArch(this.agentForm.target_os);
                return;
            }

            this.agentForm.target_arch = this.getDefaultAgentTargetArch(this.agentForm.target_os);
        },

        buildAgentPayload() {
            const payload = {
                ...this.agentForm,
                server_web_scheme: window.location.protocol.replace(':', '') || 'http',
                server_web_host: this.agentForm.server_host,
            };

            if (this.agentForm.builder === 'bundle') {
                payload.target_os = 'bundle';
                payload.target_arch = '';
            } else if (this.agentForm.builder === 'pyinstaller') {
                payload.target_os = this.agentServerTargetOs || this.agentForm.target_os || 'mac';
                payload.target_arch = '';
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

                ElementPlus.ElMessage.success('Build completed. Downloading...');

                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = data.file_name;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);

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