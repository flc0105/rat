export default {
    data() {
        return {
            agentBuilderDialogVisible: false,
            agentOutputsDialogVisible: false,
            agentBuilding: false,
            agentOutputsLoading: false,
            agentOutputsDeleting: {},
            agentServerTargetOs: 'mac',
            agentOutputs: [],
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
                return 'Source ZIP package. Includes the Python client source files.';
            }

            if (this.agentForm.builder === 'go_loader') {
                return 'Downloads the bundle and runs it with Python.';
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

        formatAgentListenerText(row) {
            const host = String(row?.server_host || '').trim();
            const port = Number(row?.server_port || 0);
            if (!host || !port) return '-';
            return `${host}:${port}`;
        },

        formatAgentWebListenerText(row) {
            const scheme = String(row?.server_web_scheme || 'http').trim() || 'http';
            const host = String(row?.server_web_host || row?.server_host || '').trim();
            const port = Number(row?.web_port || 0);
            if (!host || !port) return '-';
            return `${scheme}://${host}:${port}`;
        },

        formatAgentSourceText(value) {
            const source = String(value || '').trim();
            if (!source) return '-';

            const mapping = {
                manual: 'Manual',
                update: 'Update',
                loader: 'Loader',
            };
            return mapping[source] || source;
        },

        isAgentOutputDeleting(fileName) {
            return Boolean(this.agentOutputsDeleting[String(fileName || '').trim()]);
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

        async openAgentOutputsDialog() {
            this.agentOutputsDialogVisible = true;
            await this.loadAgentOutputs();
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
                source: 'manual',
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

        async loadAgentOutputs({silent = false} = {}) {
            if (!silent) this.agentOutputsLoading = true;
            try {
                const res = await fetch('/api/agent/outputs');
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load agent outputs');
                }
                this.agentOutputs = Array.isArray(json.data) ? json.data : [];
            } catch (e) {
                this.agentOutputs = [];
                if (!silent) {
                    ElementPlus.ElMessage.error(e.message || 'Failed to load agent outputs');
                }
            } finally {
                if (!silent) this.agentOutputsLoading = false;
            }
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

                const data = json.data || {};
                const downloadUrl = data.download_url || `/api/agent/download/${encodeURIComponent(data.file_name)}`;

                ElementPlus.ElMessage.success('Build completed. Downloading...');

                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = data.file_name;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);

                this.agentBuilderDialogVisible = false;

                if (this.agentOutputsDialogVisible) {
                    await this.loadAgentOutputs({silent: true});
                }
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Build failed');
            } finally {
                this.agentBuilding = false;
            }
        },

        async deleteAgentOutput(row) {
            const fileName = String(row?.file_name || '').trim();
            if (!fileName) return;

            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Delete agent output ${fileName}?`,
                    'Delete agent output',
                    {
                        confirmButtonText: 'Delete',
                        cancelButtonText: 'Cancel',
                        type: 'warning',
                    }
                );
            } catch (_e) {
                return;
            }

            this.agentOutputsDeleting = {
                ...this.agentOutputsDeleting,
                [fileName]: true,
            };

            try {
                const res = await fetch(`/api/agent/outputs/${encodeURIComponent(fileName)}`, {
                    method: 'DELETE',
                });
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Delete failed');
                }

                this.agentOutputs = this.agentOutputs.filter(item => String(item?.file_name || '').trim() !== fileName);
                ElementPlus.ElMessage.success('Deleted');
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Delete failed');
            } finally {
                this.agentOutputsDeleting = {
                    ...this.agentOutputsDeleting,
                    [fileName]: false,
                };
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