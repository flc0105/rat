export default {
    data() {
        return {
            agentOutputsDialogVisible: false,
            agentOutputsLoading: false,
            agentOutputsDeleting: {},
            agentOutputs: [],
        };
    },

    computed: {},

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

        async openAgentOutputsDialog() {
            this.agentOutputsDialogVisible = true;
            await this.loadAgentOutputs();
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
        },
    },

    watch: {},
};