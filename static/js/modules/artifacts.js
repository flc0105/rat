window.AppArtifactsModule = {
    data() {
        return {
            artifactDialogVisible: false,
            artifactLoading: false,
            artifactItems: [],
            artifactMachines: [],
            artifactActiveTab: 'files',
            artifactMachineIdFilter: '',
            artifactClearing: false,
        };
    },
    methods: {
        async openArtifactDialog() {
            this.artifactDialogVisible = true;
            await this.loadArtifacts();
        },

        async loadArtifacts() {
            this.artifactLoading = true;
            try {
                const url = new URL('/api/artifacts', window.location.origin);
                const machineId = String(this.artifactMachineIdFilter || '').trim();
                if (machineId) url.searchParams.set('machine_id', machineId);

                const res = await fetch(url.pathname + url.search);
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load artifacts');
                }

                const data = json.data || {};
                this.artifactItems = Array.isArray(data.items) ? data.items : [];
                this.artifactMachines = Array.isArray(data.machines) ? data.machines : [];
            } catch (e) {
                this.artifactItems = [];
                this.artifactMachines = [];
                ElementPlus.ElMessage.error(e.message || 'Failed to load artifacts');
            } finally {
                this.artifactLoading = false;
            }
        },

        async deleteArtifact(row) {
            if (!row || !row.artifact_id) {
                ElementPlus.ElMessage.warning('Invalid artifact');
                return;
            }
            try {
                await ElementPlus.ElMessageBox.confirm(
                    `Delete "${row.original_name || row.stored_name}"?`,
                    'Delete Confirmation',
                    {type: 'warning', confirmButtonText: 'Delete', cancelButtonText: 'Cancel'}
                );
                const res = await fetch(`/api/artifacts/${encodeURIComponent(row.artifact_id)}`, {method: 'DELETE'});
                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Delete failed');
                }
                ElementPlus.ElMessage.success('Deleted');
                await this.loadArtifacts();
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Delete failed');
            }
        },

        async clearArtifactCategory() {
            const activeType = String(this.artifactActiveTab || '').trim();
            if (!activeType) {
                ElementPlus.ElMessage.warning('Please select a category');
                return;
            }
            try {
                const suffix = this.artifactMachineIdFilter ? ' for selected device' : '';
                await ElementPlus.ElMessageBox.confirm(
                    `Clear all ${activeType}${suffix}?`,
                    'Clear Artifacts',
                    {type: 'warning', confirmButtonText: 'Clear', cancelButtonText: 'Cancel'}
                );

                this.artifactClearing = true;
                const res = await fetch('/api/artifacts/clear', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        type: activeType,
                        machine_id: this.artifactMachineIdFilter || ''
                    })
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Clear failed');
                }

                ElementPlus.ElMessage.success(`Cleared ${json.data?.deleted_count || 0} item(s)`);
                await this.loadArtifacts();
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
                ElementPlus.ElMessage.error(e.message || 'Clear failed');
            } finally {
                this.artifactClearing = false;
            }
        },
    },

    computed: {
        filteredArtifactItems() {
            const activeType = String(this.artifactActiveTab || '').trim();
            const machineId = String(this.artifactMachineIdFilter || '').trim();
            return (this.artifactItems || []).filter(item => {
                if (activeType && item.artifact_type !== activeType) return false;
                if (machineId && item.machine_id !== machineId) return false;
                return true;
            });
        },

        artifactCountMap() {
            const machineId = String(this.artifactMachineIdFilter || '').trim();
            const counts = {files: 0, previews: 0};
            (this.artifactItems || []).forEach(item => {
                if (!item) return;
                if (machineId && item.machine_id !== machineId) return;
                const type = String(item.artifact_type || '').trim();
                if (Object.prototype.hasOwnProperty.call(counts, type)) {
                    counts[type] += 1;
                }
            });
            return counts;
        },
    },

    watch: {
        artifactDialogVisible(val) {
            if (!val) {
                this.artifactMachineIdFilter = '';
            }
        },
    }
}
