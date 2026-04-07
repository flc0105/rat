window.AppArtifactsModule = {
    data() {
        return {
            artifactDialogVisible: false,
            artifactLoading: false,
            artifactItems: [],
            artifactHostnames: [],
            artifactActiveTab: 'files',
            artifactHostnameFilter: '',
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
                const hostname = String(this.artifactHostnameFilter || '').trim();

                if (hostname) url.searchParams.set('hostname', hostname);

                const res = await fetch(url.pathname + url.search);
                const json = await res.json();

                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Failed to load artifacts');
                }

                const data = json.data || {};
                this.artifactItems = Array.isArray(data.items) ? data.items : [];
                this.artifactHostnames = Array.isArray(data.hostnames) ? data.hostnames : [];
            } catch (e) {
                this.artifactItems = [];
                this.artifactHostnames = [];
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
                    {
                        type: 'warning',
                        confirmButtonText: 'Delete',
                        cancelButtonText: 'Cancel'
                    }
                );

                const res = await fetch(`/api/artifacts/${encodeURIComponent(row.artifact_id)}`, {
                    method: 'DELETE'
                });

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
                const hostnameText = this.artifactHostnameFilter ? ` for ${this.artifactHostnameFilter}` : '';
                await ElementPlus.ElMessageBox.confirm(
                    `Clear all ${activeType}${hostnameText}?`,
                    'Clear Artifacts',
                    {
                        type: 'warning',
                        confirmButtonText: 'Clear',
                        cancelButtonText: 'Cancel'
                    }
                );

                this.artifactClearing = true;
                const res = await fetch('/api/artifacts/clear', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        type: activeType,
                        hostname: this.artifactHostnameFilter || ''
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
            const hostname = String(this.artifactHostnameFilter || '').trim();

            return (this.artifactItems || []).filter(item => {
                if (activeType && item.artifact_type !== activeType) return false;
                if (hostname && item.hostname !== hostname) return false;
                return true;
            });
        },

        artifactCountMap() {
            const hostname = String(this.artifactHostnameFilter || '').trim();
            const counts = {
                files: 0,
                previews: 0,
            };

            (this.artifactItems || []).forEach(item => {
                if (!item) return;
                if (hostname && item.hostname !== hostname) return false;

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
                this.artifactHostnameFilter = '';
            }
        },
    }
}