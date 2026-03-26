
window.AppJobCreatorModule = {

    // methods: {
        // openJobCreatorDialog(scriptName = '') {
        //     this.jobCreatorDialogVisible = true;
        //     this.jobCreatorMode = scriptName ? 'edit' : 'new';
        //     this.jobCreatorOriginalName = scriptName || '';
        //     this.jobCreatorName = scriptName ? scriptName.replace(/\.py$/, '') : '';
        //     this.jobCreatorDescription = '';
        //     this.jobCreatorContent = '';
        //
        //     if (scriptName) {
        //         this.loadScriptForEdit(scriptName);
        //     } else {
        //         this.initJobCreatorEditor('# Your job code here\n\nimport time\nfrom client.jobs.core.job import Job\n\n\nclass MyJob(Job):\n    def __init__(self):\n        super().__init__()\n        self.interval = 5\n\n    def run(self):\n        self.mark_running()\n        self.send_to_server(1, "My job started")\n\n        while not self.stop_event.is_set():\n            self.send_to_server(1, "Working...")\n            time.sleep(self.interval)\n\n        self.send_to_server(1, "My job stopped")\n\n    def stop(self, notify=True):\n        self.request_stop(notify=notify)\n');
        //     }
        // },

        // async loadScriptForEdit(scriptName) {
        //     this.jobCreatorLoading = true;
        //     try {
        //         const res = await fetch(`/api/server/jobs/download?name=${encodeURIComponent(scriptName)}`);
        //         if (!res.ok) {
        //             throw new Error(`Failed to load script: ${res.statusText}`);
        //         }
        //         this.jobCreatorContent = await res.text();
        //
        //         // 尝试从内容中提取描述
        //         const lines = this.jobCreatorContent.split('\n');
        //         for (const line of lines) {
        //             if (line.trim().startsWith('#')) {
        //                 this.jobCreatorDescription = line.trim().substring(1).trim();
        //                 break;
        //             }
        //         }
        //
        //         this.initJobCreatorEditor(this.jobCreatorContent);
        //     } catch (e) {
        //         ElementPlus.ElMessage.error(e.message || 'Failed to load script');
        //     } finally {
        //         this.jobCreatorLoading = false;
        //     }
        // },

        // initJobCreatorEditor(content) {
        //     this.$nextTick(() => {
        //         const container = document.getElementById('job-creator-editor');
        //         if (!container) return;
        //
        //         if (this.jobCreatorEditor) {
        //             this.jobCreatorEditor.dispose();
        //         }
        //
        //         require.config({ paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' } });
        //         require(['vs/editor/editor.main'], () => {
        //             this.jobCreatorEditor = monaco.editor.create(container, {
        //                 value: content,
        //                 language: 'python',
        //                 theme: 'vs-dark',
        //                 automaticLayout: true,
        //                 fontSize: 13,
        //                 fontFamily: 'Monaco, Menlo, "Ubuntu Mono", Consolas, monospace',
        //                 lineNumbers: 'on',
        //                 minimap: { enabled: false },
        //                 scrollBeyondLastLine: false,
        //                 wordWrap: 'on',
        //                 tabSize: 4,
        //                 insertSpaces: true,
        //             });
        //             this.jobCreatorMonacoReady = true;
        //         });
        //     });
        // },

    //     getJobCreatorEditorContent() {
    //         if (this.jobCreatorEditor) {
    //             return this.jobCreatorEditor.getValue();
    //         }
    //         return this.jobCreatorContent;
    //     },
    //
    //     async saveJobCreator() {
    //         const name = this.jobCreatorName.trim();
    //         if (!name) {
    //             ElementPlus.ElMessage.warning('Please enter a job name');
    //             return;
    //         }
    //
    //         const scriptName = name.endsWith('.py') ? name : `${name}.py`;
    //         const content = this.getJobCreatorEditorContent();
    //
    //         if (!content.trim()) {
    //             ElementPlus.ElMessage.warning('Job content cannot be empty');
    //             return;
    //         }
    //
    //         this.jobCreatorSaving = true;
    //
    //         try {
    //             const res = await fetch('/api/scripts/upload', {
    //                 method: 'POST',
    //                 headers: { 'Content-Type': 'application/json' },
    //                 body: JSON.stringify({
    //                     name: scriptName,
    //                     content: content,
    //                     overwrite: true,
    //                 })
    //             });
    //
    //             const json = await res.json();
    //             if (!res.ok || json.code !== 0) {
    //                 throw new Error(json.message || 'Save failed');
    //             }
    //
    //             ElementPlus.ElMessage.success(`Job "${scriptName}" saved`);
    //
    //             this.jobCreatorDialogVisible = false;
    //
    //             // 刷新可用的脚本列表
    //             if (this.backgroundJobsDialogVisible) {
    //                 await this.loadBackgroundJobModules();
    //             }
    //         } catch (e) {
    //             ElementPlus.ElMessage.error(e.message || 'Save failed');
    //         } finally {
    //             this.jobCreatorSaving = false;
    //         }
    //     },
    //
    //     closeJobCreatorDialog() {
    //         this.jobCreatorDialogVisible = false;
    //         if (this.jobCreatorEditor) {
    //             this.jobCreatorEditor.dispose();
    //             this.jobCreatorEditor = null;
    //         }
    //     },
    //
    //     async deleteRemoteScript(scriptName) {
    //         try {
    //             await ElementPlus.ElMessageBox.confirm(
    //                 `Delete job "${scriptName}"?`,
    //                 'Delete Confirmation',
    //                 {
    //                     type: 'warning',
    //                     confirmButtonText: 'Delete',
    //                     cancelButtonText: 'Cancel'
    //                 }
    //             );
    //
    //             const res = await fetch(`/api/scripts/${encodeURIComponent(scriptName)}`, {
    //                 method: 'DELETE'
    //             });
    //
    //             const json = await res.json();
    //             if (!res.ok || json.code !== 0) {
    //                 throw new Error(json.message || 'Delete failed');
    //             }
    //
    //             ElementPlus.ElMessage.success(`Job "${scriptName}" deleted`);
    //             await this.loadBackgroundJobModules();
    //         } catch (e) {
    //             if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
    //             ElementPlus.ElMessage.error(e.message || 'Delete failed');
    //         }
    //     },
    //
    //     async startRemoteScript(scriptName) {
    //         if (!this.selectedId) {
    //             ElementPlus.ElMessage.warning('Please select a device');
    //             return;
    //         }
    //
    //         try {
    //             const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command`, {
    //                 method: 'POST',
    //                 headers: this.getTabScopedHeaders({ 'Content-Type': 'application/json' }),
    //                 body: JSON.stringify({ command: `start_job_remote ${scriptName}` })
    //             });
    //
    //             const json = await res.json();
    //             if (!res.ok || json.code !== 0) {
    //                 throw new Error(json.message || 'Start failed');
    //             }
    //
    //             const taskId = json.data && json.data.task_id;
    //             this.setActiveTask(this.selectedId, taskId || '');
    //
    //             ElementPlus.ElMessage.success(`Remote job started: ${scriptName}`);
    //
    //             this.backgroundJobsActiveTab = 'jobs';
    //             await this.loadBackgroundJobs();
    //         } catch (e) {
    //             ElementPlus.ElMessage.error(e.message || 'Start failed');
    //         }
    //     },
    // }
};