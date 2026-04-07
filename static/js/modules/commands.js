window.AppCommandsModule = {
    data() {
        return {
            commandText: '',
            sending: false,
        }
    },

    methods: {
        async sendCommand() {
            const command = (this.commandText || '').trim();

            // add 暂时关闭命令自动补全下拉 2026-04-07
            const commandInput = this.$refs.commandInputRef;
            if (commandInput && typeof commandInput.close === 'function') {
                commandInput.close();
            }

            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            if (!command) {
                ElementPlus.ElMessage.warning('Please enter a command');
                return;
            }

            this.sending = true;
            this.appendOutput(this.selectedId, '> ' + command, 'command');

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command`, {
                    method: 'POST',
                    headers: this.getTabScopedHeaders({'Content-Type': 'application/json'}),
                    body: JSON.stringify({command})
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Command failed');
                }

                const taskId = json.data && json.data.task_id;
                this.setActiveTask(this.selectedId, taskId || '');

                this.commandText = '';
                this.commandCandidatesLoadedFor = '';
                await this.loadCommandCandidates(this.selectedId);
            } catch (e) {
                this.appendOutput(this.selectedId, '[发送失败] ' + (e.message || 'unknown error'), 'error');
                ElementPlus.ElMessage.error(e.message || 'Command failed');
            } finally {
                this.sending = false;
            }
        },

        async killConnection() {
            if (!this.selectedId) {
                ElementPlus.ElMessage.warning('Please select a device');
                return;
            }

            try {
                const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/kill`, {
                    method: 'POST'
                });

                const json = await res.json();
                if (!res.ok || json.code !== 0) {
                    throw new Error(json.message || 'Disconnect failed');
                }

                ElementPlus.ElMessage.success('Disconnect command sent');
            } catch (e) {
                ElementPlus.ElMessage.error(e.message || 'Disconnect failed');
            }
        },
    }
};