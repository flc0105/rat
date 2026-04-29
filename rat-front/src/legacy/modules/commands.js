export default {
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
            // const commandInput = this.$refs.commandInputRef;
            // if (commandInput && typeof commandInput.close === 'function') {
            //     commandInput.close();
            // }

            const commandInputBar = this.$refs.commandInputBarRef;
if (commandInputBar && typeof commandInputBar.closeAutocomplete === 'function') {
    commandInputBar.closeAutocomplete();
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
                this.appendOutput(this.selectedId, '[Command failed] ' + (e.message || 'unknown error'), 'error');
                ElementPlus.ElMessage.error(e.message || 'Command failed');
                this.commandText = '';
            } finally {
                this.sending = false;
            }
        },

        // async killConnection() {
        //     if (!this.selectedId) {
        //         ElementPlus.ElMessage.warning('Please select a device');
        //         return;
        //     }
        //
        //     try {
        //         const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/kill`, {
        //             method: 'POST'
        //         });
        //
        //         const json = await res.json();
        //         if (!res.ok || json.code !== 0) {
        //             throw new Error(json.message || 'Disconnect failed');
        //         }
        //
        //         ElementPlus.ElMessage.success('Disconnect command sent');
        //     } catch (e) {
        //         ElementPlus.ElMessage.error(e.message || 'Disconnect failed');
        //     }
        // },

        // add http control toolbar actions 2026-04-10 00:00
        // async sendHttpControlCommand(command) {
        //     if (!this.selectedId) {
        //         ElementPlus.ElMessage.warning('Please select a device');
        //         return;
        //     }
        //
        //     const normalizedCommand = String(command || '').trim().toLowerCase();
        //     if (!normalizedCommand) {
        //         ElementPlus.ElMessage.warning('Invalid control command');
        //         return;
        //     }
        //
        //     const actionMap = {
        //         kill: 'Force Kill',
        //         spawn: 'Force Spawn',
        //         reset: 'Force Reset'
        //     };
        //     const actionLabel = actionMap[normalizedCommand];
        //     // const actionLabel = normalizedCommand === 'kill' ? 'Force Kill' : 'Force Reset';
        //
        //     try {
        //         await ElementPlus.ElMessageBox.confirm(
        //             `Send ${actionLabel} to current device?\n\nThis action is delivered by polling and may take a short delay before the client receives it.`,
        //             'Control Confirmation',
        //             {
        //                 type: 'warning',
        //                 confirmButtonText: 'Confirm',
        //                 cancelButtonText: 'Cancel'
        //             }
        //         );
        //
        //         const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/control`, {
        //             method: 'POST',
        //             headers: {'Content-Type': 'application/json'},
        //             body: JSON.stringify({command: normalizedCommand})
        //         });
        //
        //         const json = await res.json();
        //         if (!res.ok || json.code !== 0) {
        //             throw new Error(json.message || `${actionLabel} failed`);
        //         }
        //
        //         ElementPlus.ElMessage.success(`${actionLabel} command queued. This may take a short delay because the client checks by polling.`);
        //     } catch (e) {
        //         if (e === 'cancel' || e === 'close' || e?.message === 'cancel') {
        //             return;
        //         }
        //         ElementPlus.ElMessage.error(e.message || 'Control command failed');
        //     }
        // },


        // add http control toolbar actions 2026-04-10 00:00
        // async handleControlActionCommand(command) {
        //     const normalizedCommand = String(command || '').trim().toLowerCase();
        //
        //     // if (normalizedCommand === 'disconnect') {
        //     //     await this.killConnection();
        //     //     return;
        //     // }
        //
        //     if (normalizedCommand === 'kill' || normalizedCommand === 'reset' || normalizedCommand === 'spawn') {
        //         await this.sendHttpControlCommand(normalizedCommand);
        //         return;
        //     }
        //
        //     ElementPlus.ElMessage.warning('Unknown control action');
        // },

    }
};