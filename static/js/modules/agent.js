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
            }
        };
    },

    computed: {
        agentBuilderAlertType() {
            return this.agentForm.builder === 'pyinstaller' ? 'warning' : 'info';
        },

        agentBuilderAlertTitle() {
            return this.agentForm.builder === 'pyinstaller'
                ? 'PyInstaller 限制说明'
                : 'Go（基础版）说明';
        },

        agentBuilderAlertText() {
            if (this.agentForm.builder === 'pyinstaller') {
                return 'PyInstaller 只能打包与当前服务端相同的平台。\n'
                    + '如果当前服务端跑在 macOS，就只能打 macOS；跑在 Windows，就只能打 Windows；跑在 Linux，就只能打 Linux。\n'
                    + '若你需要跨平台构建，请改用 Go（基础版）。';
            }

            return 'Go（基础版）会打包项目目录下的 client-go，并按你当前选择的目标平台构建。\n'
                + '连接地址会使用本窗口填写的 Server IP / Server Port / Web Port。\n'
                + '基础版能力较少，但适合快速跨平台生成。';
        }
    },

    methods: {
        openAgentBuilderDialog() {
            this.agentBuilderDialogVisible = true;
            this.agentForm.server_host = window.location.hostname || '127.0.0.1';
            this.agentForm.server_port = 9999;
            this.agentForm.web_port = 8085;
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
    }
};
