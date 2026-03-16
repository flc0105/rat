const { createApp, nextTick } = Vue;

createApp({
  data() {
    return {
      connections: [],
      selectedId: '',
      outputs: {},
      commandText: '',
      sending: false,
      uploading: false,
      eventSource: null,
      sseReady: false,

      recentFilesDialogVisible: false,
      recentFilesLoading: false,
      recentFiles: []
    };
  },

  computed: {
    currentConnection() {
      return this.connections.find(item => item.client_id === this.selectedId) || null;
    },
    currentOutput() {
      return this.outputs[this.selectedId] || '';
    }
  },

  mounted() {
    this.loadConnections();
    this.initSSE();
  },

  beforeUnmount() {
    if (this.eventSource) {
      this.eventSource.close();
    }
  },

  methods: {
    async loadConnections() {
      try {
        const res = await fetch('/api/connections');
        const json = await res.json();
        this.connections = json.data || [];

        if (!this.selectedId && this.connections.length > 0) {
          this.selectedId = this.connections[0].client_id;
        }

        if (this.selectedId && !this.connections.find(item => item.client_id === this.selectedId)) {
          this.selectedId = this.connections.length > 0 ? this.connections[0].client_id : '';
        }
      } catch (e) {
        ElementPlus.ElMessage.error('加载设备列表失败');
      }
    },

    selectConnection(clientId) {
      this.selectedId = clientId;
      if (!this.outputs[clientId]) {
        this.outputs[clientId] = '';
      }
      this.scrollToBottom();
    },

    appendOutput(clientId, text) {
      if (!clientId) return;

      if (!this.outputs[clientId]) {
        this.outputs[clientId] = '';
      }

      this.outputs[clientId] += String(text ?? '');

      if (!this.outputs[clientId].endsWith('\n')) {
        this.outputs[clientId] += '\n';
      }

      this.scrollToBottom();
    },

    async sendCommand() {
      const command = (this.commandText || '').trim();

      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('请先选择设备');
        return;
      }

      if (!command) {
        ElementPlus.ElMessage.warning('请输入命令');
        return;
      }

      this.sending = true;
      this.appendOutput(this.selectedId, '> ' + command);

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ command })
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || '发送命令失败');
        }

        this.commandText = '';
      } catch (e) {
        this.appendOutput(this.selectedId, '[发送失败] ' + (e.message || 'unknown error'));
        ElementPlus.ElMessage.error(e.message || '发送命令失败');
      } finally {
        this.sending = false;
      }
    },

    async killConnection() {
      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('请先选择设备');
        return;
      }

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/kill`, {
          method: 'POST'
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || '断开失败');
        }

        ElementPlus.ElMessage.success('断开命令已发送');
      } catch (e) {
        ElementPlus.ElMessage.error(e.message || '断开失败');
      }
    },

    triggerUpload() {
      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('请先选择设备');
        return;
      }

      const input = this.$refs.uploadInputRef;
      if (input) {
        input.value = '';
        input.click();
      }
    },

    async handleUploadChange(event) {
      const file = event.target.files && event.target.files[0];
      if (!file) return;

      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('请先选择设备');
        return;
      }

      const formData = new FormData();
      formData.append('file', file);

      this.uploading = true;
      this.appendOutput(this.selectedId, `> [上传文件] ${file.name}`);

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/upload`, {
          method: 'POST',
          body: formData
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || '上传失败');
        }

        ElementPlus.ElMessage.success(`已开始上传：${file.name}`);
      } catch (e) {
        this.appendOutput(this.selectedId, `[上传失败] ${e.message || 'unknown error'}`);
        ElementPlus.ElMessage.error(e.message || '上传失败');
      } finally {
        this.uploading = false;
      }
    },

    async openRecentFilesDialog() {
      this.recentFilesDialogVisible = true;
      this.recentFilesLoading = true;

      try {
        const res = await fetch('/api/files/recent');
        const json = await res.json();

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || '加载最近文件失败');
        }

        this.recentFiles = json.data || [];
      } catch (e) {
        ElementPlus.ElMessage.error(e.message || '加载最近文件失败');
      } finally {
        this.recentFilesLoading = false;
      }
    },

    clearOutput() {
      if (this.selectedId) {
        this.outputs[this.selectedId] = '';
      }
    },

    scrollToBottom() {
      nextTick(() => {
        const el = this.$refs.terminalRef;
        if (el) {
          el.scrollTop = el.scrollHeight;
        }
      });
    },

    upsertConnection(conn) {
      const idx = this.connections.findIndex(item => item.client_id === conn.client_id);
      if (idx === -1) {
        this.connections.unshift(conn);
      } else {
        this.connections[idx] = conn;
      }

      if (!this.selectedId) {
        this.selectedId = conn.client_id;
      }
    },

    removeConnection(clientId) {
      this.connections = this.connections.filter(item => item.client_id !== clientId);
      if (this.selectedId === clientId) {
        this.selectedId = this.connections.length ? this.connections[0].client_id : '';
      }
    },

    formatBytes(size) {
      const value = Number(size || 0);
      if (value < 1024) return `${value} B`;
      if (value < 1024 * 1024) return `${(value / 1024).toFixed(2)} KB`;
      if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(2)} MB`;
      return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`;
    },

    initSSE() {
      if (this.eventSource) {
        this.eventSource.close();
      }

      const es = new EventSource('/api/stream');
      this.eventSource = es;

      es.addEventListener('open', () => {
        if (!this.sseReady) {
          this.sseReady = true;
        }
      });

      es.addEventListener('connection_online', (event) => {
        const payload = JSON.parse(event.data);
        const conn = payload.connection;
        this.upsertConnection(conn);

        ElementPlus.ElNotification({
          title: '设备上线',
          message: `${conn.hostname || conn.client_id} 已上线`,
          type: 'success'
        });
      });

      es.addEventListener('connection_offline', (event) => {
        const payload = JSON.parse(event.data);
        const clientId = payload.client_id;
        const oldConn = this.connections.find(item => item.client_id === clientId);

        this.removeConnection(clientId);

        ElementPlus.ElNotification({
          title: '设备下线',
          message: `${(oldConn && oldConn.hostname) || clientId} 已下线`,
          type: 'warning'
        });
      });

      es.addEventListener('command_result', (event) => {
        const payload = JSON.parse(event.data);
        this.appendOutput(payload.client_id, payload.text || '');
      });

      es.addEventListener('command_complete', (event) => {
        const payload = JSON.parse(event.data);
        this.appendOutput(
          payload.client_id,
          `[命令结束] ${payload.command} (${payload.success ? '成功' : '失败'})`
        );
      });

      es.addEventListener('background_message', (event) => {
        const payload = JSON.parse(event.data);
        this.appendOutput(payload.client_id, `[异步消息] ${payload.text || ''}`);
      });

      es.addEventListener('file_received', (event) => {
        const payload = JSON.parse(event.data);

        ElementPlus.ElNotification({
          title: '收到文件',
          message: `${payload.original_name} 已保存到服务器文件区`,
          type: 'success'
        });

        if (this.recentFilesDialogVisible) {
          this.openRecentFilesDialog();
        }
      });

      es.onerror = () => {
        // EventSource 会自动重连
      };
    }
  }
}).use(ElementPlus).mount('#app');