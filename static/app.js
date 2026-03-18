const { createApp, nextTick } = Vue;

createApp({
  data() {
    return {
      connections: [],
      selectedId: '',
      outputs: {},
      commandText: '',
      commandCandidates: [],
      commandCandidatesLoadedFor: '',
      commandHistoryDialogVisible: false,
      commandHistoryLoading: false,
      commandHistoryItems: [],
      commandShortcutHistoryCommands: [],
      commandShortcutHistoryLoadedFor: '',
      commandShortcutHistoryIndex: -1,
      commandShortcutDraft: '',
      commandShortcutApplying: false,
      sending: false,
      uploading: false,
      eventSource: null,
      sseReady: false,

      remoteFilesDialogVisible: false,
      remoteFilesLoading: false,
      remoteFilesCurrentPath: '',
      remoteFilesParentPath: '',
      remoteFilesEntries: [],
      remoteFilesPathInput: '',
      remoteUploadLoading: false,
      showHiddenFiles: false,

      recentFilesDialogVisible: false,
      recentFilesLoading: false,
      recentFiles: [],

      previewDialogVisible: false,
      previewLoading: false,
      previewType: '',
      previewTitle: '',
      previewUrl: '',
      previewText: ''
    };
  },

  watch: {
    previewDialogVisible(val) {
      if (!val) this.resetPreviewState();
    },
    remoteFilesDialogVisible(val) {
      if (!val) this.resetRemoteFilesState();
    }
  },

  computed: {
    currentConnection() {
      return this.connections.find(item => item.client_id === this.selectedId) || null;
    },
    currentOutputLines() {
      return this.outputs[this.selectedId] || [];
    },
    filteredRemoteFilesEntries() {
      if (this.showHiddenFiles) return this.remoteFilesEntries;
      return this.remoteFilesEntries.filter(item => !item.is_hidden);
    }
  },

  mounted() {
    this.loadConnections();
    this.initSSE();
  },

  beforeUnmount() {
    if (this.eventSource) this.eventSource.close();
  },

  methods: {
    resetPreviewState() {
      this.previewType = '';
      this.previewTitle = '';
      this.previewUrl = '';
      this.previewText = '';
    },

    resetRemoteFilesState() {
      this.remoteFilesCurrentPath = '';
      this.remoteFilesParentPath = '';
      this.remoteFilesEntries = [];
      this.remoteFilesPathInput = '';
      this.showHiddenFiles = false;
    },

    resetCommandShortcutNavigation() {
      this.commandShortcutHistoryIndex = -1;
      this.commandShortcutDraft = '';
    },

    onCommandInput() {
      if (this.commandShortcutApplying) {
        this.commandShortcutApplying = false;
        return;
      }
      this.resetCommandShortcutNavigation();
    },

    formatOsLabel(osType, osVer) {
      const type = osType || 'Unknown';
      return osVer ? `${type}` : type;
    },

    formatAddress(addr) {
      if (!addr) return '-';
      const raw = String(addr);
      const parts = raw.split(':');
      if (parts.length >= 2) return parts.slice(0, -1).join(':') || raw;
      return raw;
    },

    buildPromptLabel(conn) {
      if (!conn) return '$';
      return conn.hostname || 'host';
    },

    ensureOutputBucket(clientId) {
      if (!clientId) return;
      if (!this.outputs[clientId]) this.outputs[clientId] = [];
    },

    inferLineKind(text) {
      const value = String(text ?? '');
      if (value.startsWith('> ')) return 'command';
      if (value.startsWith('[发送失败]') || value.startsWith('[上传失败]')) return 'error';
      if (value.startsWith('[异步消息]') || value.startsWith('[Background]')) return 'info';
      if (value.startsWith('[命令结束]') || value.startsWith('[Command finished]')) {
        return /成功|Success/i.test(value) ? 'success' : 'error';
      }
      if (/failed|error|not found|denied|unable/i.test(value)) return 'error';
      if (/completed|success|saved|started|uploaded|downloaded|created|renamed|copied/i.test(value)) return 'success';
      if (/preparing|loading|refresh|connected|disconnected|warning/i.test(value)) return 'info';
      return 'default';
    },

    appendOutput(clientId, text, kind = '') {
      if (!clientId) return;
      this.ensureOutputBucket(clientId);

      const raw = String(text ?? '');
      const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      const segments = normalized.split('\n');

      segments.forEach((segment) => {
        this.outputs[clientId].push({
          text: segment === '' ? ' ' : segment,
          kind: kind || this.inferLineKind(segment),
          isMultiline: segments.length > 1
        });
      });

      this.scrollToBottom();
    },

    async ensureCommandShortcutHistory(clientId) {
      if (!clientId) return;
      if (this.commandShortcutHistoryLoadedFor === clientId && this.commandShortcutHistoryCommands.length) return;

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(clientId)}/command-history`);
        const json = await res.json();

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to load command history');
        }

        const items = Array.isArray(json.data) ? json.data : [];
        this.commandShortcutHistoryCommands = items
          .map(item => String(item.command || '').trim())
          .filter(Boolean);

        this.commandShortcutHistoryLoadedFor = clientId;
      } catch (e) {
        this.commandShortcutHistoryCommands = [];
        this.commandShortcutHistoryLoadedFor = '';
      }
    },

async handleCommandInputKeydown(event) {
  const isHistoryShortcut = event.ctrlKey || event.metaKey || event.altKey;
  if (!isHistoryShortcut) return;
  if (event.key !== 'ArrowUp' && event.key !== 'ArrowDown') return;

      event.preventDefault();

      if (!this.selectedId) return;

      await this.ensureCommandShortcutHistory(this.selectedId);

      const items = this.commandShortcutHistoryCommands;
      if (!items.length) return;

      if (event.key === 'ArrowUp') {
        if (this.commandShortcutHistoryIndex === -1) {
          this.commandShortcutDraft = this.commandText;
          this.commandShortcutHistoryIndex = 0;
        } else if (this.commandShortcutHistoryIndex < items.length - 1) {
          this.commandShortcutHistoryIndex += 1;
        } else {
          return;
        }
      }

      if (event.key === 'ArrowDown') {
        if (this.commandShortcutHistoryIndex === -1) {
          return;
        }

        if (this.commandShortcutHistoryIndex === 0) {
          this.commandShortcutHistoryIndex = -1;
          this.commandShortcutApplying = true;
          this.commandText = this.commandShortcutDraft;
          return;
        }

        this.commandShortcutHistoryIndex -= 1;
      }

      this.commandShortcutApplying = true;
      this.commandText = items[this.commandShortcutHistoryIndex] || '';
    },

    async loadPreviewPayload(fetcher, fallbackTitle = 'File Preview') {
      this.previewDialogVisible = true;
      this.previewLoading = true;
      this.resetPreviewState();

      try {
        const res = await fetcher();
        const json = await res.json();

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Preview failed');
        }

        const data = json.data || {};
        this.previewType = data.type || 'unsupported';
        this.previewTitle = data.name || fallbackTitle;

        if (this.previewType === 'image') {
          this.previewUrl = data.url || '';
        } else if (this.previewType === 'text') {
          this.previewText = data.content || '';
        }
      } catch (e) {
        this.previewDialogVisible = false;
        ElementPlus.ElMessage.error(e.message || 'Preview failed');
      } finally {
        this.previewLoading = false;
      }
    },

    async copyPreviewText() {
      if (!this.previewText) {
        ElementPlus.ElMessage.warning('No preview text available');
        return;
      }

      try {
        await navigator.clipboard.writeText(this.previewText);
        ElementPlus.ElMessage.success('Content copied');
      } catch (e) {
        ElementPlus.ElMessage.error('Failed to copy content');
      }
    },

    openPreviewOriginal() {
      if (!this.previewUrl) {
        ElementPlus.ElMessage.warning('No image available');
        return;
      }
      window.open(this.previewUrl, '_blank');
    },

    async previewRecentFile(row) {
      if (!row || !row.saved_name) {
        ElementPlus.ElMessage.warning('Invalid file');
        return;
      }

      await this.loadPreviewPayload(
        () => fetch(`/api/files/recent/${encodeURIComponent(row.saved_name)}/preview`),
        row.original_name || row.saved_name || 'File Preview'
      );
    },

    async previewRemoteEntry(row) {
      if (!row || !row.path || row.is_dir) {
        ElementPlus.ElMessage.warning('Please select a file');
        return;
      }

      await this.loadPreviewPayload(
        () => fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/preview`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: row.path })
        }),
        row.name || 'File Preview'
      );
    },

    async deleteRecentFile(row) {
      if (!row || !row.saved_name) {
        ElementPlus.ElMessage.warning('Invalid file');
        return;
      }

      try {
        await ElementPlus.ElMessageBox.confirm(
          `Delete "${row.original_name || row.saved_name}"?`,
          'Delete Confirmation',
          {
            type: 'warning',
            confirmButtonText: 'Delete',
            cancelButtonText: 'Cancel'
          }
        );

        const res = await fetch(`/api/files/recent/${encodeURIComponent(row.saved_name)}`, {
          method: 'DELETE'
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Delete failed');
        }

        ElementPlus.ElMessage.success('Deleted');

        if (this.previewDialogVisible && this.previewTitle === (row.original_name || row.saved_name)) {
          this.previewDialogVisible = false;
          this.resetPreviewState();
        }

        await this.openRecentFilesDialog();
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
        ElementPlus.ElMessage.error(e.message || 'Delete failed');
      }
    },

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

        if (this.selectedId) {
          this.loadCommandCandidates(this.selectedId);
          this.commandShortcutHistoryLoadedFor = '';
          this.commandShortcutHistoryCommands = [];
          this.ensureCommandShortcutHistory(this.selectedId);
        }
      } catch (e) {
        ElementPlus.ElMessage.error('Failed to load devices');
      }
    },

    selectConnection(clientId) {
      this.selectedId = clientId;
      this.ensureOutputBucket(clientId);
      this.commandHistoryItems = [];
      this.commandShortcutHistoryLoadedFor = '';
      this.commandShortcutHistoryCommands = [];
      this.resetCommandShortcutNavigation();
      this.loadCommandCandidates(clientId);
      this.ensureCommandShortcutHistory(clientId);
      this.scrollToBottom();
    },

    async loadCommandCandidates(clientId) {
      if (!clientId) return;
      if (this.commandCandidatesLoadedFor === clientId && this.commandCandidates.length) return;

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(clientId)}/command-candidates`);
        const json = await res.json();

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to load command candidates');
        }

        this.commandCandidates = Array.isArray(json.data) ? json.data : [];
        this.commandCandidatesLoadedFor = clientId;
      } catch (e) {
        this.commandCandidates = [];
        this.commandCandidatesLoadedFor = '';
      }
    },

    async sendCommand() {
      const command = (this.commandText || '').trim();

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
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command })
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Command failed');
        }

        this.commandText = '';
        this.resetCommandShortcutNavigation();
        this.commandShortcutHistoryLoadedFor = '';
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

    triggerUpload() {
      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('Please select a device');
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
        ElementPlus.ElMessage.warning('Please select a device');
        return;
      }

      const formData = new FormData();
      formData.append('file', file);

      this.uploading = true;
      this.appendOutput(this.selectedId, `> [Upload] ${file.name}`, 'command');

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/upload`, {
          method: 'POST',
          body: formData
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Upload failed');
        }

        ElementPlus.ElMessage.success(`Upload started: ${file.name}`);
      } catch (e) {
        this.appendOutput(this.selectedId, `[上传失败] ${e.message || 'unknown error'}`, 'error');
        ElementPlus.ElMessage.error(e.message || 'Upload failed');
      } finally {
        this.uploading = false;
      }
    },

    triggerRemoteUpload() {
      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('Please select a device');
        return;
      }

      if (!this.remoteFilesCurrentPath) {
        ElementPlus.ElMessage.warning('Current directory is empty');
        return;
      }

      const input = this.$refs.remoteUploadInputRef;
      if (input) {
        input.value = '';
        input.click();
      }
    },

    async handleRemoteUploadChange(event) {
      const file = event.target.files && event.target.files[0];
      if (!file) return;

      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('Please select a device');
        return;
      }

      if (!this.remoteFilesCurrentPath) {
        ElementPlus.ElMessage.warning('Current directory is empty');
        return;
      }

      const formData = new FormData();
      formData.append('file', file);
      formData.append('target_path', this.remoteFilesCurrentPath);

      this.remoteUploadLoading = true;
      this.appendOutput(
        this.selectedId,
        `> [Remote Upload] ${file.name} -> ${this.remoteFilesCurrentPath}`,
        'command'
      );

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/upload`, {
          method: 'POST',
          body: formData
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Upload failed');
        }

        ElementPlus.ElMessage.success(`Upload started: ${file.name}`);
        await this.refreshRemoteDirectory();
      } catch (e) {
        this.appendOutput(this.selectedId, `[上传失败] ${e.message || 'unknown error'}`, 'error');
        ElementPlus.ElMessage.error(e.message || 'Upload failed');
      } finally {
        this.remoteUploadLoading = false;
      }
    },

    async openRemoteFilesDialog() {
      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('Please select a device');
        return;
      }

      this.remoteFilesDialogVisible = true;
      await this.loadRemoteDirectory('');
    },

    async loadRemoteDirectory(path = '') {
      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('Please select a device');
        return;
      }

      this.remoteFilesLoading = true;

      try {
        const url = new URL(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files`, window.location.origin);
        if (path) url.searchParams.set('path', path);

        const res = await fetch(url.pathname + url.search);
        const json = await res.json();

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to load remote directory');
        }

        const data = json.data || {};
        this.remoteFilesCurrentPath = data.current_path || '';
        this.remoteFilesParentPath = data.parent_path || '';
        this.remoteFilesEntries = data.entries || [];
        this.remoteFilesPathInput = this.remoteFilesCurrentPath || '';
      } catch (e) {
        ElementPlus.ElMessage.error(e.message || 'Failed to load remote directory');
      } finally {
        this.remoteFilesLoading = false;
      }
    },

    async refreshRemoteDirectory() {
      await this.loadRemoteDirectory(this.remoteFilesCurrentPath || '');
    },

    async goToRemoteParent() {
      if (!this.remoteFilesParentPath) return;
      await this.loadRemoteDirectory(this.remoteFilesParentPath);
    },

    async goToRemotePathInput() {
      const path = (this.remoteFilesPathInput || '').trim();
      if (!path) {
        ElementPlus.ElMessage.warning('Please enter a path');
        return;
      }
      await this.loadRemoteDirectory(path);
    },

    async enterRemoteDirectory(row) {
      if (!row || !row.is_dir) return;
      await this.loadRemoteDirectory(row.path);
    },

    handleRemoteRowDblClick(row) {
      if (row && row.is_dir) {
        this.enterRemoteDirectory(row);
      }
    },

    async copyRemotePath(row) {
      if (!row || !row.path) {
        ElementPlus.ElMessage.warning('Invalid path');
        return;
      }

      try {
        await navigator.clipboard.writeText(row.path);
        ElementPlus.ElMessage.success('Path copied');
      } catch (e) {
        ElementPlus.ElMessage.error('Failed to copy path');
      }
    },

    handleRemoteMoreAction(command, row) {
      if (command === 'rename') {
        this.renameRemoteEntry(row);
        return;
      }
      if (command === 'copy_path') {
        this.copyRemotePath(row);
        return;
      }
      if (command === 'delete') {
        this.deleteRemoteEntry(row);
      }
    },

    async createRemoteDirectory() {
      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('Please select a device');
        return;
      }

      if (!this.remoteFilesCurrentPath) {
        ElementPlus.ElMessage.warning('Current directory is empty');
        return;
      }

      try {
        const { value } = await ElementPlus.ElMessageBox.prompt(
          'Enter the new folder name',
          'Create Directory',
          {
            confirmButtonText: 'Create',
            cancelButtonText: 'Cancel',
            inputPattern: /.+/,
            inputErrorMessage: 'Folder name is required'
          }
        );

        const folderName = String(value || '').trim();
        if (!folderName) return;

        const base = this.remoteFilesCurrentPath.replace(/[\\/]+$/, '');
        const separator = base.includes('\\') ? '\\' : '/';
        const fullPath = `${base}${base ? separator : ''}${folderName}`;

        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/mkdir`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: fullPath })
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Create directory failed');
        }

        ElementPlus.ElMessage.success('Directory created');
        await this.refreshRemoteDirectory();
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
        ElementPlus.ElMessage.error(e.message || 'Create directory failed');
      }
    },

    async renameRemoteEntry(row) {
      if (!row || !row.path) {
        ElementPlus.ElMessage.warning('Invalid path');
        return;
      }

      try {
        const { value } = await ElementPlus.ElMessageBox.prompt(
          'Enter the new name',
          'Rename',
          {
            confirmButtonText: 'Rename',
            cancelButtonText: 'Cancel',
            inputValue: row.name || '',
            inputPattern: /.+/,
            inputErrorMessage: 'New name is required'
          }
        );

        const newName = String(value || '').trim();
        if (!newName || newName === row.name) return;

        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/rename`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            old_path: row.path,
            new_name: newName
          })
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Rename failed');
        }

        ElementPlus.ElMessage.success('Renamed');
        await this.refreshRemoteDirectory();
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
        ElementPlus.ElMessage.error(e.message || 'Rename failed');
      }
    },

    async downloadRemoteEntry(row) {
      if (!row || !row.path || row.is_dir) {
        ElementPlus.ElMessage.warning('Please select a file');
        return;
      }

      try {
        const url = new URL(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files/download`, window.location.origin);
        url.searchParams.set('path', row.path);

        const res = await fetch(url.pathname + url.search, { method: 'POST' });
        const json = await res.json();

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Download failed');
        }

        const file = json.data && json.data.file;
        if (!file || !file.saved_name) {
          throw new Error('Download finished, but saved file was not found');
        }

        const downloadUrl = `/api/files/recent/${encodeURIComponent(file.saved_name)}`;
        window.open(downloadUrl, '_blank');

        ElementPlus.ElMessage.success(`Downloaded: ${row.name}`);

        if (this.recentFilesDialogVisible) {
          await this.openRecentFilesDialog();
        }
      } catch (e) {
        ElementPlus.ElMessage.error(e.message || 'Download failed');
      }
    },

    async deleteRemoteEntry(row) {
      if (!row || !row.path) {
        ElementPlus.ElMessage.warning('Invalid path');
        return;
      }

      try {
        await ElementPlus.ElMessageBox.confirm(
          `Delete "${row.name}"?${row.is_dir ? ' All nested contents will be removed as well.' : ''}`,
          'Delete Confirmation',
          {
            type: 'warning',
            confirmButtonText: 'Delete',
            cancelButtonText: 'Cancel'
          }
        );

        const url = new URL(`/api/connections/${encodeURIComponent(this.selectedId)}/remote-files`, window.location.origin);
        url.searchParams.set('path', row.path);

        const res = await fetch(url.pathname + url.search, { method: 'DELETE' });
        const json = await res.json();

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Delete failed');
        }

        ElementPlus.ElMessage.success('Deleted');
        await this.refreshRemoteDirectory();
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
        ElementPlus.ElMessage.error(e.message || 'Delete failed');
      }
    },

    async openRecentFilesDialog() {
      this.recentFilesDialogVisible = true;
      this.recentFilesLoading = true;

      try {
        const res = await fetch('/api/files/recent');
        const json = await res.json();

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to load files');
        }

        this.recentFiles = json.data || [];
      } catch (e) {
        ElementPlus.ElMessage.error(e.message || 'Failed to load files');
      } finally {
        this.recentFilesLoading = false;
      }
    },

    async openCommandHistoryDialog() {
      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('Please select a device');
        return;
      }

      this.commandHistoryDialogVisible = true;
      this.commandHistoryLoading = true;

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command-history`);
        const json = await res.json();

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to load command history');
        }

        this.commandHistoryItems = Array.isArray(json.data) ? json.data : [];
      } catch (e) {
        this.commandHistoryItems = [];
        ElementPlus.ElMessage.error(e.message || 'Failed to load command history');
      } finally {
        this.commandHistoryLoading = false;
      }
    },

    applyHistoryCommand(row) {
      if (!row || !row.command) return;
      this.commandText = row.command;
      this.commandHistoryDialogVisible = false;

      nextTick(() => {
        const input = this.$refs.commandInputRef;
        if (input && typeof input.focus === 'function') {
          input.focus();
        }
      });
    },

    async clearCommandHistory() {
      if (!this.selectedId) {
        ElementPlus.ElMessage.warning('Please select a device');
        return;
      }

      try {
        await ElementPlus.ElMessageBox.confirm(
          'Clear command history for the current host?',
          'Clear History',
          {
            type: 'warning',
            confirmButtonText: 'Clear',
            cancelButtonText: 'Cancel'
          }
        );

        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/command-history`, {
          method: 'DELETE'
        });

        const json = await res.json();
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Failed to clear command history');
        }

        this.commandHistoryItems = [];
        this.commandShortcutHistoryCommands = [];
        this.commandShortcutHistoryLoadedFor = '';
        this.resetCommandShortcutNavigation();
        ElementPlus.ElMessage.success('Command history cleared');
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return;
        ElementPlus.ElMessage.error(e.message || 'Failed to clear command history');
      }
    },

    clearOutput() {
      if (this.selectedId) this.outputs[this.selectedId] = [];
    },

    scrollToBottom() {
      nextTick(() => {
        const el = this.$refs.terminalRef;
        if (el) el.scrollTop = el.scrollHeight;
      });
    },

    upsertConnection(conn) {
      const idx = this.connections.findIndex(item => item.client_id === conn.client_id);
      if (idx === -1) {
        this.connections.unshift(conn);
      } else {
        this.connections[idx] = conn;
      }

      if (!this.selectedId) this.selectedId = conn.client_id;
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
      if (this.eventSource) this.eventSource.close();

      const es = new EventSource('/api/stream');
      this.eventSource = es;

      es.addEventListener('open', () => {
        if (!this.sseReady) this.sseReady = true;
      });

      es.addEventListener('connection_online', (event) => {
        const payload = JSON.parse(event.data);
        const conn = payload.connection;
        this.upsertConnection(conn);

        ElementPlus.ElNotification({
          title: 'Device Online',
          message: `${conn.hostname || conn.client_id} is now available`,
          type: 'success'
        });
      });

      es.addEventListener('connection_offline', (event) => {
        const payload = JSON.parse(event.data);
        const clientId = payload.client_id;
        const oldConn = this.connections.find(item => item.client_id === clientId);

        this.removeConnection(clientId);

        ElementPlus.ElNotification({
          title: 'Device Offline',
          message: `${(oldConn && oldConn.hostname) || clientId} went offline`,
          type: 'warning'
        });
      });

      es.addEventListener('command_result', (event) => {
        const payload = JSON.parse(event.data);
        this.appendOutput(payload.client_id, payload.text || '');
      });

      es.addEventListener('command_complete', async (event) => {
        const payload = JSON.parse(event.data);
        this.appendOutput(
          payload.client_id,
          `[Command finished] ${payload.command} (${payload.success ? 'Success' : 'Failed'})`,
          payload.success ? 'success' : 'error'
        );
        this.commandShortcutHistoryLoadedFor = '';
        await this.loadConnections();
      });

      es.addEventListener('background_message', async (event) => {
        const payload = JSON.parse(event.data);
        this.appendOutput(payload.client_id, `[Background] ${payload.text || ''}`, 'info');
        await this.loadConnections();
      });

      es.addEventListener('file_received', (event) => {
        const payload = JSON.parse(event.data);
        const fileName = payload.saved_name || payload.original_name;
        const downloadUrl = `/api/files/recent/${encodeURIComponent(fileName)}`;

        ElementPlus.ElNotification({
          title: 'File Received',
          dangerouslyUseHTMLString: true,
          message: `
            <div>
              <div>${payload.original_name || fileName} has been saved to the server file area</div>
              <div style="margin-top:6px;">
                <a href="${downloadUrl}" target="_blank" style="color:#409eff;text-decoration:none;">
                  Download now
                </a>
              </div>
            </div>
          `,
          type: 'success',
          duration: 6000
        });

        if (this.recentFilesDialogVisible) {
          this.openRecentFilesDialog();
        }
      });

      es.onerror = () => {
        // EventSource reconnects automatically
      };
    }
  }
}).use(ElementPlus).mount('#app');