<template>
  <div class="app">
    <header class="banner">
      <div class="banner-left">
        <div class="banner-title">Remote Control Hub</div>
        <div class="banner-subtitle">Remote access, shell control, file browsing</div>
      </div>

      <div class="banner-right">
        <span class="banner-meta-label">Online Nodes</span>
        <span class="banner-meta-value">{{ onlineConnectionsCount }}</span>

        <div class="banner-actions">
          <div class="banner-action-links">
            <span class="tool-separator" style="margin-right: 12px; margin-left: 6px"></span>

            <div class="banner-action-links">
              <button class="banner-inline-action"
                      type="button"
                      @click="openAgentBuilderDialog">
                Build Agent
              </button>
              <button class="banner-inline-action"
                      type="button"
                      onclick="window.RatAuth && window.RatAuth.logout()">
                Sign out
              </button>
            </div>
          </div>
        </div>
      </div>
    </header>

    <div class="content">
      <DeviceSidebar
          :connections="connections"
          :selected-id="selectedId"
          :status-now-tick="statusNowTick"
          @refresh="loadConnections"
          @select="selectConnection"
      />

      <main class="main panel">
        <template v-if="currentConnection">
          <div class="main-body">
            <ConnectionInfoCards
                :connection="currentConnection"
                :status-now-tick="statusNowTick"
            />

            <section class="terminal-panel">
              <div class="terminal-frame">
                <TerminalToolbar
                    :selected-id="selectedId"
                    @open-remote-files="openRemoteFilesDialog"
                    @open-artifacts="openArtifactDialog"
                    @open-info="openConnectionInfoDialog"
                    @open-jobs="openBackgroundJobsDialog"
                    @open-scripts="openScriptLibraryDialog"
                    @open-agents="openAgentOutputsDialog"
                    @open-history="openCommandHistoryDialog"
                    @open-pty="openPtyDialog"
                    @open-processes="openProcessDialog"
                    @clear="clearOutput"
                    @bottom="scrollToBottom"
                />

                <CommandInputBar
                    ref="commandInputBarRef"
                    :selected-id="selectedId"
                    :current-connection="currentConnection"
                    :current-active-task-id="currentActiveTaskId"
                    :tab-id="tabId"
                    @append-output="appendOutput"
                    @set-active-task="setActiveTask"
                />

                <TerminalOutput
                    ref="terminalOutputRef"
                    :lines="currentOutputLines"
                    @preview-artifact="previewArtifact"
                    @open-json="$refs.terminalJsonDialogRef?.open($event)"
                />
              </div>
            </section>
          </div>
        </template>

        <template v-else>
          <div class="main-empty">
            <div class="main-empty-title">No device selected</div>
            <div class="main-empty-text">Choose a device from the left sidebar to start an interactive
              session.
            </div>
          </div>
        </template>
      </main>
    </div>
  </div>

  <input
      ref="remoteUploadInputRef"
      type="file"
      class="hidden-file-input"
      @change="handleRemoteUploadChange"
  />
  <RemoteFilesDialog
      ref="remoteFilesDialogRef"
      :selected-id="selectedId"
      :get-tab-scoped-headers="getTabScopedHeaders"
      @append-output="appendOutput"
      @set-active-task="setActiveTask"
      @preview="previewRemoteEntry"
      @request-upload="triggerRemoteUploadInput"
      @upload-started="pendingRemoteUploadRefresh = $event"
      @visible-change="remoteFilesDialogVisible = $event"
      @artifacts-maybe-changed="refreshArtifactsIfOpen"
  />


  <ArtifactDialog
      ref="artifactDialogRef"
      :current-connection="currentConnection"
      @preview="previewArtifact"
  />


  <ScriptLibraryDialog
      ref="scriptLibraryDialogRef"
      :selected-id="selectedId"
      :current-connection="currentConnection"
      :get-tab-scoped-headers="getTabScopedHeaders"
      :open-script-editor="openRemoteScriptEditorInternal"
      :open-new-script-editor="openNewRemoteScriptEditor"
      @append-output="appendOutput"
      @set-active-task="setActiveTask"
  />


  <BackgroundJobsDialog
      ref="backgroundJobsDialogRef"
      :selected-id="selectedId"
      :current-connection="currentConnection"
      :get-tab-scoped-headers="getTabScopedHeaders"
      :format-date-time-standard="formatDateTimeStandard"
      :format-bytes="formatBytes"
      @set-active-task="setActiveTask"
      @preview-file="previewBackgroundJobFile"
      @open-job-editor="openRemoteJobEditor"
      @open-new-job-editor="openNewRemoteJobEditor"
      @job-deleted="handleBackgroundJobDeleted"
  />

  <PreviewDialog
      ref="previewDialogRef"
      :selected-id="selectedId"
      :remote-files-dialog-visible="remoteFilesDialogVisible"
      @remote-directory-maybe-changed="refreshRemoteDirectory"
      @artifacts-maybe-changed="refreshArtifactsIfOpen"
      @scripts-maybe-changed="refreshScriptsIfOpen"
      @background-job-modules-maybe-changed="refreshBackgroundJobModulesIfOpen"
  />


  <CommandHistoryDialog
      ref="commandHistoryDialogRef"
      :selected-id="selectedId"
      :current-connection="currentConnection"
      :format-date-time-standard="formatDateTimeStandard"
      :format-bytes="formatBytes"
      :reload-command-candidates="reloadCommandCandidatesFromHistory"
      @apply-command="applyHistoryCommand"
      @preview-file="previewArtifact"
  />


  <ConnectionInfoDialogs
      ref="connectionInfoDialogRef"
      :selected-id="selectedId"
      :current-connection="currentConnection"
      :status-now-tick="statusNowTick"
  />


  <ProcessDialogs
      ref="processDialogRef"
      :selected-id="selectedId"
  />

  <AgentBuilderDialog
      ref="agentBuilderDialogRef"
      @built="refreshAgentOutputsIfOpen"
  />

  <TerminalJsonDialog ref="terminalJsonDialogRef"/>

  <AgentOutputsDialog
      ref="agentOutputsDialogRef"
      @open-builder="openAgentBuilderDialog"
  />

  <PtyDialog
      ref="ptyDialogRef"
      :selected-id="selectedId"
      :current-connection="currentConnection"
      :get-tab-scoped-headers="getTabScopedHeaders"
  />
</template>

<script>

import AppUtilsModule from './legacy/modules/utils.js'
import AppSseModule from './legacy/modules/sse.js'
import AppConnectionModule from './legacy/modules/connection.js'
import AppTaskModule from './legacy/modules/task.js'
import AppTerminalModule from './legacy/modules/terminal.js'
import DeviceSidebar from "./components/DeviceSidebar.vue";
import ConnectionInfoCards from "./components/ConnectionInfoCards.vue";
import TerminalToolbar from "./components/TerminalToolbar.vue";
import CommandInputBar from "./components/CommandInputBar.vue";
import TerminalOutput from "./components/TerminalOutput.vue";
import ConnectionInfoDialogs from "./components/ConnectionInfoDialogs.vue";
import ProcessDialogs from "./components/ProcessDialogs.vue";
import AgentBuilderDialog from "./components/AgentBuilderDialog.vue";
import AgentOutputsDialog from "./components/AgentOutputsDialog.vue";
import CommandHistoryDialog from "./components/CommandHistoryDialog.vue";
import RemoteFilesDialog from "./components/RemoteFilesDialog.vue";
import ArtifactDialog from "./components/ArtifactDialog.vue";
import ScriptLibraryDialog from "./components/ScriptLibraryDialog.vue";
import BackgroundJobsDialog from "./components/BackgroundJobsDialog.vue";
import PreviewDialog from "./components/PreviewDialog.vue";
import TerminalJsonDialog from "./components/TerminalJsonDialog.vue";
import PtyDialog from "./components/PtyDialog.vue";

export default {
  components: {
    PtyDialog,
    TerminalJsonDialog,
    PreviewDialog,
    BackgroundJobsDialog,
    ScriptLibraryDialog,
    ArtifactDialog,
    RemoteFilesDialog,
    CommandHistoryDialog,
    AgentOutputsDialog,
    AgentBuilderDialog,
    ProcessDialogs,
    ConnectionInfoDialogs,
    TerminalOutput, CommandInputBar, TerminalToolbar, ConnectionInfoCards, DeviceSidebar
  },
  data() {
    return {

      ...AppTerminalModule.data(),
      ...AppConnectionModule.data(),
      ...AppTaskModule.data(),
      ...AppSseModule.data(),

      statusNowTick: Date.now(),
      statusTickTimer: null,
      remoteFilesDialogVisible: false,
      pendingRemoteUploadRefresh: null,
    }
  },

  computed: {
    ...AppConnectionModule.computed,
    ...AppTerminalModule.computed,
    ...AppTaskModule.computed,
  },

  watch: {
    ...AppTerminalModule.watch,
  },

  methods: {
    ...AppUtilsModule.methods,
    ...AppSseModule.methods,
    ...AppConnectionModule.methods,
    ...AppTaskModule.methods,
    ...AppTerminalModule.methods,

    openArtifactDialog() {
      return this.$refs.artifactDialogRef?.open()
    },

    refreshArtifactsIfOpen() {
      return this.$refs.artifactDialogRef?.refreshIfOpen()
    },

    openRemoteFilesDialog() {
      this.$refs.remoteFilesDialogRef?.open()
    },

    triggerRemoteUploadInput() {
      const input = this.$refs.remoteUploadInputRef

      if (input) {
        input.value = ''
        input.click()
      }
    },

    handleRemoteUploadChange(event) {
      this.$refs.remoteFilesDialogRef?.handleUploadChange(event)
    },

    loadRemoteDirectory(path = '', page = 1) {
      return this.$refs.remoteFilesDialogRef?.loadRemoteDirectory(path, page)
    },

    refreshRemoteDirectory() {
      return this.$refs.remoteFilesDialogRef?.refreshRemoteDirectory()
    },


    openBackgroundJobsDialog() {
      return this.$refs.backgroundJobsDialogRef?.open()
    },

    refreshBackgroundJobsIfOpen() {
      return this.$refs.backgroundJobsDialogRef?.refreshIfOpen()
    },

    refreshBackgroundJobModulesIfOpen() {
      return this.$refs.backgroundJobsDialogRef?.refreshModulesIfOpen()
    },

    openScriptLibraryDialog() {
      return this.$refs.scriptLibraryDialogRef?.open()
    },

    refreshScriptsIfOpen() {
      return this.$refs.scriptLibraryDialogRef?.refreshIfOpen()
    },

    openPtyDialog() {
      return this.$refs.ptyDialogRef?.open()
    },

    openProcessDialog() {
      return this.$refs.processDialogRef?.open()
    },

    openAgentBuilderDialog() {
      return this.$refs.agentBuilderDialogRef?.open()
    },

    openAgentOutputsDialog() {
      return this.$refs.agentOutputsDialogRef?.open()
    },

    refreshAgentOutputsIfOpen() {
      return this.$refs.agentOutputsDialogRef?.refreshIfOpen({silent: true})
    },

    openConnectionInfoDialog() {
      return this.$refs.connectionInfoDialogRef?.open()
    },

    scheduleBackgroundJobsRefresh(clientId = '') {
      this.$refs.backgroundJobsDialogRef?.scheduleBackgroundJobsRefresh(clientId)
    },

    handleBackgroundJobDeleted(normalizedName) {
      this.$refs.previewDialogRef?.handleBackgroundJobDeleted(normalizedName)
    },

    previewRemoteEntry(row) {
      return this.$refs.previewDialogRef?.previewRemoteEntry(row)
    },

    previewArtifact(row) {
      return this.$refs.previewDialogRef?.previewArtifact(row)
    },

    previewBackgroundJobFile(file) {
      return this.$refs.previewDialogRef?.previewBackgroundJobFile(file)
    },

    openNewRemoteScriptEditor(scriptName = 'new_script.py') {
      return this.$refs.previewDialogRef?.openNewRemoteScriptEditor(scriptName)
    },

    openRemoteScriptEditorInternal(scriptName) {
      return this.$refs.previewDialogRef?.openRemoteScriptEditorInternal(scriptName)
    },

    openNewRemoteJobEditor(scriptName = 'new_job.py') {
      return this.$refs.previewDialogRef?.openNewRemoteJobEditor(scriptName)
    },

    openRemoteJobEditor(scriptName) {
      return this.$refs.previewDialogRef?.openRemoteJobEditor(scriptName)
    },


    openCommandHistoryDialog() {
      return this.$refs.commandHistoryDialogRef?.open()
    },

    applyHistoryCommand(row) {
      if (!row || !row.command) return

      this.$refs.commandInputBarRef?.setCommandText(row.command)
    },

    async reloadCommandCandidatesFromHistory(options = {}) {
      await this.$refs.commandInputBarRef?.reloadCommandCandidates(options)
    },

    async reloadCommandCandidatesFromRuntime(options = {}) {
      await this.$refs.commandInputBarRef?.reloadCommandCandidates(options)
    },

  },

  mounted() {
    this.ensureTabId()
    this.loadConnections()
    this.initSSE()

    this.statusTickTimer = setInterval(() => {
      this.statusNowTick = Date.now()
    }, 30 * 1000)
  },

  beforeUnmount() {
    if (this.eventSource) this.eventSource.close()

    if (this.statusTickTimer) {
      clearInterval(this.statusTickTimer)
      this.statusTickTimer = null
    }
  },
}
</script>