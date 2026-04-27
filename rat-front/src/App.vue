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
  :format-os-label="formatOsLabel"
  :format-address="formatAddress"
  :get-connection-status-dot-class="getConnectionStatusDotClass"
  :get-connection-status-text="getConnectionStatusText"
  :format-connection-last-seen-relative="formatConnectionLastSeenRelative"
  @refresh="loadConnections"
  @select="selectConnection"
/>

            <main class="main panel">
                <template v-if="currentConnection">
                    <div class="main-body">
                        <ConnectionInfoCards
  :connection="currentConnection"
  :format-address="formatAddress"
  :format-os-label="formatOsLabel"
  :get-connection-status-text="getConnectionStatusText"
  :format-connection-rtt="formatConnectionRtt"
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
  @control-action="handleControlActionCommand"
  @disconnect="killConnection"
  @clear="clearOutput"
  @bottom="scrollToBottom"
/>

                                <CommandInputBar
  ref="commandInputBarRef"
  v-model="commandText"
  :sending="sending"
  :has-running-web-task="hasRunningWebTask"
  :current-task-is-cancelling="currentTaskIsCancelling"
  :query-command-candidates="queryCommandCandidates"
  @select-candidate="handleCommandCandidateSelect"
  @run="sendCommand"
  @cancel="cancelCurrentTask"
/>

                                <TerminalOutput
  ref="terminalOutputRef"
  :lines="currentOutputLines"
  :get-terminal-tail-action-items="getTerminalTailActionItems"
  :get-terminal-inline-action-items="getTerminalInlineActionItems"
  @action-click="handleTerminalActionClick"
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
  :format-bytes="formatBytes"
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
  :format-bytes="formatBytes"
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
  v-model:visible="previewDialogVisible"
  :loading="previewLoading"
  :type="previewType"
  :title="previewTitle"
  :url="previewUrl"
  :edit-mode="previewEditMode"
  :saving="previewSaving"
  :truncated="previewTruncated"
  :source-label="previewSourceLabel"
  :file-size="previewFileSize"
  :file-encoding="previewFileEncoding"
  :detected-language="previewDetectedLanguage"
  :image-info="previewImageInfo"
  @copy-text="copyPreviewText"
  @enter-edit="enterEditMode"
  @save="saveEditedContent"
  @cancel-edit="cancelEditMode"
  @clear-content="clearPreviewContent"
  @open-image-info="openPreviewImageInfoDialog"
  @open-original="openPreviewOriginal"
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
  :command-candidates="commandCandidates"
  :command-candidates-loaded-for="commandCandidatesLoadedFor"
  :load-command-candidates="loadCommandCandidates"
  :get-connection-status-text="getConnectionStatusText"
  :format-connection-last-seen="formatConnectionLastSeen"
  :format-date-time-standard="formatDateTimeStandard"
  :format-connection-rtt="formatConnectionRtt"
/>


 <ProcessDialogs
  ref="processDialogRef"
  :selected-id="selectedId"
/>

  <AgentBuilderDialog
  v-model:visible="agentBuilderDialogVisible"
  :form="agentForm"
  :builder-alert-text="agentBuilderAlertText"
  :building="agentBuilding"
  :target-os-disabled="isAgentTargetOsDisabled"
  :target-arch-disabled="isAgentTargetArchDisabled"
  @build="buildAgent"
/>

<TerminalJsonDialog
  v-model:visible="terminalJsonDialogVisible"
  :title="terminalJsonDialogTitle"
  :display-mode="terminalJsonDisplayMode"
  :table-rows="terminalJsonTableRows"
  :table-columns="terminalJsonTableColumns"
  :flat-rows="terminalJsonFlatRows"
  :text="terminalJsonText"
/>


  <PreviewImageInfoDialog
  v-model:visible="previewImageInfoDialogVisible"
  :info="previewImageInfo"
  :format-preview-image-info="formatPreviewImageInfo"
/>


<AgentOutputsDialog
  v-model:visible="agentOutputsDialogVisible"
  :outputs="agentOutputs"
  :loading="agentOutputsLoading"
  :describe-agent-target-os="describeAgentTargetOs"
  :format-agent-source-text="formatAgentSourceText"
  :format-agent-listener-text="formatAgentListenerText"
  :format-agent-web-listener-text="formatAgentWebListenerText"
  :format-date-time-standard="formatDateTimeStandard"
  :format-bytes="formatBytes"
  :is-agent-output-deleting="isAgentOutputDeleting"
  @open-builder="openAgentBuilderDialog"
  @refresh="loadAgentOutputs"
  @delete-output="deleteAgentOutput"
/>


  <PtyDialog
  ref="ptyDialogRef"
  :selected-id="selectedId"
  :current-connection="currentConnection"
  :get-tab-scoped-headers="getTabScopedHeaders"
/>
</template>

<script>
import AppStateModule from './legacy/core/state.js'
import AppUtilsModule from './legacy/modules/utils.js'
import AppCommandsModule from './legacy/modules/commands.js'
// import AppJobsModule from './legacy/modules/jobs.js'
import AppSseModule from './legacy/modules/sse.js'
import AppAgentModule from './legacy/modules/agent.js'
import AppConnectionModule from './legacy/modules/connection.js'
import AppTaskModule from './legacy/modules/task.js'
import AppTerminalModule from './legacy/modules/terminal.js'
import AppCandidatesModule from './legacy/modules/candidates.js'
// import AppHistoryModule from './legacy/modules/history.js'
import AppPreviewModule from './legacy/modules/preview.js'
import DeviceSidebar from "./components/DeviceSidebar.vue";
import ConnectionInfoCards from "./components/ConnectionInfoCards.vue";
import TerminalToolbar from "./components/TerminalToolbar.vue";
import CommandInputBar from "./components/CommandInputBar.vue";
import TerminalOutput from "./components/TerminalOutput.vue";
import ConnectionInfoDialogs from "./components/ConnectionInfoDialogs.vue";
import ProcessDialogs from "./components/ProcessDialogs.vue";
import AgentBuilderDialog from "./components/AgentBuilderDialog.vue";
import AgentOutputsDialog from "./components/AgentOutputsDialog.vue";
// import CommandExecutionDetailDialog from "./components/CommandExecutionDetailDialog.vue";
import CommandHistoryDialog from "./components/CommandHistoryDialog.vue";
import RemoteFilesDialog from "./components/RemoteFilesDialog.vue";
import ArtifactDialog from "./components/ArtifactDialog.vue";
import ScriptLibraryDialog from "./components/ScriptLibraryDialog.vue";
// import BackgroundJobMessageDialog from "./components/BackgroundJobMessageDialog.vue";
// import BackgroundJobDetailDialog from "./components/BackgroundJobDetailDialog.vue";
// import BackgroundJobStartDialog from "./components/BackgroundJobStartDialog.vue";
import BackgroundJobsDialog from "./components/BackgroundJobsDialog.vue";
import PreviewDialog from "./components/PreviewDialog.vue";
import PreviewImageInfoDialog from "./components/PreviewImageInfoDialog.vue";
import TerminalJsonDialog from "./components/TerminalJsonDialog.vue";
import PtyDialog from "./components/PtyDialog.vue";

export default {
  components: {
    PtyDialog,
    TerminalJsonDialog,
    PreviewImageInfoDialog,
    PreviewDialog,
    BackgroundJobsDialog,
    // BackgroundJobStartDialog,
    // BackgroundJobDetailDialog,
    // BackgroundJobMessageDialog,
    ScriptLibraryDialog,
    ArtifactDialog,
    RemoteFilesDialog,
    CommandHistoryDialog,
    // CommandExecutionDetailDialog,
    AgentOutputsDialog,
    AgentBuilderDialog,
    ProcessDialogs,
    ConnectionInfoDialogs,
    TerminalOutput, CommandInputBar, TerminalToolbar, ConnectionInfoCards, DeviceSidebar},
  data() {
    return {
      ...AppStateModule.data(),
      ...AppAgentModule.data(),
      ...AppPreviewModule.data(),
      // ...AppJobsModule.data(),
      ...AppCandidatesModule.data(),
      // ...AppHistoryModule.data(),
      ...AppTerminalModule.data(),
      ...AppConnectionModule.data(),
      ...AppCommandsModule.data(),
      ...AppTaskModule.data(),
      ...AppSseModule.data(),


      remoteFilesDialogVisible: false,
pendingRemoteUploadRefresh: null,

    }
  },

  computed: {
    ...AppStateModule.computed,
    ...AppAgentModule.computed,
    ...AppPreviewModule.computed,
    ...AppConnectionModule.computed,
    ...AppTerminalModule.computed,
    ...AppTaskModule.computed,
    // ...AppHistoryModule.computed,
    // ...AppJobsModule.computed,
  },

  watch: {
    ...AppStateModule.watch,
    ...AppAgentModule.watch,
    ...AppTerminalModule.watch,
    ...AppPreviewModule.watch,
    // ...AppJobsModule.watch,
    // ...AppHistoryModule.watch,
  },

  methods: {
    ...AppUtilsModule.methods,
    ...AppCommandsModule.methods,
    // ...AppJobsModule.methods,
    ...AppSseModule.methods,
    ...AppAgentModule.methods,
    ...AppConnectionModule.methods,
    ...AppTaskModule.methods,
    ...AppTerminalModule.methods,
    ...AppCandidatesModule.methods,
    // ...AppHistoryModule.methods,
    ...AppPreviewModule.methods,

//     updateBackgroundJobParam(name, value) {
//   if (!name) return
//
//   this.backgroundJobParamForm = {
//     ...this.backgroundJobParamForm,
//     [name]: value,
//   }
// },




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

openConnectionInfoDialog() {
  return this.$refs.connectionInfoDialogRef?.open()
},

scheduleBackgroundJobsRefresh(clientId = '') {
  this.$refs.backgroundJobsDialogRef?.scheduleBackgroundJobsRefresh(clientId)
},

handleBackgroundJobDeleted(normalizedName) {
  if (
    this.previewDialogVisible &&
    (this.previewSource === 'server_job' || this.previewSource === 'background_job')
  ) {
    const currentPreviewName = this.normalizeServerJobFilename(this.previewFilePath || this.previewTitle || '')

    if (currentPreviewName === normalizedName) {
      this.previewDialogVisible = false

      if (typeof this.destroyMonacoEditor === 'function') {
        this.destroyMonacoEditor()
      }
    }
  }
},


    openCommandHistoryDialog() {
  return this.$refs.commandHistoryDialogRef?.open()
},

applyHistoryCommand(row) {
  if (!row || !row.command) return

  this.commandText = row.command

  this.$nextTick(() => {
    const commandInputBar = this.$refs.commandInputBarRef

    if (commandInputBar && typeof commandInputBar.focusInput === 'function') {
      commandInputBar.focusInput()
    }
  })
},

async reloadCommandCandidatesFromHistory(options = {}) {
  if (options?.reset) {
    this.commandCandidatesLoadedFor = ''
  }

  if (!this.selectedId) return

  await this.loadCommandCandidates(this.selectedId)
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

    // if (this.backgroundJobsRefreshTimer) {
    //   clearTimeout(this.backgroundJobsRefreshTimer)
    //   this.backgroundJobsRefreshTimer = null
    // }

    if (this.statusTickTimer) {
      clearInterval(this.statusTickTimer)
      this.statusTickTimer = null
    }
  },
}
</script>