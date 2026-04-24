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
  @artifacts-maybe-changed="artifactDialogVisible && loadArtifacts()"
/>



<ArtifactDialog
  v-model:visible="artifactDialogVisible"
  v-model:active-tab="artifactActiveTab"
  v-model:machine-id-filter="artifactMachineIdFilter"
  :loading="artifactLoading"
  :clearing="artifactClearing"
  :items="filteredArtifactItems"
  :machines="artifactMachines"
  :count-map="artifactCountMap"
  :format-bytes="formatBytes"
  @refresh="loadArtifacts"
  @clear="clearArtifactCategory"
  @tab-change="loadArtifacts"
  @filter-change="loadArtifacts"
  @preview="previewArtifact"
  @delete="deleteArtifact"
/>


<ScriptLibraryDialog
  v-model:visible="scriptLibraryDialogVisible"
  :loading="scriptLibraryLoading"
  :upload-loading="serverScriptUploadLoading"
  :selected-directory="selectedScriptDirectory"
  :directory-tree-data="scriptDirectoryTreeData"
  :directory-items="currentScriptDirectoryItems"
  :is-script-supported-for-current-connection="isScriptSupportedForCurrentConnection"
  :format-script-platform-label="formatScriptPlatformLabel"
  :script-has-params="scriptHasParams"
  @create-script="createRemoteScriptPrompt"
  @trigger-upload="triggerScriptUpload"
  @upload-change="handleServerScriptUpload"
  @create-folder="createRemoteScriptFolderPrompt"
  @rename-folder="renameRemoteScriptFolder"
  @delete-folder="deleteRemoteScriptFolder"
  @refresh="loadScriptCatalog"
  @tree-node-click="handleScriptTreeNodeClick"
  @run-script="openScriptRunDialog"
  @edit-script="openRemoteScriptEditor"
  @rename-script="renameServerScript"
  @delete-script="deleteServerScript"
/>



<ScriptRunDialog
  v-model:visible="scriptRunDialogVisible"
  :item="pendingRunScriptItem"
  :param-specs="pendingRunScriptParamSpecs"
  :param-form="scriptParamForm"
  :submitting="scriptRunSubmitting"
  :is-script-supported-for-current-connection="isScriptSupportedForCurrentConnection"
  :format-script-platform-label="formatScriptPlatformLabel"
  @update-param="updateScriptParam"
  @cancel="closeScriptRunDialog"
  @confirm="confirmRunScript"
/>


  <BackgroundJobsDialog
  v-model:visible="backgroundJobsDialogVisible"
  :active-tab="backgroundJobsActiveTab"
  :modules="backgroundJobModules || []"
  :jobs="sortedBackgroundJobs || []"
  :modules-loading="backgroundJobModulesLoading"
  :jobs-loading="backgroundJobsLoading"
  :upload-loading="serverJobUploadLoading"
  :is-job-supported-for-current-connection="isJobSupportedForCurrentConnection"
  :format-job-platform-label="formatJobPlatformLabel"
  :has-background-job-params="hasBackgroundJobParams"
  :is-background-job-start-disabled="isBackgroundJobStartDisabled"
  :build-background-job-state-tag-type="buildBackgroundJobStateTagType"
  :format-background-job-duration="formatBackgroundJobDuration"
  :format-date-time-standard="formatDateTimeStandard"
  @update:active-tab="backgroundJobsActiveTab = $event"
  @create-job="createRemoteJobPrompt"
  @trigger-upload="triggerServerJobUpload"
  @upload-change="handleServerJobUpload"
  @refresh-modules="loadBackgroundJobModules"
  @start-job="openBackgroundJobStartDialog"
  @edit-job="openRemoteJobEditor"
  @delete-job="deleteRemoteScript"
  @refresh-jobs="loadBackgroundJobs"
  @open-detail="openBackgroundJobDetail"
  @stop-job="stopBackgroundJob"
/>

<BackgroundJobStartDialog
  v-model:visible="backgroundJobStartDialogVisible"
  :item="pendingStartJobModule"
  :params="pendingStartJobModule?.metadata?.params || []"
  :param-form="backgroundJobParamForm || {}"
  :submitting="backgroundJobStartSubmitting"
  :is-job-supported-for-current-connection="isJobSupportedForCurrentConnection"
  :format-job-platform-label="formatJobPlatformLabel"
  @update-param="updateBackgroundJobParam"
  @cancel="closeBackgroundJobStartDialog"
  @confirm="confirmStartBackgroundJobWithParams"
/>

<BackgroundJobDetailDialog
  v-model:visible="backgroundJobDetailDialogVisible"
  :item="selectedBackgroundJob"
  :messages="selectedBackgroundJobMessagesDesc || []"
  :files="selectedBackgroundJob?.files || []"
  :build-background-job-state-tag-type="buildBackgroundJobStateTagType"
  :format-background-job-duration="formatBackgroundJobDuration"
  :format-date-time-standard="formatDateTimeStandard"
  :format-background-job-message-text="formatBackgroundJobMessageText"
  :format-bytes="formatBytes"
  @stop-job="stopBackgroundJob"
  @open-message="openBackgroundJobMessageDialog"
  @preview-file="previewBackgroundJobFile"
/>

<BackgroundJobMessageDialog
  v-model:visible="backgroundJobMessageDialogVisible"
  :message="selectedBackgroundJobMessage || {}"
  :format-date-time-standard="formatDateTimeStandard"
  :format-background-job-message-text="formatBackgroundJobMessageText"
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
  v-model:visible="commandHistoryDialogVisible"
  v-model:active-tab="commandHistoryActiveTab"
  v-model:search-text="commandHistorySearchText"
  :search-summary="commandHistorySearchSummary"
  :quick-items="filteredCommandHistoryItems"
  :execution-items="filteredCommandExecutionItems"
  :quick-loading="commandHistoryLoading"
  :execution-loading="commandExecutionHistoryLoading"
  :build-command-execution-status-tag-type="buildCommandExecutionStatusTagType"
  :format-date-time-standard="formatDateTimeStandard"
  :format-command-execution-duration="formatCommandExecutionDuration"
  :build-command-execution-single-line-summary="buildCommandExecutionSingleLineSummary"
  @refresh="openCommandHistoryDialog"
  @clear-history="clearCommandHistory"
  @clear-search="clearCommandHistorySearch"
  @apply="applyHistoryCommand"
  @toggle-pin="toggleCommandHistoryPinned"
  @move-pin="moveCommandHistoryPinned"
  @open-detail="openCommandExecutionDetail"
  @delete-execution="deleteCommandExecutionItem"
/>

<CommandExecutionDetailDialog
  v-model:visible="commandExecutionDetailDialogVisible"
  :entry="selectedCommandExecutionEntry"
  :output-records="selectedCommandExecutionOutputRecordsDesc"
  :output-sort-order="commandExecutionOutputSortOrder"
  :build-command-execution-status-tag-type="buildCommandExecutionStatusTagType"
  :format-command-execution-duration="formatCommandExecutionDuration"
  :build-command-execution-summary="buildCommandExecutionSummary"
  :format-command-execution-record-text="formatCommandExecutionRecordText"
  :get-command-execution-file-status-text="getCommandExecutionFileStatusText"
  :format-bytes="formatBytes"
  @toggle-output-sort="toggleCommandExecutionOutputSort"
  @preview-file="previewArtifact"
/>

<ConnectionInfoDialogs
  v-model:info-visible="connectionInfoDialogVisible"
  v-model:value-visible="connectionInfoValueDialogVisible"
  :loading="connectionInfoLoading"
  :cards="connectionInfoCards"
  :commands="connectionInfoClientCommands"
  :value-title="connectionInfoValueDialogTitle"
  :value-value="connectionInfoValueDialogValue"
  @open-value="openConnectionInfoValueDialog"
/>


 <ProcessDialogs
  v-model:process-dialog-visible="processDialogVisible"
  v-model:process-detail-dialog-visible="processDetailDialogVisible"
  v-model:process-active-tab="processActiveTab"
  v-model:filter-text="processFilterText"
  :process-manager-summary-text="processManagerSummaryText"
  :process-tab-label="processTabLabel"
  :app-tab-label="appTabLabel"
  :filtered-processes="filteredProcesses"
  :filtered-apps="filteredApps"
  :processes-loading="processesLoading"
  :apps-loading="appsLoading"
  :process-detail-loading="processDetailLoading"
  :process-detail="processDetail"
  :process-detail-basic-rows="processDetailBasicRows"
  :process-detail-command-line-text="processDetailCommandLineText"
  @close="closeProcessDialog"
  @refresh="refreshProcessManager"
  @open-detail="openProcessDetail"
  @kill-process="killProcess"
  @kill-app="killApp"
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
  v-model:visible="ptyDialogVisible"
  v-model:shell-path="ptyShellPath"
  :current-connection="currentConnection"
  :pty-status="ptyStatus"
  :pty-error="ptyError"
  @closed="handlePtyDialogClosed"
  @focus="focusPtyInput"
  @close="closePtyDialog"
/>
</template>

<script>
import AppStateModule from './legacy/core/state.js'
import AppUtilsModule from './legacy/modules/utils.js'
import AppCommandsModule from './legacy/modules/commands.js'
import AppFilesModule from './legacy/modules/files.js'
import AppJobsModule from './legacy/modules/jobs.js'
import AppScriptsModule from './legacy/modules/scripts.js'
import AppSseModule from './legacy/modules/sse.js'
import AppAgentModule from './legacy/modules/agent.js'
import AppProcessModule from './legacy/modules/process.js'
import AppConnectionModule from './legacy/modules/connection.js'
import AppTaskModule from './legacy/modules/task.js'
import AppTerminalModule from './legacy/modules/terminal.js'
import AppPtyModule from './legacy/modules/pty.js'
import AppCandidatesModule from './legacy/modules/candidates.js'
import AppHistoryModule from './legacy/modules/history.js'
import AppArtifactsModule from './legacy/modules/artifacts.js'
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
import CommandExecutionDetailDialog from "./components/CommandExecutionDetailDialog.vue";
import CommandHistoryDialog from "./components/CommandHistoryDialog.vue";
import RemoteFilesDialog from "./components/RemoteFilesDialog.vue";
import ArtifactDialog from "./components/ArtifactDialog.vue";
import ScriptLibraryDialog from "./components/ScriptLibraryDialog.vue";
import ScriptRunDialog from "./components/ScriptRunDialog.vue";
import BackgroundJobMessageDialog from "./components/BackgroundJobMessageDialog.vue";
import BackgroundJobDetailDialog from "./components/BackgroundJobDetailDialog.vue";
import BackgroundJobStartDialog from "./components/BackgroundJobStartDialog.vue";
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
    BackgroundJobStartDialog,
    BackgroundJobDetailDialog,
    BackgroundJobMessageDialog,
    ScriptRunDialog,
    ScriptLibraryDialog,
    ArtifactDialog,
    RemoteFilesDialog,
    CommandHistoryDialog,
    CommandExecutionDetailDialog,
    AgentOutputsDialog,
    AgentBuilderDialog,
    ProcessDialogs,
    ConnectionInfoDialogs,
    TerminalOutput, CommandInputBar, TerminalToolbar, ConnectionInfoCards, DeviceSidebar},
  data() {
    return {
      ...AppStateModule.data(),
      ...AppArtifactsModule.data(),
      ...AppAgentModule.data(),
      ...AppProcessModule.data(),
      ...AppFilesModule.data(),
      ...AppPreviewModule.data(),
      ...AppJobsModule.data(),
      ...AppScriptsModule.data(),
      ...AppCandidatesModule.data(),
      ...AppHistoryModule.data(),
      ...AppTerminalModule.data(),
      ...AppPtyModule.data(),
      ...AppConnectionModule.data(),
      ...AppCommandsModule.data(),
      ...AppTaskModule.data(),
      ...AppSseModule.data(),
    }
  },

  computed: {
    ...AppStateModule.computed,
    ...AppProcessModule.computed,
    ...AppAgentModule.computed,
    ...AppPreviewModule.computed,
    ...AppConnectionModule.computed,
    ...AppTerminalModule.computed,
    ...AppTaskModule.computed,
    ...AppHistoryModule.computed,
    ...AppFilesModule.computed,
    ...AppArtifactsModule.computed,
    ...AppJobsModule.computed,
    ...AppScriptsModule.computed,
  },

  watch: {
    ...AppStateModule.watch,
    ...AppAgentModule.watch,
    ...AppProcessModule.watch,
    ...AppTerminalModule.watch,
    ...AppPreviewModule.watch,
    ...AppFilesModule.watch,
    ...AppArtifactsModule.watch,
    ...AppJobsModule.watch,
    ...AppScriptsModule.watch,
    ...AppHistoryModule.watch,
  },

  methods: {
    ...AppUtilsModule.methods,
    ...AppCommandsModule.methods,
    ...AppFilesModule.methods,
    ...AppJobsModule.methods,
    ...AppScriptsModule.methods,
    ...AppSseModule.methods,
    ...AppAgentModule.methods,
    ...AppProcessModule.methods,
    ...AppConnectionModule.methods,
    ...AppTaskModule.methods,
    ...AppTerminalModule.methods,
    ...AppPtyModule.methods,
    ...AppCandidatesModule.methods,
    ...AppHistoryModule.methods,
    ...AppArtifactsModule.methods,
    ...AppPreviewModule.methods,

updateScriptParam(name, value) {
  if (!name) return

  this.scriptParamForm = {
    ...this.scriptParamForm,
    [name]: value,
  }
},

    updateBackgroundJobParam(name, value) {
  if (!name) return

  this.backgroundJobParamForm = {
    ...this.backgroundJobParamForm,
    [name]: value,
  }
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

    if (this.backgroundJobsRefreshTimer) {
      clearTimeout(this.backgroundJobsRefreshTimer)
      this.backgroundJobsRefreshTimer = null
    }

    if (this.statusTickTimer) {
      clearInterval(this.statusTickTimer)
      this.statusTickTimer = null
    }
  },
}
</script>
