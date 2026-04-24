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

    <input ref="remoteUploadInputRef" type="file" class="hidden-file-input" @change="handleRemoteUploadChange"/>

<RemoteFilesDialog
  ref="remoteFilesDialogRef"
  v-model:visible="remoteFilesDialogVisible"
  v-model:pin-manager-visible="remotePinManagerDialogVisible"

  :remote-breadcrumb-items="remoteBreadcrumbItems"
  :remote-files-parent-path="remoteFilesParentPath"

  :quick-jump-loading="quickJumpLoading"
  :remote-pinned-jump-loading="remotePinnedJumpLoading"
  :remote-pinned-jump-items="remotePinnedJumpItems"

  :remote-upload-loading="remoteUploadLoading"
  :has-remote-selection="hasRemoteSelection"
  :remote-zip-downloading="remoteZipDownloading"
  :remote-selected-paths="remoteSelectedPaths"

  :remote-pin-button-text="remotePinButtonText"
  :has-pinned-quick-jumps="hasPinnedQuickJumps"

  :has-remote-clipboard="hasRemoteClipboard"
  :remote-clipboard-paths="remoteClipboardPaths"
  :remote-clipboard-action-text="remoteClipboardActionText"
  :remote-clipboard-source-path="remoteClipboardSourcePath"

  :show-hidden-files="showHiddenFiles"

  :display-remote-files-entries="displayRemoteFilesEntries"
  :remote-files-loading="remoteFilesLoading"

  :remote-files-total="remoteFilesTotal"
  :remote-files-hidden-total="remoteFilesHiddenTotal"
  :remote-files-all-total="remoteFilesAllTotal"
  :remote-files-total-pages="remoteFilesTotalPages"
  :remote-files-page="remoteFilesPage"
  :remote-files-page-size="remoteFilesPageSize"
  :remote-files-page-size-options="remoteFilesPageSizeOptions"

  :format-bytes="formatBytes"
  :is-remote-entry-selected="isRemoteEntrySelected"

  @breadcrumb="goToRemoteBreadcrumb"
  @refresh="refreshRemoteDirectory"
  @parent="goToRemoteParent"
  @jump="jumpToPath"

  @create-folder="createRemoteDirectory"
  @trigger-upload="triggerRemoteUpload"
  @download-selected="downloadSelectedRemoteEntries"
  @delete-selected="deleteSelectedRemoteEntries"
  @more-command="handleRemoteToolbarMoreCommand"

  @row-dblclick="handleRemoteRowDblClick"
  @selection-change="handleRemoteSelectionChange"
  @enter-dir="enterRemoteDirectory"
  @preview="previewRemoteEntry"
  @download="downloadRemoteEntry"
  @row-more-action="handleRemoteMoreAction"

  @page-change="handleRemotePageChange"
  @size-change="handleRemotePageSizeChange"

  @toggle-select="toggleRemoteSelection"
  @copy-one="row => { remoteSelectedPaths = [row.path]; copySelectedRemoteEntries() }"
  @cut-one="row => { remoteSelectedPaths = [row.path]; cutSelectedRemoteEntries() }"
  @rename="renameRemoteEntry"
  @copy-path="copyRemotePath"
  @delete="deleteRemoteEntry"

  @edit-pin="promptEditPinnedQuickJump"
  @delete-pin="deletePinnedQuickJump"
/>



    <el-dialog v-model="artifactDialogVisible" title="Artifact Manager" width="1160px" top="5vh"
               class="fixed-dialog recent-files-dialog artifact-dialog">
        <div class="fixed-dialog-body">
            <div class="dialog-head">
                <div class="dialog-head-left">
                    <el-button size="small" @click="loadArtifacts">Refresh</el-button>
                    <el-button size="small" type="danger" :loading="artifactClearing" @click="clearArtifactCategory">
                        Clear
                    </el-button>
                </div>
                <div class="dialog-head-right">
                    <div class="dialog-path-box artifact-filter-box">
                        <el-select v-model="artifactMachineIdFilter" clearable filterable
                                   placeholder="Filter by device" @change="loadArtifacts">
                            <el-option v-for="item in artifactMachines" :key="item.machine_id" :label="item.hostname || item.machine_id" :value="item.machine_id"/>
                        </el-select>
                    </div>
                </div>
            </div>

            <el-tabs v-model="artifactActiveTab" class="command-history-tabs" @tab-change="loadArtifacts">
                <el-tab-pane name="files">
                    <template #label>Files ({{ artifactCountMap.files || 0 }})</template>
                </el-tab-pane>
                <el-tab-pane name="previews">
                    <template #label>Previews ({{ artifactCountMap.previews || 0 }})</template>
                </el-tab-pane>
            </el-tabs>

            <div class="dialog-table-shell">
                <el-table :data="filteredArtifactItems" v-loading="artifactLoading" stripe width="100%" height="100%"
                          empty-text="No artifacts available" table-layout="fixed">
                    <el-table-column prop="original_name" label="Name" min-width="280" show-overflow-tooltip>
                        <template #default="{ row }">
                            <div class="ellipsis">{{ row.original_name || row.stored_name }}</div>
                        </template>
                    </el-table-column>
                    <el-table-column label="Hostname" min-width="180" show-overflow-tooltip>
                        <template #default="{ row }">
                            <div class="ellipsis">{{ row.hostname || '-' }}</div>
                        </template>
                    </el-table-column>
                    <el-table-column label="Category" min-width="160" show-overflow-tooltip>
                        <template #default="{ row }">
                            <div class="ellipsis">{{ row.category || '-' }}</div>
                        </template>
                    </el-table-column>
                    <el-table-column label="Size" width="110" align="center">
                        <template #default="{ row }">{{ formatBytes(row.size) }}</template>
                    </el-table-column>
                    <el-table-column label="Created" width="170" show-overflow-tooltip>
                        <template #default="{ row }">
                            <div class="ellipsis">{{ row.created_at || '-' }}</div>
                        </template>
                    </el-table-column>
                    <el-table-column label="Actions" width="200" align="center" fixed="right">
                        <template #default="{ row }">
                            <div class="table-actions table-actions-links">
                                <a href="#" class="table-action-link" @click.prevent="previewArtifact(row)">Preview</a>
                                <a class="table-action-link" :href="row.download_url" target="_blank">Download</a>
                                <a href="#" class="table-action-link danger"
                                   @click.prevent="deleteArtifact(row)">Delete</a>
                            </div>
                        </template>
                    </el-table-column>
                </el-table>
            </div>

            <div class="mobile-file-list-shell">
                <div class="mobile-file-list" v-loading="artifactLoading">
                    <div v-if="!filteredArtifactItems.length && !artifactLoading" class="empty-state">No artifacts
                        available
                    </div>
                    <div v-else class="mobile-file-grid">
                        <div v-for="row in filteredArtifactItems" :key="row.artifact_id" class="mobile-file-card">
                            <div class="mobile-file-card-top">
                                <div class="mobile-file-icon">📄</div>
                                <div class="mobile-file-main">
                                    <div class="mobile-file-name">{{ row.original_name || row.stored_name }}</div>
                                    <div class="mobile-file-tags">
                                        <el-tag v-if="row.hostname" size="small">{{ row.hostname }}</el-tag>
                                    </div>
                                    <div class="mobile-file-meta">
                                        <div class="mobile-file-meta-item">
                                            <div class="mobile-file-meta-label">Category</div>
                                            <div class="mobile-file-meta-value">{{ row.category || '-' }}
                                            </div>
                                        </div>
                                        <div class="mobile-file-meta-item">
                                            <div class="mobile-file-meta-label">Size</div>
                                            <div class="mobile-file-meta-value">{{ formatBytes(row.size) }}</div>
                                        </div>
                                        <div class="mobile-file-meta-item">
                                            <div class="mobile-file-meta-label">Created</div>
                                            <div class="mobile-file-meta-value">{{ row.created_at || '-' }}</div>
                                        </div>
                                    </div>
                                    <div class="mobile-file-actions">
                                        <el-button size="small" type="primary" plain @click="previewArtifact(row)">
                                            Preview
                                        </el-button>
                                        <a class="table-action-link" :href="row.download_url"
                                           target="_blank">Download</a>
                                        <el-button size="small" type="danger" plain @click="deleteArtifact(row)">
                                            Delete
                                        </el-button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </el-dialog>

<el-dialog v-model="scriptLibraryDialogVisible" title="Script Library" width="1180px" top="6vh"
           class="fixed-dialog script-library-dialog">
    <div class="fixed-dialog-body script-library-body" v-loading="scriptLibraryLoading">
        <div class="background-jobs-toolbar script-library-toolbar">
            <div class="script-library-toolbar-left">
<el-button size="small" class="toolbar-btn" type="primary" plain @click="createRemoteScriptPrompt()">New</el-button>
<el-button size="small" class="toolbar-btn" @click="triggerScriptUpload" :loading="serverScriptUploadLoading">Upload</el-button>
<el-button size="small" class="toolbar-btn" @click="createRemoteScriptFolderPrompt">New Folder</el-button>
<el-button size="small" class="toolbar-btn" @click="renameRemoteScriptFolder" :disabled="!selectedScriptDirectory">Rename Folder</el-button>
<el-button size="small" class="toolbar-btn" type="danger" plain @click="deleteRemoteScriptFolder" :disabled="!selectedScriptDirectory">Delete Folder</el-button>

<el-button size="small" class="toolbar-btn" @click="loadScriptCatalog" :loading="scriptLibraryLoading">Refresh</el-button>
                <input id="server-script-upload-input"
                       type="file"
                       accept=".py,text/x-python"
                       style="display: none"
                       @change="handleServerScriptUpload">
            </div>

            <div class="script-library-toolbar-right">
                <span class="background-job-module-key mono">
                    Upload Target: {{ selectedScriptDirectory || 'root' }}
                </span>
            </div>
        </div>

        <div class="script-library-shell">
            <div class="script-library-tree panel-lite">
                <div class="background-jobs-section-title">Folders</div>

                <div class="script-library-pane-scroll">
                    <el-tree
                            :data="scriptDirectoryTreeData"
                            node-key="key"
                            default-expand-all
                            highlight-current
                            :expand-on-click-node="true"
                            class="script-library-tree-view"
                            @node-click="handleScriptTreeNodeClick">
                        <template #default="{ data }">
                            <span class="script-tree-node">
                                <span class="script-tree-node-label">{{ data.label }}</span>
                            </span>
                        </template>
                    </el-tree>

                </div>
            </div>

            <div class="script-library-directory panel-lite">
                <div class="script-library-directory-top">
                    <div>
                        <div class="background-jobs-section-title">{{ selectedScriptDirectory || 'Scripts' }}</div>
                        <div class="background-job-module-key mono">
                            {{ currentScriptDirectoryItems.length }} script<span v-if="currentScriptDirectoryItems.length !== 1">s</span>
                        </div>
                    </div>
                </div>

                <div class="script-library-pane-scroll">
                    <div v-if="currentScriptDirectoryItems.length" class="script-library-card-list script-library-card-list-single">
                        <div v-for="item in currentScriptDirectoryItems"
                             :key="item.script_name"
                             class="script-library-card">
                            <div class="script-library-card-main">
                                <div class="script-library-card-title"
                                     :title="item.display_name || item.script_name">
                                    {{ item.display_name || item.script_name }}
                                </div>

                                <div class="script-library-card-path mono"
                                     :title="item.path || item.script_name">
                                    {{ item.path || item.script_name }}
                                </div>

                                <div class="script-library-card-description"
                                     :title="item.description || ''">
                                    {{ item.description || 'No description' }}
                                </div>

                                <div class="script-tags script-library-card-tags">
                                    <el-tag size="small"
                                            :type="isScriptSupportedForCurrentConnection(item) ? 'info' : 'danger'">
                                        {{ formatScriptPlatformLabel(item) }}
                                    </el-tag>
                                    <el-tag v-if="scriptHasParams(item)" size="small" type="warning">Params</el-tag>
                                </div>
                            </div>

                            <div class="script-library-card-actions">
<!--                                <el-button size="small" type="primary" plain @click="openScriptRunDialog(item)">Run</el-button>-->
                                <el-button size="small"
                                   type="primary"
                                   plain
                                   :disabled="!isScriptSupportedForCurrentConnection(item)"
                                   @click="openScriptRunDialog(item)">
                                    Run
                                </el-button>
                                <el-button size="small" plain @click="openRemoteScriptEditor(item.script_name)">Edit</el-button>
                                <el-button size="small" plain @click="renameServerScript(item.script_name)">Rename</el-button>
                                <el-button size="small" type="danger" plain @click="deleteServerScript(item.script_name)">Delete</el-button>
                            </div>
                        </div>
                    </div>

                    <div v-else class="empty-state">No scripts in this folder</div>
                </div>
            </div>
        </div>
    </div>
</el-dialog>

<el-dialog v-model="scriptRunDialogVisible"
           :title="pendingRunScriptItem ? `Run ${pendingRunScriptItem.display_name || pendingRunScriptItem.script_name}` : 'Run Script'"
           width="680px"
           top="10vh"
           class="fixed-dialog">
    <div v-if="pendingRunScriptItem" class="fixed-dialog-body">
        <div class="script-run-dialog-top">
            <div class="background-job-module-key mono">{{ pendingRunScriptItem.path || pendingRunScriptItem.script_name }}</div>
            <div v-if="pendingRunScriptItem.description" class="script-library-description">{{ pendingRunScriptItem.description }}</div>

            <div class="background-job-module-tags" style="margin-top: 10px;">
                <el-tag size="small" :type="isScriptSupportedForCurrentConnection(pendingRunScriptItem) ? 'info' : 'danger'">
                    {{ formatScriptPlatformLabel(pendingRunScriptItem) }}
                </el-tag>
                <el-tag v-if="pendingRunScriptParamSpecs.length" size="small" type="warning">Params</el-tag>
            </div>
        </div>

        <el-form v-if="pendingRunScriptParamSpecs.length" label-position="top" class="script-library-form">
            <el-form-item v-for="param in pendingRunScriptParamSpecs"
                          :key="`script-param-${param.name}`"
                          :label="`${param.name} (${param.type || 'string'})`">
                <el-switch v-if="param.type === 'boolean'" v-model="scriptParamForm[param.name]"></el-switch>

                <el-select v-else-if="param.type === 'select' && param.options && param.options.length"
                           v-model="scriptParamForm[param.name]"
                           style="width: 100%">
                    <el-option v-for="option in param.options"
                               :key="`${param.name}-${option}`"
                               :label="option"
                               :value="option"></el-option>
                </el-select>

                <el-input v-else
                          v-model="scriptParamForm[param.name]"
                          :placeholder="param.description || param.name"></el-input>

                <div class="hint-text" style="margin-top: 6px;">
                    {{ param.description || 'No description' }}
                    <template v-if="param.required"> · required</template>
                    <template v-if="param.default !== undefined && param.default !== null && param.type !== 'boolean'"> · default: {{ param.default }}</template>
                    <template v-if="param.min !== undefined"> · min: {{ param.min }}</template>
                    <template v-if="param.max !== undefined"> · max: {{ param.max }}</template>
                </div>
            </el-form-item>
        </el-form>

        <div v-else class="empty-state" style="min-height: 96px;">This script has no declared parameters.</div>
    </div>

    <template #footer>
        <el-button @click="closeScriptRunDialog">Cancel</el-button>
        <el-button type="primary" :loading="scriptRunSubmitting" @click="confirmRunScript">Run</el-button>
    </template>
</el-dialog>

    <el-dialog v-model="backgroundJobsDialogVisible" title="Background Jobs" width="1180px" top="5vh"
               class="fixed-dialog  background-jobs-dialog">
        <div class="fixed-dialog-body background-jobs-body">
            <el-tabs v-model="backgroundJobsActiveTab" class="background-jobs-tabs">
                <el-tab-pane label="Modules" name="modules">
                    <div class="background-jobs-toolbar">
                                <el-button size="small" type="primary" class="toolbar-btn" plain @click="createRemoteJobPrompt()">
                            New
                        </el-button>
                                                <el-button size="small" class="toolbar-btn" @click="triggerServerJobUpload"
                                   :loading="serverJobUploadLoading">Upload
                        </el-button>

                        <el-button size="small" class="toolbar-btn" @click="loadBackgroundJobModules"
                                   :loading="backgroundJobModulesLoading">Refresh
                        </el-button>


                        <input id="server-job-upload-input"
                               type="file"
                               accept=".py,text/x-python"
                               style="display: none"
                               @change="handleServerJobUpload">
                    </div>
                    <div class="background-jobs-modules panel-lite">
                        <div class="background-jobs-section-title">Available Jobs</div>
                        <div v-if="!backgroundJobModules.length && !backgroundJobModulesLoading" class="empty-state">No
                            background jobs available
                        </div>
                        <!-- 统一展示远程 background job -->
                        <div class="background-job-module-list" v-else>
                            <div v-for="item in backgroundJobModules"
     :key="item.module_id || `job:${item.job_name}`"
     class="background-job-module-card">
    <div class="background-job-module-main">
        <div class="background-job-module-name"
             :title="item.display_name || item.job_name">
            {{ item.display_name || item.job_name }}
        </div>

        <div v-if="item.subtitle"
             class="background-job-module-key mono"
             :title="item.subtitle">
            {{ item.subtitle }}
        </div>

        <div v-if="item.description"
             class="background-job-module-desc"
             :title="item.description">
            {{ item.description }}
        </div>

        <div class="background-job-module-tags">
            <el-tag size="small"
                    :type="isJobSupportedForCurrentConnection(item) ? 'info' : 'danger'">
                {{ formatJobPlatformLabel(item.metadata?.platforms || []) }}
            </el-tag>
            <el-tag v-if="hasBackgroundJobParams(item)" size="small" type="warning">
                Params
            </el-tag>
        </div>
    </div>

    <div class="background-job-module-actions">
        <el-button
            size="small"
            type="primary"
            plain
            @click="openBackgroundJobStartDialog(item)"
            :disabled="isBackgroundJobStartDisabled(item)"
        >
            Start
        </el-button>
        <el-button size="small"
                   plain
                   @click="openRemoteJobEditor(item.job_name)">
            Edit
        </el-button>
        <el-button size="small"
                   type="danger"
                   plain
                   @click="deleteRemoteScript(item.job_name)">
            Delete
        </el-button>
    </div>
</div>
                        </div>
                    </div>
                </el-tab-pane>

                <el-tab-pane label="Jobs" name="jobs">
                    <div class="background-jobs-toolbar">
                        <el-button size="small" class="toolbar-btn" @click="loadBackgroundJobs" :loading="backgroundJobsLoading">Refresh
                        </el-button>
                    </div>
                    <div class="background-jobs-list-shell panel-lite" v-loading="backgroundJobsLoading">
                        <div class="background-jobs-section-title">Reported Jobs</div>
                        <div v-if="!sortedBackgroundJobs.length && !backgroundJobsLoading" class="empty-state">No
                            background jobs reported for this connection
                        </div>
                        <div v-else class="background-jobs-list">
                            <div v-for="job in sortedBackgroundJobs" :key="job.job_id"
                                 class="background-job-summary-card">
                                <div class="background-job-summary-main">
                                    <div class="background-job-summary-top">
                                        <div class="background-job-summary-title-wrap">
                                            <div class="background-job-summary-title-line">
                                                <span class="background-job-summary-title">{{ job.display_name || job.job_name }}</span>
                                                <el-tag :type="buildBackgroundJobStateTagType(job.state)" size="small">
                                                    {{ job.state || 'unknown' }}
                                                </el-tag>
                                            </div>
                                            <div class="background-job-summary-subtitle mono">{{ job.job_name }} / {{
                                                job.job_key || '-' }}
                                            </div>
                                        </div>
                                    </div>
                                    <div class="background-job-summary-stats">
                                        <span>{{ formatBackgroundJobDuration(job.duration_seconds) }}</span>
                                        <span>{{ job.message_count || 0 }} msgs</span>
                                        <span>{{ job.file_count || 0 }} files</span>
                                        <span>{{ job.thread_name || '-' }}</span>
                                        <span>{{ formatDateTimeStandard(job.started_at) || '-' }}</span>
                                    </div>
                                </div>
                                <div class="background-job-summary-actions">
                                    <el-button size="small" plain @click="openBackgroundJobDetail(job)">Details
                                    </el-button>
                                    <el-button size="small" type="danger" plain @click="stopBackgroundJob(job)"
                                               :disabled="!job.job_key || job.state === 'stopped'">Stop
                                    </el-button>
                                </div>
                            </div>
                        </div>
                    </div>
                </el-tab-pane>
            </el-tabs>
        </div>
    </el-dialog>

    <el-dialog v-model="backgroundJobStartDialogVisible"
               :title="pendingStartJobModule ? `Start ${pendingStartJobModule.display_name || pendingStartJobModule.job_name}` : 'Start Background Job'"
               width="640px" top="10vh" class="fixed-dialog">
        <div v-if="pendingStartJobModule" class="fixed-dialog-body">
            <div class="background-jobs-section-title">{{ pendingStartJobModule.description || 'Configure job parameters before starting' }}</div>
            <div class="background-job-module-tags" style="margin-bottom: 12px;">
                <el-tag size="small" :type="isJobSupportedForCurrentConnection(pendingStartJobModule) ? 'info' : 'danger'">
                    {{ formatJobPlatformLabel(pendingStartJobModule.metadata?.platforms || []) }}
                </el-tag>
            </div>
            <el-form label-position="top">
                <el-form-item v-for="param in (pendingStartJobModule.metadata?.params || [])"
                              :key="`job-param-${param.name}`"
                              :label="`${param.name} (${param.type || 'string'})`">
                    <el-input v-model="backgroundJobParamForm[param.name]"
                              :placeholder="param.description || param.name"></el-input>
                    <div class="hint-text" style="margin-top: 6px;">
                        {{ param.description || 'No description' }}
                        <template v-if="param.required"> · required</template>
                        <template v-if="param.default !== undefined && param.default !== null"> · default: {{ param.default }}</template>
                        <template v-if="param.min !== undefined"> · min: {{ param.min }}</template>
                        <template v-if="param.max !== undefined"> · max: {{ param.max }}</template>
                    </div>
                </el-form-item>
            </el-form>
        </div>
        <template #footer>
            <el-button @click="closeBackgroundJobStartDialog">Cancel</el-button>
            <el-button type="primary"
                       :loading="backgroundJobStartSubmitting"
                       @click="confirmStartBackgroundJobWithParams">
                Start
            </el-button>
        </template>
    </el-dialog>

    <el-dialog v-model="backgroundJobDetailDialogVisible"
               :title="selectedBackgroundJob ? (selectedBackgroundJob.display_name || selectedBackgroundJob.job_name || 'Background Job') : 'Background Job Detail'"
               width="1080px" top="5vh" class="fixed-dialog background-job-detail-dialog">
        <div class="fixed-dialog-body" v-if="selectedBackgroundJob">
            <div class="background-job-detail-head">
                <div class="background-job-detail-head-left">
                    <div class="background-job-title-line">
                        <div class="background-job-title">{{ selectedBackgroundJob.display_name ||
                            selectedBackgroundJob.job_name }}
                        </div>
                        <el-tag :type="buildBackgroundJobStateTagType(selectedBackgroundJob.state)" size="small">{{
                            selectedBackgroundJob.state || 'unknown' }}
                        </el-tag>
                    </div>
                    <div class="background-job-subtitle mono">{{ selectedBackgroundJob.job_name }} / {{
                        selectedBackgroundJob.job_key || '-' }}
                    </div>
                </div>
                <div class="background-job-card-head-right">
                    <el-button size="small" type="danger" plain @click="stopBackgroundJob(selectedBackgroundJob)"
                               :disabled="!selectedBackgroundJob.job_key || selectedBackgroundJob.state === 'stopped'">
                        Stop
                    </el-button>
                </div>
            </div>

            <div class="background-job-stats">
                <div class="background-job-stat">
                    <div class="background-job-stat-label">Duration</div>
                    <div class="background-job-stat-value">{{
                        formatBackgroundJobDuration(selectedBackgroundJob.duration_seconds) }}
                    </div>
                </div>
                <div class="background-job-stat">
                    <div class="background-job-stat-label">Messages</div>
                    <div class="background-job-stat-value">{{ selectedBackgroundJob.message_count || 0 }}</div>
                </div>
                <div class="background-job-stat">
                    <div class="background-job-stat-label">Files</div>
                    <div class="background-job-stat-value">{{ selectedBackgroundJob.file_count || 0 }}</div>
                </div>
                <div class="background-job-stat">
                    <div class="background-job-stat-label">Started</div>
                    <div class="background-job-stat-value">{{ formatDateTimeStandard(selectedBackgroundJob.started_at)
                        || '-' }}
                    </div>
                </div>
                <div class="background-job-stat">
                    <div class="background-job-stat-label">Stopped</div>
                    <div class="background-job-stat-value">{{ formatDateTimeStandard(selectedBackgroundJob.stopped_at)
                        || '-' }}
                    </div>
                </div>
                <div class="background-job-stat">
                    <div class="background-job-stat-label">Thread</div>
                    <div class="background-job-stat-value mono">{{ selectedBackgroundJob.thread_name || '-' }}</div>
                </div>
            </div>

            <div class="background-job-panels">
                <div class="background-job-panel">
                    <div class="background-job-panel-title">Messages</div>
                    <div class="background-job-message-list">
                        <div v-for="(message, index) in selectedBackgroundJobMessagesDesc"
                             :key="`${selectedBackgroundJob.job_id}-msg-${index}`"
                             class="background-job-message-item clickable"
                             @click="openBackgroundJobMessageDialog(message)">
                            <div class="background-job-message-time">{{ formatDateTimeStandard(message.time) || '-' }}
                            </div>
                            <div class="background-job-message-text single-line"
                                 :class="{ 'is-error': message.status === 0, 'is-success': message.status === 1 }">{{
                                formatBackgroundJobMessageText(message.text || '') }}
                            </div>
                        </div>
                        <div v-if="!selectedBackgroundJob.messages || !selectedBackgroundJob.messages.length"
                             class="empty-state compact">No messages
                        </div>
                    </div>
                </div>

                <div class="background-job-panel">
                    <div class="background-job-panel-title">Files</div>
                    <div class="background-job-file-list">
                        <div v-for="(file, index) in selectedBackgroundJob.files"
                             :key="`${selectedBackgroundJob.job_id}-file-${index}`" class="background-job-file-item">
                            <div class="background-job-file-main">
                                <div class="background-job-file-name">{{ file.original_name || file.stored_name || '-'
                                    }}
                                </div>
                                <div class="background-job-file-meta">
                                    <span>{{ formatBytes(file.size || 0) }}</span>
                                    <span>{{ formatDateTimeStandard(file.time) || '-' }}</span>
                                </div>
                            </div>
                            <div class="background-job-file-actions">
                                <a class="table-action-link" style="cursor:pointer"
                                   @click="previewBackgroundJobFile(file)">Preview</a>
                                <a class="table-action-link" :href="file.download_url" target="_blank">Download</a>
                            </div>
                        </div>
                        <div v-if="!selectedBackgroundJob.files || !selectedBackgroundJob.files.length"
                             class="empty-state compact">No files
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </el-dialog>

    <el-dialog v-model="backgroundJobMessageDialogVisible" title="Message" width="760px" top="8vh"
               class="fixed-dialog background-job-message-dialog">
        <div class="fixed-dialog-body">
            <div class="background-job-full-message-time">{{ formatDateTimeStandard(selectedBackgroundJobMessage.time)
                || '-' }}
            </div>
            <pre class="background-job-full-message-text"
                 :class="{ 'is-error': selectedBackgroundJobMessage.status === 0, 'is-success': selectedBackgroundJobMessage.status === 1 }">{{ formatBackgroundJobMessageText(selectedBackgroundJobMessage.text || '') }}</pre>
        </div>
    </el-dialog>

    <el-dialog v-model="previewDialogVisible" :title="previewTitle || 'File Preview'" width="1080px" top="5vh"
               class="fixed-dialog preview-dialog">
        <div v-loading="previewLoading" class="preview-wrap">
            <div class="preview-toolbar" v-if="previewType === 'image' || previewType === 'text'">
                <div class="preview-toolbar-left">
                    <template v-if="previewType === 'text'">
                        <el-button size="small" @click="copyPreviewText">
                            Copy
                        </el-button>
                        <el-button
                                v-if="!previewEditMode && !previewTruncated"
                                size="small"
                                type="primary"
                                @click="enterEditMode"
                        >
                            Edit
                        </el-button>
                        <template v-else-if="previewEditMode">

                            <el-button
                                    size="small"
                                    type="primary"
                                    :loading="previewSaving"
                                    @click="saveEditedContent"
                            >
                                Save
                            </el-button>
                            <el-button
                                    size="small"
                                    @click="cancelEditMode"
                            >
                                Cancel
                            </el-button>
                                        <el-button
                                    size="small"
                                    type="danger"
                                    plain
                                    @click="clearPreviewContent"
                            >
                                Clear
                            </el-button>
                        </template>
                    </template>
      <template v-if="previewType === 'image' && previewUrl">
    <el-button
            v-if="previewImageInfo"
            size="small"
            @click="openPreviewImageInfoDialog"
    >
        Image Info
    </el-button>
    <el-button size="small" @click="openPreviewOriginal">
        Open Original
    </el-button>
</template>
                </div>

                <div class="preview-toolbar-right">
                    <template v-if="previewType === 'text'">
                        <div class="preview-info-tags">
                            <el-tag size="small" type="primary">
                                {{ previewSourceLabel }}
                            </el-tag>
                            <el-tag size="small" type="info">{{ previewFileSize }}</el-tag>
                            <el-tag size="small" type="info">{{ previewFileEncoding }}</el-tag>
                         <el-tag size="small" type="info">{{ previewDetectedLanguage }}</el-tag>

                            <el-tag v-if="previewTruncated" size="small" type="danger">
                                Truncated - Edit disabled
                            </el-tag>
                            <el-tag v-else size="small" type="success">Full content</el-tag>
                        </div>
                    </template>
                </div>
            </div>

            <template v-if="previewType === 'image' && previewUrl">
                <div class="image-preview-box"><img :src="previewUrl" alt="preview" class="preview-image"/></div>
            </template>

            <template v-else-if="previewType === 'text'">
                <!-- Monaco Editor 容器 -->
                <div id="monaco-editor-container" class="monaco-editor-container"></div>
            </template>

            <template v-else-if="previewType === 'unsupported'">
                <div class="empty-state">This file type is not supported for preview.</div>
            </template>
            <template v-else>
                <div class="empty-state">No preview available.</div>
            </template>
        </div>
    </el-dialog>

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


    <el-dialog
        v-model="terminalJsonDialogVisible"
        :title="terminalJsonDialogTitle"
        width="980px"
        top="8vh"
        class="fixed-dialog"
>
    <template v-if="terminalJsonDisplayMode === 'table'">
        <div style="max-height: 65vh; overflow: auto;">
            <el-table
                    :data="terminalJsonTableRows"
                    border
                    stripe
                    style="width: 100%;"
            >
                <el-table-column
                        v-for="column in terminalJsonTableColumns"
                        :key="column.prop"
                        :prop="column.prop"
                        :label="column.label"
                        min-width="140"
                        show-overflow-tooltip
                />
            </el-table>
        </div>
    </template>

    <template v-else-if="terminalJsonDisplayMode === 'flat'">
        <div style="max-height: 65vh; overflow: auto;">
            <div
                    v-for="item in terminalJsonFlatRows"
                    :key="item.key"
                    style="display: grid; grid-template-columns: 220px 1fr; gap: 12px; padding: 8px 0; border-bottom: 1px solid #ebeef5;"
            >
                <div style="color: #606266; font-weight: 500; word-break: break-word;">
                    {{ item.label }}
                </div>
                <div style="word-break: break-word;">
                    {{ item.value }}
                </div>
            </div>
        </div>
    </template>

    <template v-else>
        <div style="max-height: 65vh; overflow: auto;">
            <pre
                    style="margin: 0; white-space: pre-wrap; word-break: break-word; font-family: monospace; font-size: 13px; line-height: 1.6;"
            >{{ terminalJsonText }}</pre>
        </div>
    </template>
</el-dialog>
   <el-dialog
        v-model="previewImageInfoDialogVisible"
        title="Image Info"
        width="760px"
        top="8vh"
        class="fixed-dialog"
>
    <div style="max-height: 65vh; overflow: auto;">
        <template v-if="previewImageInfo">
            <div
                    v-if="formatPreviewImageInfo(previewImageInfo).basic.length"
                    style="margin-bottom: 20px;"
            >
                <div style="font-weight: 600; font-size: 14px; margin-bottom: 10px;">
                    Basic
                </div>
                <div
                        v-for="item in formatPreviewImageInfo(previewImageInfo).basic"
                        :key="'basic-' + item.key"
                        style="display: grid; grid-template-columns: 180px 1fr; gap: 12px; padding: 8px 0; border-bottom: 1px solid #ebeef5;"
                >
                    <div style="color: #606266; font-weight: 500;">{{ item.label }}</div>
                    <div style="word-break: break-word;">{{ item.value }}</div>
                </div>
            </div>

            <div
                    v-if="formatPreviewImageInfo(previewImageInfo).exif.length"
                    style="margin-bottom: 20px;"
            >
                <div style="font-weight: 600; font-size: 14px; margin-bottom: 10px;">
                    EXIF
                </div>
                <div
                        v-for="item in formatPreviewImageInfo(previewImageInfo).exif"
                        :key="'exif-' + item.key"
                        style="display: grid; grid-template-columns: 180px 1fr; gap: 12px; padding: 8px 0; border-bottom: 1px solid #ebeef5;"
                >
                    <div style="color: #606266; font-weight: 500;">{{ item.label }}</div>
                    <div style="word-break: break-word;">{{ item.value }}</div>
                </div>
            </div>

            <div v-if="formatPreviewImageInfo(previewImageInfo).other.length">
                <div style="font-weight: 600; font-size: 14px; margin-bottom: 10px;">
                    Other
                </div>
                <div
                        v-for="item in formatPreviewImageInfo(previewImageInfo).other"
                        :key="'other-' + item.key"
                        style="display: grid; grid-template-columns: 180px 1fr; gap: 12px; padding: 8px 0; border-bottom: 1px solid #ebeef5;"
                >
                    <div style="color: #606266; font-weight: 500;">{{ item.label }}</div>
                    <div style="word-break: break-word;">{{ item.value }}</div>
                </div>
            </div>
        </template>

        <el-empty v-else description="No image info available"></el-empty>
    </div>
</el-dialog>



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


    <el-dialog
        v-model="ptyDialogVisible"
        title="Remote PTY"
        width="900px"
        top="6vh"
        class="fixed-dialog pty-dialog"
        @closed="handlePtyDialogClosed"
    >
        <div class="pty-shell">
            <div class="pty-toolbar">
                <div class="pty-toolbar-left">
                    <span class="pty-badge">{{ currentConnection ? (currentConnection.hostname || currentConnection.client_id) : 'No device' }}</span>
                    <span class="pty-badge pty-badge-status">{{ ptyStatus || 'idle' }}</span>
                    <span v-if="ptyError" class="pty-error-text">{{ ptyError }}</span>
                </div>
                <div class="pty-toolbar-right">
                    <el-input v-model="ptyShellPath" size="small" placeholder="Optional shell path" class="pty-shell-input"/>
                    <el-button size="small" @click="focusPtyInput">Focus</el-button>
                    <el-button size="small" @click="closePtyDialog">Close</el-button>
                </div>
            </div>
            <div class="pty-screen-shell xterm-shell" @click="focusPtyInput">
                <div ref="ptyTerminalRef" class="pty-terminal-host"></div>
            </div>
            <div class="pty-hint">Powered by xterm.js. Supports ANSI control sequences, vim/less/top style full-screen apps, sudo prompts, paste and resize.</div>
        </div>
    </el-dialog>
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

export default {
  components: {
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
