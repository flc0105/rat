<template>
  <el-dialog
    v-model="visible"
    title="External Tool Manager"
    width="1240px"
    top="5vh"
    class="fixed-dialog external-tool-dialog"
    modal-class="external-tool-overlay"
    @closed="handleClosed"
  >
    <div class="fixed-dialog-body external-tool-body" v-loading="loading">
      <div class="external-tool-toolbar">
        <div class="external-tool-toolbar-left">
          <el-button size="small" :loading="loading" @click="refreshAll">
            Refresh
          </el-button>

          <div class="external-tool-target-control">
            <el-select
              v-model="deviceFilter"
              size="small"
              filterable
              class="external-tool-target-select"
              placeholder="Select target"
              @change="handleTargetFilterChange"
            >
              <el-option
                v-for="item in deviceFilterOptions"
                :key="item.value"
                :label="item.label"
                :value="item.value"
              />
            </el-select>
          </div>

          <el-checkbox
            v-if="activeTab === 'modules'"
            v-model="packageOnlyCompatible"
            size="small"
            @change="handlePackageOnlyCompatibleChange"
          >
            Only compatible
          </el-checkbox>
        </div>

        <div class="external-tool-toolbar-right">
          <el-input
            v-model="searchText"
            size="small"
            clearable
            class="external-tool-search"
            :placeholder="activeTab === 'modules' ? 'Search modules/packages' : 'Search instances'"
          />
        </div>
      </div>

      <el-tabs v-model="activeTab" class="external-tool-tabs">
        <el-tab-pane label="Packages" name="modules">
          <div v-if="filteredModules.length" class="external-tool-package-split">
            <div class="external-tool-package-list-panel">
              <div class="external-tool-package-list">
                <div
                  v-for="item in filteredModules"
                  :key="item.id"
                  class="external-tool-card external-tool-package-list-card"
                  :class="{ active: selectedPackage?.id === item.id }"
                  @click="selectPackage(item)"
                >
                  <div class="external-tool-card-main">
                    <div class="external-tool-package-list-title" :title="item.display_name || item.id">
                      {{ item.display_name || item.id }}
                    </div>
                    <div class="external-tool-package-list-status">
                      <el-tag
                        v-if="getModuleInstallStatus(item).label"
                        size="small"
                        :type="getModuleInstallStatus(item).type"
                        effect="plain"
                      >
                        {{ getModuleInstallStatus(item).label }}
                      </el-tag>
                      <span v-else class="muted small-text">Unknown</span>
                      <template v-if="selectedPackage?.id === item.id">
                        <el-tag size="small" type="info" class="external-tool-package-list-mobile-meta-tag">
                          {{ formatPlatforms(item.platforms) }}
                        </el-tag>
                        <el-tag
                          v-if="item.version"
                          size="small"
                          type="info"
                          class="external-tool-package-list-mobile-meta-tag"
                        >
                          {{ formatVersionLabel(item.version) }}
                        </el-tag>
                      </template>
                    </div>
                    <div class="external-tool-package-list-desc" :title="item.description || ''">
                      {{ item.description || 'No description' }}
                    </div>

                    <div
                      v-if="selectedPackage?.id === item.id"
                      class="external-tool-package-mobile-detail"
                      @click.stop
                    >
                      <div class="external-tool-package-mobile-actions">
                        <el-button
                          class="external-tool-package-mobile-action-button"
                          size="small"
                          type="primary"
                          plain
                          :disabled="!canInstallPackageAction(item)"
                          @click.stop="installOnly(item)"
                        >
                          {{ getInstallMenuLabel(item) }}
                        </el-button>

                        <el-dropdown
                          trigger="click"
                          size="small"
                          @command="handlePackageMoreCommand($event, item)"
                        >
                          <el-button
                            class="external-tool-package-mobile-action-button"
                            size="small"
                            plain
                            @click.stop
                          >
                            More
                          </el-button>
                          <template #dropdown>
                            <el-dropdown-menu>
                              <el-dropdown-item command="download">
                                Download Zip
                              </el-dropdown-item>
                              <el-dropdown-item command="edit">
                                Edit Metadata
                              </el-dropdown-item>
                              <el-dropdown-item divided command="status" :disabled="!canUsePackageAction(item)">
                                Install Status
                              </el-dropdown-item>
                              <el-dropdown-item command="copy" :disabled="!canUsePackageAction(item)">
                                Copy Command
                              </el-dropdown-item>
                              <el-dropdown-item
                                command="clear_cache"
                                divided
                                :disabled="!canUsePackageAction(item)"
                              >
                                Clear Package Cache
                              </el-dropdown-item>
                              <el-dropdown-item
                                command="uninstall"
                                :disabled="!canUninstallPackageAction(item)"
                              >
                                {{ getUninstallMenuLabel(item) }}
                              </el-dropdown-item>
                            </el-dropdown-menu>
                          </template>
                        </el-dropdown>
                      </div>

                      <div class="external-tool-modules-panel external-tool-package-mobile-modules">
                        <div class="external-tool-detail-section-title">Modules</div>
                        <div v-if="getPackageModules(item).length" class="external-tool-package-modules detail">
                          <div
                            v-for="module in getPackageModules(item)"
                            :key="module.id"
                            class="external-tool-package-module-card"
                          >
                            <div class="external-tool-package-module-content">
                              <div class="external-tool-package-module-title-row">
                                <span class="strong">{{ module.display_name || module.id }}</span>
                                <el-tag size="small" type="info">daemon</el-tag>
                              </div>
                              <div class="external-tool-package-module-desc" :title="module.description || ''">
                                {{ module.description || 'No description' }}
                              </div>
                            </div>
                            <el-button
                              size="small"
                              type="primary"
                              plain
                              :disabled="!canRunModuleAction(module)"
                              @click.stop="openStartDialog(module, getSelectedTargetSideForAction(), 'run')"
                            >
                              {{ getRunButtonLabel(module) }}
                            </el-button>
                          </div>
                        </div>
                        <div v-else class="external-tool-empty small">
                          No runnable modules.
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="external-tool-package-detail-panel">
              <div v-if="selectedPackage" class="external-tool-package-detail-card">
                <div class="external-tool-package-detail-header">
                  <div class="external-tool-package-detail-main">
                    <div class="external-tool-title large" :title="selectedPackage.display_name || selectedPackage.id">
                      {{ selectedPackage.display_name || selectedPackage.id }}
                    </div>
                    <div class="external-tool-package-detail-tags">
                      <el-tag size="small" type="info">
                        {{ formatPlatforms(selectedPackage.platforms) }}
                      </el-tag>
                      <el-tag v-if="selectedPackage.version" size="small" type="info">
                        {{ formatVersionLabel(selectedPackage.version) }}
                      </el-tag>
                      <el-tag
                        v-if="getModuleInstallStatus(selectedPackage).label"
                        size="small"
                        :type="getModuleInstallStatus(selectedPackage).type"
                        effect="plain"
                      >
                        {{ getModuleInstallStatus(selectedPackage).label }}
                      </el-tag>
                    </div>
                    <div class="external-tool-desc external-tool-package-detail-desc" :title="selectedPackage.description || ''">
                      {{ selectedPackage.description || 'No description' }}
                    </div>
                  </div>

                  <div class="external-tool-package-detail-actions">
                    <div class="external-tool-package-detail-action-row">
                      <el-button
                        class="external-tool-package-detail-action-button"
                        size="small"
                        type="primary"
                        plain
                        :disabled="!canInstallPackageAction(selectedPackage)"
                        @click="installOnly(selectedPackage)"
                      >
                        {{ getInstallMenuLabel(selectedPackage) }}
                      </el-button>

                      <el-dropdown
                        trigger="click"
                        size="small"
                        @command="handlePackageMoreCommand($event, selectedPackage)"
                      >
                        <el-button class="external-tool-package-detail-action-button" size="small" plain>
                          More
                        </el-button>
                        <template #dropdown>
                          <el-dropdown-menu>
                            <el-dropdown-item command="download">
                              Download Zip
                            </el-dropdown-item>
                            <el-dropdown-item command="edit">
                              Edit Metadata
                            </el-dropdown-item>
                            <el-dropdown-item divided command="status" :disabled="!canUsePackageAction(selectedPackage)">
                              Install Status
                            </el-dropdown-item>
                            <el-dropdown-item command="copy" :disabled="!canUsePackageAction(selectedPackage)">
                              Copy Command
                            </el-dropdown-item>
                            <el-dropdown-item
                              command="clear_cache"
                              divided
                              :disabled="!canUsePackageAction(selectedPackage)"
                            >
                              Clear Package Cache
                            </el-dropdown-item>
                            <el-dropdown-item
                              command="uninstall"
                              :disabled="!canUninstallPackageAction(selectedPackage)"
                            >
                              {{ getUninstallMenuLabel(selectedPackage) }}
                            </el-dropdown-item>
                          </el-dropdown-menu>
                        </template>
                      </el-dropdown>
                    </div>
                  </div>
                </div>

                <div class="external-tool-package-detail-section external-tool-modules-panel">
                  <div class="external-tool-detail-section-title">Modules</div>
                  <div v-if="getPackageModules(selectedPackage).length" class="external-tool-package-modules detail">
                    <div
                      v-for="module in getPackageModules(selectedPackage)"
                      :key="module.id"
                      class="external-tool-package-module-card"
                    >
                      <div class="external-tool-package-module-content">
                        <div class="external-tool-package-module-title-row">
                          <span class="strong">{{ module.display_name || module.id }}</span>
                          <el-tag size="small" type="info">daemon</el-tag>
                        </div>
                        <div class="external-tool-package-module-desc" :title="module.description || ''">
                          {{ module.description || 'No description' }}
                        </div>
                      </div>
                      <el-button
                        size="small"
                        type="primary"
                        plain
                        :disabled="!canRunModuleAction(module)"
                        @click="openStartDialog(module, getSelectedTargetSideForAction(), 'run')"
                      >
                        {{ getRunButtonLabel(module) }}
                      </el-button>
                    </div>
                  </div>
                  <div v-else class="external-tool-empty small">
                    No runnable modules.
                  </div>
                </div>
              </div>
              <div v-else class="external-tool-empty">
                Select a package.
              </div>
            </div>
          </div>

          <div v-else class="external-tool-empty">
            {{ searchText ? 'No matching external tool packages' : 'No external tool meta files found' }}
          </div>
        </el-tab-pane>

        <el-tab-pane label="Instances" name="instances">
          <div class="external-tool-instance-toolbar">
            <div class="external-tool-hint">
              Target: {{ activeDeviceFilterLabel }}.
            </div>
          </div>

          <div v-if="filteredInstances.length" class="external-tool-instance-table-shell">
            <el-table
              :data="filteredInstances"
              size="small"
              class="external-tool-instance-table"
              height="560"
              row-key="row_key"
            >
<!--            <el-table-column label="Target" min-width="190">-->
<!--              <template #default="{ row }">-->
<!--                <div class="mono strong" :title="row.machine_id || row.device_id">{{ row.machine_label || '-' }}</div>-->
<!--&lt;!&ndash;                <div class="muted mono" :title="row.connection_id || row.device_id">&ndash;&gt;-->
<!--&lt;!&ndash;                  {{ row.connection_id ? `conn: ${shortenDeviceId(row.connection_id)}` : '-' }}&ndash;&gt;-->
<!--&lt;!&ndash;                </div>&ndash;&gt;-->
<!--              </template>-->
<!--            </el-table-column>-->


              <el-table-column label="Instance" min-width="170">
                <template #default="{ row }">
                  <div class="mono strong" :title="row.instance_id">{{ row.instance_id }}</div>
                  <div class="muted mono" :title="row.tool_id">{{ row.tool_id }}</div>
                </template>
              </el-table-column>

              <el-table-column label="Status" width="110">
                <template #default="{ row }">
                  <el-tag size="small" :type="statusTagType(row.status)">
                    {{ row.status || '-' }}
                  </el-tag>
                </template>
              </el-table-column>



              <el-table-column label="PID" width="95">
                <template #default="{ row }">
                  <span class="mono">{{ row.pid || '-' }}</span>
                </template>
              </el-table-column>

              <el-table-column label="Port" min-width="210">
                <template #default="{ row }">
                  <span class="mono" :title="formatPortInfo(row)">{{ formatPortInfo(row) }}</span>
                </template>
              </el-table-column>

              <el-table-column label="Started" width="180">
                <template #default="{ row }">
                  <span class="mono muted">{{ shortTime(row.started_at) }}</span>
                </template>
              </el-table-column>

              <el-table-column label="Actions" width="240">
                <template #default="{ row }">
                  <div class="external-tool-table-actions">
                    <el-button size="small" plain @click="openInstanceLogs(row)">
                      Logs
                    </el-button>
<!--                  <el-button size="small" plain @click="openInstanceInfo(row)">-->
<!--                    Info-->
<!--                  </el-button>-->
                    <el-button
                      size="small"
                      type="danger"
                      plain
                      :disabled="!row.running && row.status !== 'stale'"
                      @click="stopInstance(row)"
                    >
                      Stop
                    </el-button>
                    <el-dropdown
                      trigger="click"
                      size="small"
                      @command="handleInstanceMoreCommand($event, row)"
                    >
                      <el-button size="small" plain>
                        More
                      </el-button>
                      <template #dropdown>
                        <el-dropdown-menu>
                          <el-dropdown-item command="info">
                            Info
                          </el-dropdown-item>

                          <el-dropdown-item
                            v-if="canOpenWebInstance(row)"
                            command="open_web"
                          >
                            Open Web
                          </el-dropdown-item>

                          <el-dropdown-item command="restart" :disabled="!canRestartInstance(row)">
                            Restart
                          </el-dropdown-item>
                          <el-dropdown-item command="clear_logs" :disabled="!canModifyStoppedInstanceFiles(row)">
                            Clear Logs
                          </el-dropdown-item>
                          <el-dropdown-item command="remove" :disabled="!canModifyStoppedInstanceFiles(row)">
                            Remove
                          </el-dropdown-item>
                        </el-dropdown-menu>
                      </template>
                    </el-dropdown>
                  </div>
                </template>
              </el-table-column>
            </el-table>
          </div>

          <div v-if="filteredInstances.length" class="external-tool-instance-card-shell">
            <div class="external-tool-instance-card-list">
              <div
                v-for="row in filteredInstances"
                :key="row.row_key"
                class="external-tool-instance-card"
              >
                <div class="external-tool-instance-card-top">
                  <div class="external-tool-instance-icon">
                    <span :class="{ running: row.running, stale: row.status === 'stale' }"></span>
                  </div>

                  <div class="external-tool-instance-card-main">
                    <div class="external-tool-instance-name" :title="row.instance_id">
                      {{ row.instance_id }}
                    </div>

                    <div class="external-tool-instance-tags">
                      <el-tag size="small" :type="statusTagType(row.status)">
                        {{ row.status || '-' }}
                      </el-tag>
                      <el-tag size="small" type="info">
                        {{ row.side || '-' }}
                      </el-tag>
                      <el-tag size="small" type="info">
                        {{ row.display_name || row.tool_id }}
                      </el-tag>
                    </div>

                    <div class="external-tool-instance-meta">
                      <div class="external-tool-instance-meta-item">
                        <div class="external-tool-instance-meta-label">Tool</div>
                        <div class="external-tool-instance-meta-value mono" :title="row.tool_id">
                          {{ row.tool_id || '-' }}
                        </div>
                      </div>

                      <div class="external-tool-instance-meta-item">
                        <div class="external-tool-instance-meta-label">PID</div>
                        <div class="external-tool-instance-meta-value mono">
                          {{ row.pid || '-' }}
                        </div>
                      </div>

                      <div class="external-tool-instance-meta-item">
                        <div class="external-tool-instance-meta-label">Port</div>
                        <div class="external-tool-instance-meta-value mono" :title="formatPortInfo(row)">
                          {{ formatPortInfo(row) }}
                        </div>
                      </div>

                      <div class="external-tool-instance-meta-item">
                        <div class="external-tool-instance-meta-label">Started</div>
                        <div class="external-tool-instance-meta-value mono">
                          {{ shortTime(row.started_at) }}
                        </div>
                      </div>
                    </div>

                    <div class="external-tool-instance-card-actions">
                      <el-button size="small" type="primary" plain @click="openInstanceLogs(row)">
                        Logs
                      </el-button>
                      <el-button
                        size="small"
                        type="danger"
                        plain
                        :disabled="!row.running && row.status !== 'stale'"
                        @click="stopInstance(row)"
                      >
                        Stop
                      </el-button>
                      <el-dropdown
                        trigger="click"
                        size="small"
                        @command="handleInstanceMoreCommand($event, row)"
                      >
                        <el-button size="small" plain>
                          More
                        </el-button>
                        <template #dropdown>
                          <el-dropdown-menu>
                            <el-dropdown-item command="info">
                              Info
                            </el-dropdown-item>
                            <el-dropdown-item
                              v-if="canOpenWebInstance(row)"
                              command="open_web"
                            >
                              Open Web
                            </el-dropdown-item>
                            <el-dropdown-item command="restart" :disabled="!canRestartInstance(row)">
                              Restart
                            </el-dropdown-item>
                            <el-dropdown-item command="clear_logs" :disabled="!canModifyStoppedInstanceFiles(row)">
                              Clear Logs
                            </el-dropdown-item>
                            <el-dropdown-item command="remove" :disabled="!canModifyStoppedInstanceFiles(row)">
                              Remove
                            </el-dropdown-item>
                          </el-dropdown-menu>
                        </template>
                      </el-dropdown>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div v-else class="external-tool-empty">
            {{ searchText || deviceFilter ? 'No matching instances' : 'No instances yet. Start one from Packages.' }}
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>
  </el-dialog>

  <el-dialog
    v-model="startDialogVisible"
    :title="startDialogTitle"
    width="650px"
    append-to-body
    @closed="resetStartDialog"
  >
    <div v-if="pendingItem" class="external-tool-run-body">
      <div class="external-tool-run-summary">
        <div><strong>{{ pendingItem.display_name || pendingItem.id }}</strong></div>
        <div class="mono">{{ pendingItem.id }} / {{ activeDeviceFilterLabel }}</div>
        <div class="external-tool-param-help">
          Instance Name isolates config, pid, state and logs. Example: vite-8087 or ssh-6000.
        </div>
      </div>

      <el-form label-position="top" class="external-tool-param-form">
        <el-form-item
          v-for="param in pendingParams"
          :key="param.name"
          :label="formatParamLabel(param)"
        >
          <el-switch
            v-if="normalizeParamType(param.type) === 'boolean'"
            v-model="paramForm[param.name]"
          />

          <el-input-number
            v-else-if="normalizeParamType(param.type) === 'integer'"
            v-model="paramForm[param.name]"
            :placeholder="param.description || param.name"
            controls-position="right"
            class="external-tool-number"
          />

          <el-input
            v-else
            v-model="paramForm[param.name]"
            :placeholder="param.description || param.name"
            clearable
          />

          <div v-if="param.description" class="external-tool-param-help">
            {{ param.description }}
          </div>
        </el-form-item>

        <div v-if="!pendingParams.length" class="external-tool-empty small">
          This tool has no runtime params.
        </div>
      </el-form>
    </div>

    <template #footer>
      <el-button size="small" @click="startDialogVisible = false">Cancel</el-button>
      <el-button size="small" type="primary" :loading="submitting" @click="confirmStart">
        Run
      </el-button>
    </template>
  </el-dialog>

  <el-dialog
    v-model="logDialogVisible"
    :title="logDialogTitle"
    width="940px"
    append-to-body
  >
    <div v-if="logFilePath" class="external-tool-log-path mono" :title="logFilePath">
      Log file: {{ logFilePath }}
    </div>
    <pre ref="logContentRef" class="external-tool-log-content">{{ logContent || 'No log content.' }}</pre>
    <template #footer>
      <el-button size="small" :loading="logLoading" @click="refreshCurrentLogs">Refresh Logs</el-button>
      <el-button size="small" @click="logDialogVisible = false">Close</el-button>
    </template>
  </el-dialog>

  <el-dialog
    v-model="detailDialogVisible"
    :title="detailDialogTitle"
    width="780px"
    top="6vh"
    append-to-body
    modal-class="external-tool-info-overlay"
    class="external-tool-detail-dialog external-tool-info-dialog"
  >
    <div class="external-tool-detail-body">
      <div v-if="detailSubtitle" class="external-tool-detail-subtitle">
        {{ detailSubtitle }}
      </div>

      <div
        v-for="section in detailSections"
        :key="section.title"
        class="external-tool-detail-section"
      >
        <div class="external-tool-detail-section-title">
          {{ section.title }}
        </div>

        <div class="external-tool-detail-grid">
          <div
            v-for="row in section.rows"
            :key="`${section.title}:${row.label}`"
            class="external-tool-detail-row"
          >
            <div class="external-tool-detail-label">
              {{ row.label }}
            </div>
            <div
              class="external-tool-detail-value"
              :class="{ mono: row.mono, multiline: row.multiline }"
              :title="row.multiline ? '' : stringifyDetailValue(row.value)"
            >
              <pre v-if="row.multiline" class="external-tool-detail-pre">{{ formatDetailValue(row.value) }}</pre>
              <span v-else>{{ formatDetailValue(row.value) }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <template #footer>
      <el-button
        v-if="detailCopyText"
        size="small"
        plain
        @click="copyDetailText"
      >
        Copy Command
      </el-button>
      <el-button size="small" @click="detailDialogVisible = false">Close</el-button>
    </template>
  </el-dialog>
</template>

<script>
import { ElMessage, ElMessageBox } from 'element-plus'

export default {
  name: 'ExternalToolManagerDialog',

  props: {
    selectedId: {
      type: [String, Number],
      default: '',
    },
    currentConnection: {
      type: Object,
      default: null,
    },
    connections: {
      type: Array,
      default: () => [],
    },
    getTabScopedHeaders: {
      type: Function,
      default: null,
    },
  },

  emits: [
    'append-output',
    'set-active-task',
    'open-tool-meta-editor',
  ],

  data() {
    return {
      visible: false,
      loading: false,
      submitting: false,
      logLoading: false,
      installLoading: false,
      activeTab: 'modules',
      items: [],
      serverInstances: {},
      clientInstances: {},
      installStatuses: {},
      searchText: '',
      deviceFilter: '',
      packageOnlyCompatible: true,
      selectedPackageId: '',
      startDialogVisible: false,
      pendingToolId: '',
      pendingTargetSide: '',
      pendingStartMode: 'run',
      paramForm: {},
      logDialogVisible: false,
      logDialogTitle: 'External Tool Logs',
      logFilePath: '',
      logContent: '',
      currentLogRow: null,
      detailDialogVisible: false,
      detailDialogTitle: '',
      detailSubtitle: '',
      detailSections: [],
      detailCopyText: '',
      serverPlatform: '',
      serverArch: '',
    }
  },

  computed: {
    currentClientPlatform() {
      return this.normalizePlatform(
        this.currentConnection?.os_alias ||
        this.currentConnection?.os_type ||
        this.currentConnection?.platform ||
        this.currentConnection?.system ||
        '',
      )
    },

    currentClientArch() {
      return this.normalizeArch(
        this.currentConnection?.arch ||
        this.currentConnection?.cpu_arch ||
        this.currentConnection?.architecture ||
        this.currentConnection?.machine_arch ||
        '',
      )
    },

    allModules() {
      const modules = []
      for (const pkg of this.items || []) {
        for (const module of this.getPackageModules(pkg)) {
          modules.push(module)
        }
      }
      return modules
    },

    currentDeviceId() {
      return this.normalizeDeviceId(this.selectedId || this.currentConnection?.client_id || '')
    },

    currentMachineId() {
      return this.normalizeMachineId(this.currentConnection?.machine_id || '')
    },

    deviceFilterOptions() {
      const options = [
        { value: '__server__', label: 'Server host' },
      ]
      const seen = new Set(options.map(item => item.value))
      for (const conn of this.connections || []) {
        const machineId = this.normalizeMachineId(conn?.machine_id)
        if (!machineId || seen.has(machineId)) continue
        seen.add(machineId)
        options.push({ value: machineId, label: this.formatMachineOptionLabel(conn) })
      }
      if (this.currentMachineId && !seen.has(this.currentMachineId)) {
        seen.add(this.currentMachineId)
        options.push({ value: this.currentMachineId, label: this.formatCurrentMachineLabel() })
      }
      return options
    },

    activeDeviceFilterLabel() {
      const value = this.normalizeDeviceId(this.deviceFilter)
      const option = this.deviceFilterOptions.find(item => item.value === value)
      if (option) return option.label
      if (!value) return 'current target'
      return this.shortenMachineId(value)
    },

    serverModules() {
      return (this.allModules || []).filter(item => this.supportsSide(item, 'server'))
    },

    clientModules() {
      return (this.allModules || []).filter(item => this.supportsSide(item, 'client'))
    },

    isServerTargetSelected() {
      return this.normalizeDeviceId(this.deviceFilter || this.defaultTargetValue()) === '__server__'
    },

    selectedTargetMachineId() {
      return this.normalizeMachineId(this.deviceFilter || this.defaultTargetValue())
    },

    selectedTargetSide() {
      if (this.isServerTargetSelected) return 'server'
      return 'client'
    },

    selectedTargetClientId() {
      if (this.selectedTargetSide !== 'client') return ''
      return this.getClientDeviceIdForMachine(this.selectedTargetMachineId)
    },

    selectedTargetPlatform() {
      if (this.selectedTargetSide !== 'client') return this.serverPlatform
      return this.getPlatformForMachineId(this.selectedTargetMachineId)
    },

    selectedTargetArch() {
      if (this.selectedTargetSide !== 'client') return this.serverArch
      return this.getArchForMachineId(this.selectedTargetMachineId)
    },

    filteredModules() {
      const keyword = String(this.searchText || '').trim().toLowerCase()

      return (this.items || []).filter((item) => {
        if (this.packageOnlyCompatible && !this.isPackageAvailableForTarget(item)) return false
        if (!keyword) return true
        return this.moduleSearchText(item).includes(keyword)
      })
    },

    selectedPackage() {
      const list = this.filteredModules || []
      if (!list.length) return null
      const selectedId = String(this.selectedPackageId || '').trim()
      return list.find(item => item.id === selectedId) || list[0]
    },

    allInstances() {
      const rows = []
      for (const item of this.serverModules) {
        const list = this.serverInstances[item.id] || []
        for (const instance of list) rows.push(this.normalizeInstanceRow(item, instance, 'server', '__server__'))
      }
      for (const item of this.clientModules) {
        const byDevice = this.clientInstances || {}
        for (const [deviceId, toolMap] of Object.entries(byDevice)) {
          const list = toolMap?.[item.id] || []
          for (const instance of list) rows.push(this.normalizeInstanceRow(item, instance, 'client', deviceId))
        }
      }
      return rows.sort((a, b) => {
        if (a.running !== b.running) return a.running ? -1 : 1
        return String(b.started_at || '').localeCompare(String(a.started_at || ''))
      })
    },

    filteredInstances() {
      const keyword = String(this.searchText || '').trim().toLowerCase()
      const machine = this.normalizeMachineId(this.deviceFilter || this.defaultTargetValue())
      return this.allInstances.filter((row) => {
        if (machine === '__server__') {
          if (row.side !== 'server') return false
        } else if (machine && row.machine_id !== machine) {
          return false
        }
        if (!keyword) return true
        const values = [
          row.side,
          row.status,
          row.machine_id,
          row.machine_label,
          row.hostname,
          row.connection_id,
          row.tool_id,
          row.display_name,
          row.instance_id,
          row.pid,
          row.exec_path,
          row.config_path,
          row.stdout,
          row.pid_file,
          this.formatPortInfo(row),
        ].map(value => String(value || '').toLowerCase())
        return values.some(value => value.includes(keyword))
      })
    },

    pendingItem() {
      const target = String(this.pendingToolId || '').trim()
      return (this.allModules || []).find(item => String(item.id || '').trim() === target) || null
    },

    pendingParams() {
      return Array.isArray(this.pendingItem?.params) ? this.pendingItem.params : []
    },

    startDialogTitle() {
      const item = this.pendingItem
      const name = item ? (item.display_name || item.id) : 'External Tool'
      const side = this.pendingTargetSide === 'server' ? 'Server' : 'This Client'
      const action = 'Run'
      return `${action} ${name} on ${side}`
    },
  },

  watch: {
    async selectedId() {
      if (!this.visible) return
      this.deviceFilter = this.defaultTargetValue()
      await this.refreshInstallStatuses(false)
      await this.refreshInstances(false)
    },
  },

  methods: {
    async open() {
      this.deviceFilter = this.defaultTargetValue()
      this.visible = true
      await this.refreshAll()
    },

    isOpen() {
      return this.visible
    },

    async refreshIfOpen() {
      if (!this.visible) return
      await this.refreshAll()
    },

    handleClosed() {
      this.resetStartDialog()
      this.currentLogRow = null
      this.logFilePath = ''
    },

    buildJsonHeaders(extra = {}) {
      if (typeof this.getTabScopedHeaders === 'function') {
        return this.getTabScopedHeaders(extra)
      }
      return extra
    },

    logExternalToolTarget(action, item = null, extra = {}) {
      const selectedMachineId = this.selectedTargetMachineId
      const selectedClientId = this.selectedTargetSide === 'client'
        ? this.getClientDeviceIdForMachine(selectedMachineId)
        : '__server__'

      const payload = {
        action,
        package_id: item?.package_meta?.id || item?.package_id || item?.id || '',
        selected_side: this.selectedTargetSide,
        selected_machine_id: selectedMachineId,
        selected_client_id: selectedClientId,
        current_device_id: this.currentDeviceId,
        current_machine_id: this.currentMachineId,
        selected_target_platform: this.selectedTargetPlatform,
        selected_target_arch: this.selectedTargetArch,
        current_client_platform: this.currentClientPlatform,
        current_client_arch: this.currentClientArch,
        server_platform: this.serverPlatform,
        server_arch: this.serverArch,
        ...extra,
      }

      console.info('[external-tools] target', payload)
      return payload
    },

    selectPackage(item) {
      if (!item?.id) return
      this.selectedPackageId = item.id
    },

    async refreshAll() {
      this.loading = true
      try {
        await this.loadCatalog(false)
        await this.refreshInstallStatuses(false)
        await this.refreshInstances(false)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to refresh external tools')
      } finally {
        this.loading = false
      }
    },

    async loadCatalog(showError = true) {
      try {
        const res = await fetch('/api/external-tools/catalog')
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load external tools')
        const catalog = json.data || {}
        this.serverPlatform = this.normalizePlatform(catalog.server_platform || '')
        this.serverArch = this.normalizeArch(catalog.server_arch || '')
        this.items = Array.isArray(catalog.items) ? catalog.items : []
        if (!this.selectedPackageId && this.items.length) this.selectedPackageId = this.items[0].id || ''
        this.applyCatalogInstallStatuses(this.items, '__server__')
      } catch (e) {
        if (showError) ElMessage.error(e.message || 'Failed to load external tools')
        throw e
      }
    },

    applyCatalogInstallStatuses(items, clientDeviceId = '') {
      for (const item of items || []) {
        const status = item?.install_status
        if (!status) continue
        const side = status.side || this.getItemSides(item)[0] || ''
        const deviceId = side === 'server' ? '__server__' : this.normalizeDeviceId(clientDeviceId)
        if (side === 'client' && !deviceId) {
          this.logExternalToolTarget('apply-catalog-status-skip', item, {
            reason: 'client install_status returned without explicit client_id',
          })
          continue
        }
        this.setInstallStatus(item, side, deviceId, { ...status, loading: false, error: status.error || '' })
      }
    },

    async loadClientCatalogStatuses(deviceId = '', showError = true) {
      const targetDeviceId = this.normalizeDeviceId(deviceId)
      if (!targetDeviceId || targetDeviceId === '__server__' || targetDeviceId === '__all__') return []

      const targetPlatform = this.getPlatformForConnectionId(targetDeviceId)
      const targetArch = this.getArchForConnectionId(targetDeviceId)
      this.logExternalToolTarget('client-catalog-request', null, {
        request_client_id: targetDeviceId,
        request_platform: targetPlatform,
        request_arch: targetArch,
      })
      if (!targetPlatform || !targetArch) {
        const message = `Unable to resolve target platform/arch for client ${targetDeviceId}`
        if (showError) ElMessage.error(message)
        throw new Error(message)
      }

      const targetItems = (this.items || []).filter(item => this.doesPackageBuildMatch(item, targetPlatform, targetArch))
      for (const item of targetItems) {
        const previous = this.installStatuses[this.installStatusKey(item, 'client', targetDeviceId)] || {}
        this.setInstallStatus(item, 'client', targetDeviceId, {
          ...previous,
          loading: true,
          error: '',
        })
      }

      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(targetDeviceId)}/external-tools/catalog`, {
          method: 'POST',
          headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({
            platform: targetPlatform,
            arch: targetArch,
          }),
        })
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load client install statuses')
        const catalog = json.data || {}
        const items = Array.isArray(catalog.items) ? catalog.items : []
        const seen = new Set()
        for (const item of items) {
          const status = item?.install_status
          const packageId = String(item?.id || status?.package_id || status?.tool_id || '').trim()
          if (!packageId) continue
          seen.add(packageId)
          if (status) {
            this.setInstallStatus(item, 'client', targetDeviceId, {
              ...status,
              side: 'client',
              loading: false,
              error: status.error || '',
            })
          }
        }
        for (const item of targetItems) {
          if (seen.has(String(item?.id || '').trim())) continue
          this.setInstallStatus(item, 'client', targetDeviceId, {
            tool_id: item.id,
            package_id: item.id,
            side: 'client',
            installed: false,
            loading: false,
            error: 'client status not returned',
            message: 'client status not returned',
          })
        }
        return Array.isArray(catalog.client_install_statuses) ? catalog.client_install_statuses : []
      } catch (e) {
        for (const item of targetItems) {
          this.setInstallStatus(item, 'client', targetDeviceId, {
            tool_id: item.id,
            package_id: item.id,
            side: 'client',
            installed: false,
            loading: false,
            error: e.message || 'Failed to load client install statuses',
            message: e.message || 'Failed to load client install statuses',
          })
        }
        if (showError) ElMessage.error(e.message || 'Failed to load client install statuses')
        return []
      }
    },

    getPackageById(packageId) {
      const id = String(packageId || '').trim()
      if (!id) return null
      return (this.items || []).find(item => String(item?.id || '').trim() === id) || null
    },

    normalizeModuleFromPackage(pkg, module) {
      if (!pkg || !module) return null
      const moduleId = String(module.id || module.module_id || '').trim()
      const toolId = String(module.tool_id || (moduleId ? `${pkg.id}.${moduleId}` : '')).trim()
      if (!toolId) return null
      return {
        ...module,
        id: toolId,
        tool_id: toolId,
        module_id: moduleId || toolId,
        package_id: pkg.id,
        package_meta: pkg,
        package: pkg.package || {},
        package_install: pkg.install || {},
        package_execs: pkg.execs || {},
        package_platforms: pkg.platforms || [],
        package_archs: pkg.archs || [],
        version: module.version || pkg.version || '',
        sides: ['server', 'client'],
        platforms: pkg.platforms || module.platforms || [],
        archs: pkg.archs || module.archs || [],
      }
    },

    getPackageModules(pkg) {
      const result = []
      for (const module of pkg?.modules || []) {
        const normalized = this.normalizeModuleFromPackage(pkg, module)
        if (normalized) result.push(normalized)
      }
      return result
    },

    formatPackageModules(pkg) {
      return this.getPackageModules(pkg).map(module => module.display_name || module.module_id || module.id).join(', ')
    },

    getPackageForModule(module) {
      return module?.package_meta || this.getPackageById(module?.package_id || '') || module
    },

    canRunModuleAction(module) {
      const pkg = this.getPackageForModule(module)
      if (!this.isPackageAvailableForTarget(pkg)) return false
      const side = this.getSelectedTargetSideForAction()
      const deviceId = side === 'server' ? '__server__' : this.getActionDeviceId(pkg)
      const status = this.installStatuses[this.installStatusKey(pkg, side, deviceId)]
      return !!status?.installed
    },

    getItemSides(item) {
      const raw = item?.sides !== undefined ? item.sides : item?.side
      const source = Array.isArray(raw) ? raw : [raw]
      const sides = []
      const seen = new Set()
      for (const value of source) {
        const side = String(value || '').trim().toLowerCase()
        if (!['server', 'client'].includes(side) || seen.has(side)) continue
        seen.add(side)
        sides.push(side)
      }
      return sides.length ? sides : ['client']
    },

    supportsSide(item, side) {
      const normalized = String(side || '').trim().toLowerCase()
      return !!item && ['server', 'client'].includes(normalized)
    },

    getActionSideForItem(item) {
      const side = this.getSelectedTargetSideForAction()
      return this.supportsSide(item, side) ? side : this.getItemSides(item)[0]
    },

    installStatusKey(itemOrToolId, side = '', deviceId = '') {
      const toolId = typeof itemOrToolId === 'object'
        ? (itemOrToolId?.package_meta?.id || itemOrToolId?.package_id || itemOrToolId?.id)
        : itemOrToolId
      const normalizedSide = side || (typeof itemOrToolId === 'object' ? this.getItemSides(itemOrToolId)[0] : '')
      const normalizedDeviceId = normalizedSide === 'server' ? '__server__' : this.normalizeDeviceId(deviceId)
      return `${normalizedSide}:${normalizedDeviceId}:${toolId || ''}`
    },

    getModuleTargetTagLabel(item) {
      const sides = this.getItemSides(item)
      if (sides.includes('server') && sides.includes('client')) return 'Server / Client'
      return sides.includes('server') ? 'Server' : 'Client'
    },

    getModuleTargetTagType(item) {
      const sides = this.getItemSides(item)
      if (sides.includes('server') && sides.includes('client')) return 'info'
      if (sides.includes('server')) return 'success'
      return 'warning'
    },

    getInstallStatusTargetLabel() {
      return this.getSelectedTargetSideForAction() === 'server' ? 'Server' : 'This Client'
    },

    getModuleInstallDeviceId(item) {
      return this.getSelectedTargetSideForAction() === 'server' ? '__server__' : this.getActionDeviceId(item)
    },

    getModuleInstallStatus(item) {
      if (!this.isPackageAvailableForTarget(item)) {
        return { label: 'Unavailable for target', type: 'info' }
      }
      const side = this.getSelectedTargetSideForAction()
      const targetLabel = this.getInstallStatusTargetLabel(item)
      const deviceId = this.getModuleInstallDeviceId(item)
      if (side === 'client' && !deviceId) return { label: 'Install: no client', type: 'info' }
      const status = this.installStatuses[this.installStatusKey(item, side, deviceId)]
      if (!status) return { label: `Status unknown on ${targetLabel}`, type: 'info' }
      if (status.loading) return { label: 'Checking...', type: 'info' }
      if (status.error) return { label: `Status unknown on ${targetLabel}`, type: 'info' }
      return status.installed
        ? { label: `Installed on ${targetLabel}`, type: 'success' }
        : { label: `Not installed on ${targetLabel}`, type: 'warning' }
    },

    setInstallStatus(itemOrToolId, side, deviceId, status) {
      const key = this.installStatusKey(itemOrToolId, side, deviceId)
      this.installStatuses = {
        ...this.installStatuses,
        [key]: { ...(status || {}) },
      }
    },

    async refreshInstallStatuses(showToast = false) {
      const side = this.getSelectedTargetSideForAction()
      if (side === 'server') {
        for (const item of this.items || []) {
          if (!this.isPackageAvailableForTarget(item)) continue
          await this.fetchInstallStatus(item, 'server', '__server__', { silent: true, force: true })
        }
      } else {
        const deviceId = this.selectedTargetClientId
        if (!deviceId) {
          this.logExternalToolTarget('refresh-install-statuses-skip', null, {
            reason: 'no selectedTargetClientId',
          })
          if (showToast) ElMessage.warning('Please select an online client')
          return
        }
        await this.loadClientCatalogStatuses(deviceId, showToast)
      }
      if (showToast) ElMessage.success('Install statuses refreshed')
    },

    isPackageAvailableForTarget(item) {
      if (!item) return false
      const pkg = item?.package_meta || item
      const side = this.getSelectedTargetSideForAction()
      if (side === 'server') return this.isServerPlatformSupported(pkg)
      const deviceId = this.getActionDeviceId(pkg)
      const platform = this.selectedTargetPlatform
      const arch = this.selectedTargetArch
      return !!deviceId &&
        this.selectedTargetSide === 'client' &&
        !!platform &&
        !!arch &&
        this.doesPackageBuildMatch(pkg, platform, arch)
    },

    getPackageCurrentInstallStatus(item) {
      if (!item) return null
      const side = this.getSelectedTargetSideForAction()
      const deviceId = this.getModuleInstallDeviceId(item)
      return this.installStatuses[this.installStatusKey(item, side, deviceId)] || null
    },

    canUsePackageAction(item) {
      return this.isPackageAvailableForTarget(item)
    },

    canInstallPackageAction(item) {
      if (!this.canUsePackageAction(item)) return false
      if (this.installLoading) return false
      const status = this.getPackageCurrentInstallStatus(item)
      if (status?.loading) return false
      return !status || status.installed !== true
    },

    async fetchInstallStatus(item, side = item?.side, deviceId = '', options = {}) {
      if (!item?.id) return null
      const targetSide = side || item.side
      const targetDeviceId = targetSide === 'server' ? '__server__' : this.normalizeDeviceId(deviceId)
      if (targetSide === 'client' && !targetDeviceId) {
        this.logExternalToolTarget('fetch-install-status-skip', item, {
          reason: 'missing targetDeviceId',
          requested_device_id: deviceId,
        })
        return null
      }
      const statusKey = this.installStatusKey(item, targetSide, targetDeviceId)
      const cachedStatus = this.installStatuses[statusKey]
      if (cachedStatus && !cachedStatus.loading && !cachedStatus.error && !options.force) return cachedStatus

      if (targetSide === 'client') {
        await this.loadClientCatalogStatuses(targetDeviceId, !options.silent)
        const refreshed = this.installStatuses[statusKey]
        if (refreshed) return refreshed
        return null
      }

      const previousStatus = this.installStatuses[statusKey] || {}
      this.setInstallStatus(item, targetSide, targetDeviceId, { ...previousStatus, loading: true, error: '' })
      try {
        const res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/install-status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ params: {} }),
        })
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to read install status')
        const data = json.data || {}
        this.setInstallStatus(item, targetSide, targetDeviceId, { ...data, loading: false, error: data.error || '' })
        return data
      } catch (e) {
        this.setInstallStatus(item, targetSide, targetDeviceId, {
          ...previousStatus,
          loading: false,
          error: e.message || 'Failed to read install status',
        })
        if (!options.silent) ElMessage.error(e.message || 'Failed to read install status')
        return null
      }
    },


    async refreshInstances(showToast = true) {
      const device = this.normalizeMachineId(this.deviceFilter || this.defaultTargetValue())

      if (device === '__server__' || !device) {
        await this.loadAllServerInstances(false)
      } else {
        const deviceId = this.getClientDeviceIdForMachine(device)
        if (!deviceId) {
          this.logExternalToolTarget('refresh-instances-skip', null, {
            reason: 'selected machine has no matching online client_id',
            selected_machine_id: device,
          })
          if (showToast) ElMessage.warning('Please select an online client')
          return
        }
        await this.loadAllClientInstances(deviceId, false)
      }

      if (showToast) ElMessage.success('Instances refreshed')
    },


    groupInstancesByTool(items = []) {
  const grouped = {}
  for (const row of items || []) {
    const toolId = String(row?.tool_id || '').trim()
    if (!toolId) continue
    if (!grouped[toolId]) grouped[toolId] = []
    grouped[toolId].push(row)
  }
  return grouped
},

normalizeInstanceByToolPayload(data = {}, modules = []) {
  if (data.by_tool && typeof data.by_tool === 'object') {
    const normalized = {}
    for (const item of modules || []) {
      if (item?.id) normalized[item.id] = []
    }
    for (const [toolId, rows] of Object.entries(data.by_tool || {})) {
      normalized[toolId] = Array.isArray(rows) ? rows : []
    }
    return normalized
  }

  const grouped = this.groupInstancesByTool(Array.isArray(data.items) ? data.items : [])
  for (const item of modules || []) {
    if (item?.id && !grouped[item.id]) grouped[item.id] = []
  }
  return grouped
},

async loadAllServerInstances(showToast = true) {
  try {
    const res = await fetch('/api/external-tools/server/instances')
    const json = await res.json()
    if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load server instances')

    const data = json.data || {}
    const nextServerInstances = this.normalizeInstanceByToolPayload(data, this.serverModules)

    this.serverInstances = {
      ...this.serverInstances,
      ...nextServerInstances,
    }

    if (showToast) ElMessage.success('Server instances refreshed')
  } catch (e) {
    if (showToast) ElMessage.error(e.message || 'Failed to load server instances')
    throw e
  }
},

async loadAllClientInstances(deviceId = '', showToast = true) {
  const targetDeviceId = this.normalizeDeviceId(deviceId)
  if (!targetDeviceId || targetDeviceId === '__server__' || targetDeviceId === '__all__') return

  try {
    const res = await fetch(`/api/connections/${encodeURIComponent(targetDeviceId)}/external-tools/instances`, {
      method: 'POST',
      headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({}),
    })
    const json = await res.json()
    if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load client instances')

    const data = json.data || {}
    const nextToolMap = this.normalizeInstanceByToolPayload(data, this.clientModules)

    this.clientInstances = {
      ...this.clientInstances,
      [targetDeviceId]: nextToolMap,
    }

    if (showToast) ElMessage.success('Client instances refreshed')
  } catch (e) {
    if (showToast) ElMessage.error(e.message || 'Failed to load client instances')
    throw e
  }
},

    // async refreshInstances(showToast = true) {
    //   const device = this.normalizeMachineId(this.deviceFilter || this.defaultTargetValue())
    //
    //   if (device === '__server__' || !device) {
    //     await Promise.allSettled(this.serverModules.map(item => this.loadServerInstances(item.id, false)))
    //   } else {
    //     const clientDeviceIds = this.getClientDeviceIdsForFilter(device)
    //     for (const deviceId of clientDeviceIds) {
    //       for (const item of this.clientModules) {
    //         await this.loadClientInstances(item.id, deviceId, false)
    //       }
    //     }
    //   }
    //
    //   if (showToast) ElMessage.success('Instances refreshed')
    // },

    async loadServerInstances(toolId, showToast = true) {
      if (!toolId) return
      try {
        const res = await fetch(`/api/external-tools/${encodeURIComponent(toolId)}/server/instances`)
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load server instances')
        const data = json.data || {}
        this.serverInstances = {
          ...this.serverInstances,
          [toolId]: Array.isArray(data.items) ? data.items : [],
        }
        if (showToast) ElMessage.success('Server instances refreshed')
      } catch (e) {
        if (showToast) ElMessage.error(e.message || 'Failed to load server instances')
      }
    },

    async loadClientInstances(toolId, deviceId = '', showToast = true) {
      const targetDeviceId = this.normalizeDeviceId(deviceId)
      if (!toolId || !targetDeviceId || targetDeviceId === '__server__' || targetDeviceId === '__all__') return
      try {
        const res = await fetch(`/api/connections/${encodeURIComponent(targetDeviceId)}/external-tools/${encodeURIComponent(toolId)}/instances`, {
          method: 'POST',
          headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({}),
        })
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load client instances')
        const data = json.data || {}
        this.clientInstances = {
          ...this.clientInstances,
          [targetDeviceId]: {
            ...(this.clientInstances[targetDeviceId] || {}),
            [toolId]: Array.isArray(data.items) ? data.items : [],
          },
        }
        if (showToast) ElMessage.success('Client instances refreshed')
      } catch (e) {
        if (showToast) ElMessage.error(e.message || 'Failed to load client instances')
      }
    },

    defaultTargetValue() {
      return this.currentMachineId || '__server__'
    },

    getClientDeviceIdForMachine(machineId) {
      const id = this.normalizeMachineId(machineId)
      if (!id || id === '__server__' || id === '__all__') return ''
      const conn = this.findConnectionByMachineId(id)
      if (conn?.client_id) return this.normalizeDeviceId(conn.client_id)
      if (id === this.currentMachineId && this.currentDeviceId) return this.currentDeviceId
      const byConnectionId = this.findConnectionById(id)
      if (byConnectionId?.client_id) return this.normalizeDeviceId(byConnectionId.client_id)
      return ''
    },

    getPlatformForMachineId(machineId) {
      const id = this.normalizeMachineId(machineId)
      if (!id || id === '__server__' || id === '__all__') return ''
      const conn = this.findConnectionByMachineId(id) || (id === this.currentMachineId ? this.currentConnection : null)
      return this.normalizePlatform(
        conn?.os_alias || conn?.os_type || conn?.platform || conn?.system || '',
      )
    },

    getPlatformForConnectionId(deviceId) {
      const conn = this.findConnectionById(deviceId) || (this.normalizeDeviceId(deviceId) === this.currentDeviceId ? this.currentConnection : null)
      return this.normalizePlatform(conn?.os_alias || conn?.os_type || conn?.platform || conn?.system || '')
    },

    getArchForMachineId(machineId) {
      const id = this.normalizeMachineId(machineId)
      if (!id || id === '__server__' || id === '__all__') return ''
      const conn = this.findConnectionByMachineId(id) || (id === this.currentMachineId ? this.currentConnection : null)
      return this.normalizeArch(conn?.arch || conn?.cpu_arch || conn?.architecture || conn?.machine_arch || '')
    },

    getArchForConnectionId(deviceId) {
      const conn = this.findConnectionById(deviceId) || (this.normalizeDeviceId(deviceId) === this.currentDeviceId ? this.currentConnection : null)
      return this.normalizeArch(conn?.arch || conn?.cpu_arch || conn?.architecture || conn?.machine_arch || '')
    },

    getActionDeviceId(item) {
      if (!item || !this.supportsSide(item, 'client')) return ''

      const machineId = this.selectedTargetMachineId
      if (!machineId || machineId === '__server__' || machineId === '__all__') return ''

      const deviceId = this.getClientDeviceIdForMachine(machineId)
      if (!deviceId) {
        this.logExternalToolTarget('resolve-client-id-missing', item, {
          reason: 'selected machine has no matching online client_id',
        })
      }

      return deviceId
    },

    normalizeDeviceId(value) {
      return String(value || '').trim()
    },

    normalizeMachineId(value) {
      return String(value || '').trim()
    },

    shortenDeviceId(deviceId) {
      const value = this.normalizeDeviceId(deviceId)
      if (!value) return '-'
      if (value === '__server__') return 'server'
      if (value === '__all__') return 'all'
      return value.length > 12 ? value.slice(0, 12) : value
    },

    shortenMachineId(machineId) {
      const value = this.normalizeMachineId(machineId)
      if (!value) return '-'
      if (value === '__server__') return 'server'
      if (value === '__all__') return 'all'
      return value.length > 12 ? value.slice(0, 12) : value
    },

    findConnectionById(deviceId) {
      const id = this.normalizeDeviceId(deviceId)
      return (this.connections || []).find(conn => this.normalizeDeviceId(conn?.client_id) === id) || null
    },

    findConnectionByMachineId(machineId) {
      const id = this.normalizeMachineId(machineId)
      return (this.connections || []).find(conn => this.normalizeMachineId(conn?.machine_id) === id) || null
    },

    getMachineIdForConnectionId(deviceId) {
      if (deviceId === '__server__') return '__server__'
      const conn = this.findConnectionById(deviceId)
      return this.normalizeMachineId(conn?.machine_id || (deviceId === this.currentDeviceId ? this.currentConnection?.machine_id : '') || deviceId)
    },

    getHostnameForConnectionId(deviceId) {
      const conn = this.findConnectionById(deviceId) || (deviceId === this.currentDeviceId ? this.currentConnection : null)
      return String(conn?.hostname || '').trim()
    },

    formatMachineOptionLabel(conn) {
      const machineId = this.normalizeMachineId(conn?.machine_id)
      const shortId = this.shortenMachineId(machineId)
      const hostname = String(conn?.hostname || '').trim()
      return hostname ? `${shortId} (${hostname})` : shortId
    },

    formatCurrentMachineLabel() {
      const conn = this.currentConnection || this.findConnectionById(this.currentDeviceId)
      if (conn?.machine_id) return this.formatMachineOptionLabel(conn)
      return this.shortenMachineId(this.currentMachineId)
    },

    getMachineLabel(machineId, side = '', connectionId = '') {
      const id = this.normalizeMachineId(machineId)
      if (side === 'server' || id === '__server__') return 'Server host'
      const conn = this.findConnectionByMachineId(id) || this.findConnectionById(connectionId)
      if (conn?.machine_id) return this.formatMachineOptionLabel(conn)
      if (id === this.currentMachineId && this.currentConnection) return this.formatMachineOptionLabel(this.currentConnection)
      return this.shortenMachineId(id)
    },

    getClientDeviceIdsForFilter(filterValue) {
      const value = this.normalizeMachineId(filterValue)
      if (!value || value === '__server__') return []
      if (value === '__all__') {
        const ids = []
        const seen = new Set()
        for (const conn of this.connections || []) {
          const id = this.normalizeDeviceId(conn?.client_id)
          if (!id || seen.has(id)) continue
          seen.add(id)
          ids.push(id)
        }
        return ids
      }

      const ids = []
      const seen = new Set()
      for (const conn of this.connections || []) {
        const machineId = this.normalizeMachineId(conn?.machine_id)
        const clientId = this.normalizeDeviceId(conn?.client_id)
        if (!clientId || seen.has(clientId)) continue
        if (machineId === value || clientId === value) {
          seen.add(clientId)
          ids.push(clientId)
        }
      }
      if (!ids.length && value === this.currentMachineId && this.currentDeviceId) {
        ids.push(this.currentDeviceId)
      }
      return ids
    },

    async handleTargetFilterChange() {
      await this.refreshInstallStatuses(false)
      await this.refreshInstances(false)
    },

    async handlePackageOnlyCompatibleChange() {
      await this.refreshInstallStatuses(false)
    },

    normalizePlatform(value) {
      const text = String(value || '').trim().toLowerCase()
      const aliases = {
        windows: 'win',
        win32: 'win',
        darwin: 'mac',
        macos: 'mac',
        osx: 'mac',
        linux: 'linux',
        ios: 'ios',
        common: '*',
        all: '*',
        '*': '*',
      }
      return aliases[text] || text
    },

    normalizeArch(value) {
      const text = String(value || '').trim().toLowerCase().replace(/-/g, '_')
      const aliases = {
        x86_64: 'amd64',
        amd64: 'amd64',
        i386: '386',
        i686: '386',
        aarch64: 'arm64',
        arm64: 'arm64',
        all: '*',
        common: '*',
        '*': '*',
      }
      return aliases[text] || text
    },

    normalizeArchs(archs) {
      const source = Array.isArray(archs)
        ? archs
        : (typeof archs === 'string' && archs.trim() ? [archs] : [])
      const result = []
      const seen = new Set()
      source.forEach((arch) => {
        const normalized = this.normalizeArch(arch)
        if (!normalized || seen.has(normalized)) return
        seen.add(normalized)
        result.push(normalized)
      })
      return result.length ? result : ['*']
    },

    normalizePlatforms(platforms) {
      const source = Array.isArray(platforms)
        ? platforms
        : (typeof platforms === 'string' && platforms.trim() ? [platforms] : [])
      const result = []
      const seen = new Set()
      source.forEach((platform) => {
        const normalized = this.normalizePlatform(platform)
        if (!normalized || seen.has(normalized)) return
        seen.add(normalized)
        result.push(normalized)
      })
      return result.length ? result : ['*']
    },

    doesPlatformMatch(item, platform) {
      const target = this.normalizePlatform(platform)
      const platforms = this.normalizePlatforms(item?.platforms || item?.package_platforms || item?.platform)
      if (!target || !platforms.length) return false
      if (platforms.includes('*')) return true
      return platforms.includes(target)
    },

    doesArchMatch(item, arch) {
      const target = this.normalizeArch(arch)
      const archs = this.normalizeArchs(item?.archs || item?.package_archs || item?.arch)
      if (!target || !archs.length) return false
      if (archs.includes('*')) return true
      return archs.includes(target)
    },

    doesPackageBuildMatch(item, platform, arch) {
      const packages = item?.platform_packages || item?.package_meta?.platform_packages || null
      if (!packages || typeof packages !== 'object') return false
      const platformValue = this.normalizePlatform(platform)
      const archValue = this.normalizeArch(arch)
      if (!platformValue || !archValue) return false
      const exactKey = `${platformValue}-${archValue}`
      if (packages[exactKey]) return true
      return Object.values(packages).some((info) => {
        const itemPlatform = this.normalizePlatform(info?.platform || '')
        const itemArch = this.normalizeArch(info?.arch || '')
        const platformOk = itemPlatform === '*' || itemPlatform === platformValue
        const archOk = itemArch === '*' || itemArch === archValue
        return platformOk && archOk
      })
    },

    isServerPlatformSupported(item) {
      if (!item || !this.serverPlatform || !this.serverArch) return false
      return this.doesPackageBuildMatch(item, this.serverPlatform, this.serverArch)
    },

    isClientPlatformSupported(item) {
      return this.doesPackageBuildMatch(item, this.currentClientPlatform, this.currentClientArch)
    },

    formatPlatforms(platforms) {
      const normalized = this.normalizePlatforms(platforms)
      if (!normalized.length || normalized.includes('*')) return 'All platforms'
      return normalized.map((platform) => {
        if (platform === 'mac') return 'macOS'
        if (platform === 'win') return 'Windows'
        if (platform === 'linux') return 'Linux'
        if (platform === 'ios') return 'iOS'
        return platform
      }).join(', ')
    },

    moduleSearchText(item) {
      const moduleText = this.getPackageModules(item).map(module => [module.id, module.module_id, module.name, module.display_name, module.description].join(' ')).join(' ')
      const execText = Object.keys(item?.execs || {}).join(' ')
      return [
        item.id,
        item.name,
        item.display_name,
        item.description,
        item.package?.filename,
        item.package?.executable_rel_path,
        moduleText,
        execText,
        (item.tags || []).join(' '),
      ].map(value => String(value || '').toLowerCase()).join(' ')
    },

    normalizeParamType(type) {
      const value = String(type || 'string').trim().toLowerCase()
      if (value === 'int' || value === 'number') return 'integer'
      if (value === 'bool') return 'boolean'
      return value || 'string'
    },

    formatParamLabel(param) {
      const label = param.label || param.name
      const required = param.required ? ' *' : ''
      return `${label}${required}`
    },

    // buildParamDefaults(item) {
    //   const form = {}
    //   for (const param of item?.params || []) {
    //     const name = String(param?.name || '').trim()
    //     if (!name) continue
    //     if (name === 'instance_name' && (param.default === undefined || param.default === null || String(param.default).trim() === '')) {
    //       form[name] = this.defaultInstanceName(item)
    //     } else if (param.default !== undefined && param.default !== null) {
    //       form[name] = param.default
    //     } else if (this.normalizeParamType(param.type) === 'boolean') {
    //       form[name] = false
    //     } else {
    //       form[name] = ''
    //     }
    //   }
    //   return form
    // },

    buildParamDefaults(item) {
  const form = {}
  for (const param of item?.params || []) {
    const name = String(param?.name || '').trim()
    if (!name) continue

    if (name === 'instance_name' && (param.default === undefined || param.default === null || String(param.default).trim() === '')) {
      form[name] = this.defaultInstanceName(item)
    } else if (name === 'access_host' && (param.default === undefined || param.default === null || String(param.default).trim() === '')) {
      // 打开 config/start 弹框时直接把浏览器当前 hostname 填进 input。
      form[name] = this.getBrowserAccessHost()
    } else if (param.default !== undefined && param.default !== null) {
      form[name] = param.default
    } else if (this.normalizeParamType(param.type) === 'boolean') {
      form[name] = false
    } else {
      form[name] = ''
    }
  }
  return form
},


    defaultInstanceName(item) {
      if (item?.name === 'frps') return 'frps-7000'
      if (item?.name === 'frpc') return 'vite-8087'
      return 'default'
    },

    // buildStartParams() {
    //   const params = {}
    //   for (const param of this.pendingParams || []) {
    //     const name = String(param?.name || '').trim()
    //     if (!name) continue
    //     const value = this.paramForm[name]
    //     if (param.required && (value === '' || value === undefined || value === null)) {
    //       throw new Error(`Param ${name} is required`)
    //     }
    //     params[name] = value
    //   }
    //   return params
    // },

    buildStartParams() {
  const params = {}
  const hasAccessHostParam = (this.pendingParams || []).some(param => String(param?.name || '').trim() === 'access_host')

  for (const param of this.pendingParams || []) {
    const name = String(param?.name || '').trim()
    if (!name) continue

    let value = this.paramForm[name]

    // 如果用户刻意把 access_host 清空，提交前再补一次当前浏览器 hostname。
    if (name === 'access_host' && (value === '' || value === undefined || value === null)) {
      value = this.getBrowserAccessHost()
    }

    if (param.required && (value === '' || value === undefined || value === null)) {
      throw new Error(`Param ${name} is required`)
    }

    params[name] = value
  }

  // 兼容：meta 里 web.url 用了 {{access_host}}，但 params 没显式声明 access_host 时，
  // 仍然给 runtime state 里补一个，方便后续 Open Web。
  if (!hasAccessHostParam && this.pendingItem && this.getModuleWebUrlTemplate(this.pendingItem)) {
    params.access_host = this.getBrowserAccessHost()
  }

  return params
},

    deriveInstanceId(params) {
      const raw = params.instance_name || params.instance_id || (
        params.proxy_name && params.remote_port ? `${params.proxy_name}-${params.remote_port}` : ''
      ) || (params.bind_port ? `frps-${params.bind_port}` : 'default')
      return String(raw || 'default').trim().replace(/[^A-Za-z0-9_.-]+/g, '-').replace(/^[._-]+|[._-]+$/g, '') || 'default'
    },

    openStartDialog(item, side, mode = 'run') {
      this.pendingToolId = String(item?.id || '').trim()
      this.pendingTargetSide = side
      this.pendingStartMode = 'run'
      this.paramForm = this.buildParamDefaults(item)
      this.startDialogVisible = true
    },

    resetStartDialog() {
      this.startDialogVisible = false
      this.submitting = false
      this.pendingToolId = ''
      this.pendingTargetSide = ''
      this.pendingStartMode = 'run'
      this.paramForm = {}
    },

    downloadTool(item) {
      const id = String(item?.id || '').trim()
      if (!id) return
      const platform = this.selectedTargetPlatform
      const arch = this.selectedTargetArch

      this.logExternalToolTarget('download-package', item, {
        request_platform: platform,
        request_arch: arch,
      })

      if (!platform || !arch) {
        ElMessage.warning('Please select a valid target first')
        return
      }

      const params = new URLSearchParams()
      params.set('platform', platform)
      params.set('arch', arch)
      window.open(`/api/external-tools/${encodeURIComponent(id)}/download?${params.toString()}`, '_blank')
    },

    getSelectedTargetSideForAction() {
      return this.isServerTargetSelected ? 'server' : 'client'
    },

    getRunButtonLabel() {
      return this.isServerTargetSelected ? 'Run on Server' : 'Run on This Client'
    },

    getInstallMenuLabel(item = null) {
      const status = item ? this.getPackageCurrentInstallStatus(item) : null
      if (status?.installed) {
        return this.isServerTargetSelected ? 'Installed on Server' : 'Installed on This Client'
      }
      return this.isServerTargetSelected ? 'Install on Server' : 'Install on This Client'
    },


    getUninstallMenuLabel() {
      return this.isServerTargetSelected ? 'Uninstall from Server' : 'Uninstall from This Client'
    },

handlePackageMoreCommand(command, item) {
  if (command === 'download') return this.downloadTool(item)
  if (command === 'edit') return this.$emit('open-tool-meta-editor', item.id)
  if (!this.canUsePackageAction(item)) return null
  if (command === 'status') return this.showInstallStatus(item)
  if (command === 'copy') return this.copyInstallCommand(item)
  if (command === 'clear_cache') return this.clearPackageCache(item)
  if (command === 'uninstall') return this.uninstallPackage(item)
  return null
},

    getPackageTargetMachineId(item) {
  if (!item) return ''
  if (this.getSelectedTargetSideForAction() === 'server') return '__server__'
  return this.selectedTargetMachineId
},

getPackageTargetConnectionIds(item) {
  if (!item || this.getSelectedTargetSideForAction() !== 'client' || !this.supportsSide(item, 'client')) return []
  const machineId = this.getPackageTargetMachineId(item)
  const ids = this.getClientDeviceIdsForFilter(machineId)
  if (!ids.length) {
    this.logExternalToolTarget('package-target-connections-empty', item, {
      reason: 'selected machine has no matching client connections',
      selected_machine_id: machineId,
    })
  }
  return ids
},

getPackageTargetInstanceRows(item) {
  if (!item?.id) return []
  const packageId = String(item.id || '').trim()

  if (this.getSelectedTargetSideForAction() === 'server') {
    return this.allInstances.filter(row => row.side === 'server' && (row.package_id === packageId || String(row.tool_id || '').startsWith(`${packageId}.`)))
  }

  const machineId = this.getPackageTargetMachineId(item)
  return this.allInstances.filter(row => (
    row.side === 'client' &&
    (row.package_id === packageId || String(row.tool_id || '').startsWith(`${packageId}.`)) &&
    row.machine_id === machineId
  ))
},

hasRunningInstancesForPackage(item) {
  return this.getPackageTargetInstanceRows(item).some(row => row.running || String(row.status || '').toLowerCase() === 'running')
},

canUninstallPackageAction(item) {
  if (!this.canUsePackageAction(item)) return false

  const status = this.installStatuses[this.installStatusKey(
    item,
    this.getSelectedTargetSideForAction(),
    this.getModuleInstallDeviceId(item),
  )]

  if (status && status.installed === false) return false
  return !this.hasRunningInstancesForPackage(item)
},

async uninstallPackage(item) {
  if (!item?.id) return
  if (!this.canUsePackageAction(item)) {
    ElMessage.warning(this.getSelectedTargetSideForAction() === 'client' ? 'Please select a supported client first' : 'This package is not supported')
    return
  }

  // 卸载前刷新一次实例状态，避免 UI 旧数据导致误删。
  try {
    await this.refreshInstances(false)
  } catch (_) {
    // refresh 失败不直接中断，后端/client 仍会再做一次 running 校验。
  }

  if (this.hasRunningInstancesForPackage(item)) {
    ElMessage.warning('This package still has running instances on this machine. Stop them before uninstalling.')
    return
  }

  try {
    await ElMessageBox.confirm(
      `Uninstall ${item.display_name || item.id} from ${this.getSelectedTargetSideForAction() === 'server' ? 'server' : 'this machine'}?`,
      'Uninstall External Tool',
      {
        type: 'warning',
        confirmButtonText: 'Uninstall',
        cancelButtonText: 'Cancel',
      },
    )
  } catch (_) {
    return
  }

  try {
    this.installLoading = true
    let data
    if (this.getSelectedTargetSideForAction() === 'server') {
      data = await this.uninstallServerTool(item)
      this.setInstallStatus(item, 'server', '__server__', {
        ...(data || {}),
        installed: false,
        loading: false,
        error: '',
      })
    } else {
      const deviceIds = this.getPackageTargetConnectionIds(item)
      if (!deviceIds.length) throw new Error('Please select a device')
      // 实际卸载只对当前选中的连接发命令；同 machine 多连接时，后端命令仍落在该机器本地路径。
      const deviceId = this.normalizeDeviceId(deviceIds[0])
      this.logExternalToolTarget('uninstall-client-package', item, {
        request_client_id: deviceId,
        request_platform: this.getPlatformForConnectionId(deviceId),
        request_arch: this.getArchForConnectionId(deviceId),
      })
      data = await this.uninstallClientTool(item, deviceId)
      this.setInstallStatus(item, 'client', deviceId, {
        ...(data || {}),
        installed: false,
        loading: false,
        error: '',
      })
      await this.loadClientCatalogStatuses(deviceId, false)
    }

    ElMessage.success(data?.message || `Uninstalled: ${item.display_name || item.id}`)
  } catch (e) {
    ElMessage.error(e.message || 'Failed to uninstall package')
  } finally {
    this.installLoading = false
  }
},

async uninstallServerTool(item) {
  const res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/uninstall`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ params: {} }),
  })
  const json = await res.json()
  if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to uninstall server package')
  return json.data || {}
},

async uninstallClientTool(item, deviceId) {
  const targetDeviceId = this.normalizeDeviceId(deviceId)
  if (!targetDeviceId) throw new Error('Please select a device')

  const requestPlatform = this.getPlatformForConnectionId(targetDeviceId)
  const requestArch = this.getArchForConnectionId(targetDeviceId)
  this.logExternalToolTarget('uninstall-client-request', item, {
    request_client_id: targetDeviceId,
    request_platform: requestPlatform,
    request_arch: requestArch,
  })
  if (!requestPlatform || !requestArch) throw new Error(`Unable to resolve target platform/arch for client ${targetDeviceId}`)

  const res = await fetch(`/api/connections/${encodeURIComponent(targetDeviceId)}/external-tools/${encodeURIComponent(item.id)}/uninstall`, {
    method: 'POST',
    headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      params: {},
      platform: requestPlatform,
      arch: requestArch,
    }),
  })
  const json = await res.json()
  if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to uninstall client package')
  return json.data || {}
},

    async clearPackageCache(item) {
      if (!item?.id) return
      if (!this.canUsePackageAction(item)) {
        ElMessage.warning(this.getSelectedTargetSideForAction() === 'client' ? 'Please select a supported client first' : 'This package is not supported')
        return
      }

      try {
        await ElMessageBox.confirm(
          `Clear cached package archive for ${item.display_name || item.id} on ${this.getSelectedTargetSideForAction() === 'server' ? 'server' : 'this machine'}? Installed files will not be removed.`,
          'Clear Package Cache',
          {
            type: 'warning',
            confirmButtonText: 'Clear Cache',
            cancelButtonText: 'Cancel',
          },
        )
      } catch (_) {
        return
      }

      try {
        this.installLoading = true
        let data
        const side = this.getSelectedTargetSideForAction()
        const deviceId = side === 'server' ? '__server__' : this.getActionDeviceId(item)
        if (side === 'server') {
          data = await this.clearServerPackageCache(item)
        } else {
          if (!deviceId) throw new Error('Please select a device')
          data = await this.clearClientPackageCache(item, deviceId)
          await this.loadClientCatalogStatuses(deviceId, false)
        }
        ElMessage.success(data?.message || 'Package cache cleared')
      } catch (e) {
        ElMessage.error(e.message || 'Failed to clear package cache')
      } finally {
        this.installLoading = false
      }
    },

    async clearServerPackageCache(item) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/clear-cache`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ params: {} }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to clear server package cache')
      return json.data || {}
    },

    async clearClientPackageCache(item, deviceId) {
      const targetDeviceId = this.normalizeDeviceId(deviceId)
      if (!targetDeviceId) throw new Error('Please select a device')

      const requestPlatform = this.getPlatformForConnectionId(targetDeviceId)
      const requestArch = this.getArchForConnectionId(targetDeviceId)
      this.logExternalToolTarget('clear-client-cache-request', item, {
        request_client_id: targetDeviceId,
        request_platform: requestPlatform,
        request_arch: requestArch,
      })
      if (!requestPlatform || !requestArch) throw new Error(`Unable to resolve target platform/arch for client ${targetDeviceId}`)

      const res = await fetch(`/api/connections/${encodeURIComponent(targetDeviceId)}/external-tools/${encodeURIComponent(item.id)}/clear-cache`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          params: {},
          platform: requestPlatform,
          arch: requestArch,
        }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to clear client package cache')
      return json.data || {}
    },

    async installOnly(item) {
      if (!this.canUsePackageAction(item)) {
        ElMessage.warning(this.getSelectedTargetSideForAction() === 'client' ? 'Please select a supported client first' : 'This package is not supported')
        return
      }
      try {
        this.installLoading = true
        let res
        const side = this.getSelectedTargetSideForAction()
        const deviceId = side === 'server' ? '__server__' : this.getActionDeviceId(item)
        if (side === 'server') {
          res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/install`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ params: {} }),
          })
        } else {
          if (!deviceId) throw new Error('Please select a target machine')
          const requestPlatform = this.getPlatformForConnectionId(deviceId)
          const requestArch = this.getArchForConnectionId(deviceId)
          this.logExternalToolTarget('install-client-package', item, {
            request_client_id: deviceId,
            request_platform: requestPlatform,
            request_arch: requestArch,
          })
          if (!requestPlatform || !requestArch) throw new Error(`Unable to resolve target platform/arch for client ${deviceId}`)

          res = await fetch(`/api/connections/${encodeURIComponent(deviceId)}/external-tools/${encodeURIComponent(item.id)}/install`, {
            method: 'POST',
            headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
            body: JSON.stringify({
              params: {},
              platform: requestPlatform,
              arch: requestArch,
            }),
          })
        }
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to install package')
        const data = json.data || {}
        this.setInstallStatus(item, side, deviceId, { ...data, loading: false, error: data.error || '' })
        const sourceLabel = data.used_cache
          ? 'Installed from cached package'
          : data.downloaded
            ? 'Downloaded and installed'
            : data.package_source === 'local'
              ? 'Installed from local package file'
              : 'Installed successfully'
        const message = data.already_installed
          ? `Already installed: ${data.executable_path || data.install_dir || item.id}`
          : `${sourceLabel}: ${data.executable_path || data.install_dir || item.id}`
        ElMessage.success(message)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to install package')
      } finally {
        this.installLoading = false
      }
    },

    formatBytes(value) {
      const size = Number(value || 0)
      if (!Number.isFinite(size) || size <= 0) return '0 B'
      const units = ['B', 'KB', 'MB', 'GB']
      let n = size
      let i = 0
      while (n >= 1024 && i < units.length - 1) {
        n /= 1024
        i += 1
      }
      return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
    },

    formatExecMap(value) {
      const map = value && typeof value === 'object' ? value : {}
      const entries = Object.entries(map).filter(([name, path]) => String(name || '').trim() && String(path || '').trim())
      if (!entries.length) return '-'
      return entries.map(([name, path]) => `${name}: ${path}`).join('\n')
    },

    formatCommandMap(data) {
      const commands = data?.commands && typeof data.commands === 'object' ? data.commands : {}
      const entries = Object.entries(commands).filter(([name, command]) => String(name || '').trim() && String(command || '').trim())
      if (entries.length) return entries.map(([name, command]) => `${name}: ${command}`).join('\n')
      if (data?.command) return String(data.command)
      if (data?.executable_path) return String(data.executable_path)
      return '-'
    },

    packageExecNames(item) {
      return Object.keys(item?.execs || {}).filter(Boolean).join(', ') || '-'
    },

    formatInstallStatusDetails(data, item = null) {
      if (!data) return 'No install status available'
      const cache = data.cache || {}
      const newline = String.fromCharCode(10)
      const installLog = data.install_log || 'No install log available.'
      return [
        `Status: ${data.installed ? 'installed' : 'not installed'}`,
        `Install dir: ${data.install_dir || '-'}`,
        `Exec paths:${newline}${this.formatExecMap(data.exec_paths)}`,
        `Cached package: ${cache.exists || cache.cached ? 'yes' : 'no'}`,
        `Cache path: ${cache.cache_path || data.cache_path || '-'}`,
        `Cache size: ${cache.size ? this.formatBytes(cache.size) : '-'}`,
        `Cache mtime: ${cache.mtime || '-'}`,
        item?.source ? `Source: ${item.source}` : '',
        `Install log:${newline}${installLog}`,
      ].filter(Boolean).join(newline)
    },

    async getInstallStatusForAction(item) {
      const side = this.getSelectedTargetSideForAction()
      const deviceId = side === 'server' ? '__server__' : this.getActionDeviceId(item)
      return this.fetchInstallStatus(item, side, deviceId, { silent: false, force: true })
    },

    async showInstallStatus(item) {
      const data = await this.getInstallStatusForAction(item)
      if (!data) return
      const modulesText = this.formatPackageModules(item) || '-'
      const execsText = this.packageExecNames(item)
      this.showDetailDialog({
        title: `${item.display_name || item.id} install status`,
        subtitle: `${item.id} / ${this.getSelectedTargetSideForAction()}`,
        copyText: this.formatCommandMap(data),
        sections: [
          {
            title: 'Package',
            rows: [
              { label: 'ID', value: item.id || '-', mono: true },
              { label: 'Modules', value: modulesText, mono: true, multiline: modulesText.includes('\n') },
              { label: 'Execs', value: execsText, mono: true },
              { label: 'Platform package', value: data.package_key || '-', mono: true },
              { label: 'Source', value: item.source || data.source || data.package_source || '-' },
            ],
          },
          {
            title: 'Install status',
            rows: [
              { label: 'Status', value: data.installed ? 'Installed' : (data.installed === false ? 'Not installed' : 'Unknown') },
              { label: 'Install dir', value: data.install_dir || '-', mono: true },
              { label: 'Exec paths', value: this.formatExecMap(data.exec_paths), mono: true, multiline: true },
            ],
          },
          {
            title: 'Package cache',
            rows: [
              { label: 'Cached package', value: (data.cache?.exists || data.cache?.cached || data.cached) ? 'Yes' : 'No' },
              { label: 'Cache path', value: data.cache?.cache_path || data.cache_path || '-', mono: true },
              { label: 'Cache dir', value: data.cache?.cache_dir || '-', mono: true },
              { label: 'Cache size', value: data.cache?.size ? this.formatBytes(data.cache.size) : '-' },
              { label: 'Cache mtime', value: data.cache?.mtime || '-' },
            ],
          },
          {
            title: 'Install log',
            rows: [
              { label: 'Path', value: data.install_log_path || '-', mono: true },
              { label: 'Log', value: data.install_log || 'No install log available.', mono: true, multiline: true },
            ],
          },
        ],
      })
    },

    async copyInstallCommand(item) {
      const data = await this.getInstallStatusForAction(item)
      if (!data) return
      const command = this.formatCommandMap(data)
      if (!command || command === '-') {
        ElMessage.warning('No command available to copy')
        return
      }
      try {
        if (window.isSecureContext && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
          await navigator.clipboard.writeText(command)
        } else {
          this.copyTextFallback(command)
        }
        ElMessage.success(data.installed ? 'Command copied' : 'Command copied; package is not installed yet')
      } catch (e) {
        try {
          this.copyTextFallback(command)
          ElMessage.success(data.installed ? 'Command copied' : 'Command copied; package is not installed yet')
        } catch (_) {
          ElMessage.error('Failed to copy command')
        }
      }
    },

    copyTextFallback(text) {
      const textarea = document.createElement('textarea')
      textarea.value = String(text || '')
      textarea.setAttribute('readonly', '')
      textarea.style.position = 'fixed'
      textarea.style.left = '-9999px'
      textarea.style.top = '0'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.focus()
      textarea.select()
      textarea.setSelectionRange(0, textarea.value.length)
      const ok = document.execCommand('copy')
      document.body.removeChild(textarea)
      if (!ok) throw new Error('Fallback copy failed')
    },

    showDetailDialog({ title = '', subtitle = '', sections = [], copyText = '' } = {}) {
      this.detailDialogTitle = title || 'Details'
      this.detailSubtitle = subtitle || ''
      this.detailSections = (sections || []).map(section => ({
        title: section.title || 'Details',
        rows: (section.rows || []).filter(row => row && row.label),
      })).filter(section => section.rows.length)
      this.detailCopyText = copyText || ''
      this.detailDialogVisible = true
    },

    stringifyDetailValue(value) {
      if (value === undefined || value === null || value === '') return '-'
      if (typeof value === 'string') return value
      try {
        return JSON.stringify(value, null, 2)
      } catch (_) {
        return String(value)
      }
    },

    formatDetailValue(value) {
      return this.stringifyDetailValue(value)
    },

    async copyDetailText() {
      if (!this.detailCopyText) return
      try {
        if (window.isSecureContext && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
          await navigator.clipboard.writeText(this.detailCopyText)
        } else {
          this.copyTextFallback(this.detailCopyText)
        }
        ElMessage.success('Copied')
      } catch (e) {
        try {
          this.copyTextFallback(this.detailCopyText)
          ElMessage.success('Copied')
        } catch (_) {
          ElMessage.error('Failed to copy')
        }
      }
    },

    async confirmStart() {
      const item = this.pendingItem
      if (!item) {
        this.resetStartDialog()
        return
      }

      try {
        this.submitting = true
        const params = this.buildStartParams()
        const instanceId = this.deriveInstanceId(params)
        if (this.pendingTargetSide === 'server') {
          await this.startServerInstance(item, params, instanceId, false)
        } else {
          await this.startClientInstance(item, params, instanceId, false)
        }
        this.activeTab = 'instances'
        this.resetStartDialog()
      } catch (e) {
        ElMessage.error(e.message || 'Failed to start external tool')
      } finally {
        this.submitting = false
      }
    },

    async startServerInstance(item, params, instanceId, installIfNeeded = false) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/instances/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ params, instance_id: instanceId, install_if_needed: false }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to start server tool')
      ElMessage.success(json.data?.message || 'Server instance started')
      if (json.data?.install) this.setInstallStatus(this.getPackageForModule(item), 'server', '__server__', json.data.install)
      await this.loadServerInstances(item.id, false)
    },

    async startClientInstance(item, params, instanceId, installIfNeeded = false, deviceId = '') {
      const targetDeviceId = this.normalizeDeviceId(deviceId || this.getActionDeviceId(this.getPackageForModule(item)))
      if (!targetDeviceId) throw new Error('Please select a target machine')

      const requestPlatform = this.getPlatformForConnectionId(targetDeviceId)
      const requestArch = this.getArchForConnectionId(targetDeviceId)
      this.logExternalToolTarget('start-client-instance', item, {
        request_client_id: targetDeviceId,
        request_platform: requestPlatform,
        request_arch: requestArch,
      })
      if (!requestPlatform || !requestArch) throw new Error(`Unable to resolve target platform/arch for client ${targetDeviceId}`)

      const res = await fetch(`/api/connections/${encodeURIComponent(targetDeviceId)}/external-tools/${encodeURIComponent(item.id)}/instances/start`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          params,
          instance_id: instanceId,
          install_if_needed: false,
          platform: requestPlatform,
          arch: requestArch,
        }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to start client tool')
      ElMessage.success(json.data?.message || 'Client instance started')
      if (json.data?.install) this.setInstallStatus(this.getPackageForModule(item), 'client', targetDeviceId, json.data.install)
      await this.loadClientInstances(item.id, targetDeviceId, false)
    },

    normalizeInstanceRow(item, instance, side, deviceId = '') {
      const runtime = instance.runtime || {}
      const config = instance.config || {}
      const params = instance.params || {}
      const configPath = config.target || instance.config_file || ''
      const normalizedDeviceId = side === 'server' ? '__server__' : this.normalizeDeviceId(deviceId)
      const machineId = side === 'server' ? '__server__' : this.getMachineIdForConnectionId(normalizedDeviceId)
      const hostname = side === 'server' ? '' : this.getHostnameForConnectionId(normalizedDeviceId)
      return {
        row_key: `${side}:${normalizedDeviceId}:${item.id}:${instance.instance_id}`,
        side,
        device_id: normalizedDeviceId,
        connection_id: normalizedDeviceId,
        machine_id: machineId,
        hostname,
        machine_label: this.getMachineLabel(machineId, side, normalizedDeviceId),
        tool_id: item.id,
        package_id: item.package_id || instance.package_id || '',
        module_id: item.module_id || instance.module_id || '',
        display_name: item.display_name || item.id,
        instance_id: instance.instance_id || 'default',
        status: instance.status || '-',
        running: !!instance.running,
        pid: instance.pid || '',
        pid_file: instance.pid_file || runtime.pid_file || '',
        stdout: instance.stdout || runtime.stdout || '',
        stderr: instance.stderr || runtime.stderr || '',
        state_file: instance.state_file || runtime.state_file || '',
        config_path: configPath,
        params,
        started_at: instance.started_at || '',
        stopped_at: instance.stopped_at || '',
        exec_path: runtime.argv?.[0] || item.package?.executable_rel_path || '',
        cwd: runtime.cwd || instance.cwd || '',
        argv: runtime.argv || instance.argv || [],
        raw: instance,
        module: item,
      }
    },

    // formatPortInfo(row) {
    //   const params = row.params || {}
    //   if (params.local_port || params.remote_port) {
    //     const localIp = params.local_ip || '127.0.0.1'
    //     const localPort = params.local_port || '-'
    //     const remotePort = params.remote_port || '-'
    //     return `${localIp}:${localPort} -> server:${remotePort}`
    //   }
    //   if (params.bind_port) return `bind:${params.bind_port}`
    //   if (params.server_port) return `control:${params.server_port}`
    //   return '-'
    // },



    formatPortInfo(row) {
  const params = row.params || {}

  // 1. 端口映射类，优先展示完整映射关系，比如 frpc。
  if (params.local_port || params.remote_port) {
    const localIp = params.local_ip || params.local_addr || params.local_host || '127.0.0.1'
    const localPort = params.local_port || '-'
    const remoteHost = params.remote_host || params.server_addr || 'server'
    const remotePort = params.remote_port || '-'
    return `${localIp}:${localPort} -> ${remoteHost}:${remotePort}`
  }

  // 2. 服务监听类，比如 filebrowser、http server、web ui。
  const listenPort =
    params.port ||
    params.listen_port ||
    params.http_port ||
    params.web_port ||
    params.ui_port ||
    params.dashboard_port ||
    params.rtsp_port ||
    params.hls_port ||
    params.webrtc_port

  if (listenPort) {
    const listenHost =
      params.address ||
      params.listen_addr ||
      params.listen_address ||
      params.host ||
      params.bind_addr ||
      params.bind_address ||
      params.ip ||
      '127.0.0.1'

    return `${listenHost}:${listenPort}`
  }

  // 3. 服务端 bind 类，比如 frps。
  if (params.bind_port) {
    const bindHost = params.bind_addr || params.bind_address || params.address || '0.0.0.0'
    return `${bindHost}:${params.bind_port}`
  }

  // 4. 控制端口类，比如 frpc 连接 frps 的 server_port。
  if (params.server_port) {
    const serverHost = params.server_addr || params.server_host || 'server'
    return `${serverHost}:${params.server_port}`
  }

  // 5. 如果 meta 里直接给了 URL，也可以显示。
  const url =
    params.url ||
    params.http_url ||
    params.web_url ||
    params.publish_url ||
    params.public_url

  if (url) return String(url)

  return '-'
},

    statusTagType(status) {
      const value = String(status || '').toLowerCase()
      if (value === 'running') return 'success'
      if (value === 'stale' || value === 'error') return 'danger'
      if (value === 'stopped') return 'info'
      return 'info'
    },

    shortTime(value) {
      const text = String(value || '').trim()
      if (!text) return '-'
      return text.replace('T', ' ').slice(0, 19)
    },

    async stopInstance(row) {
      try {
        await ElMessageBox.confirm(
          `Stop ${row.side} instance ${row.tool_id}/${row.instance_id}?`,
          'Stop External Tool Instance',
          {
            type: 'warning',
            confirmButtonText: 'Stop',
            cancelButtonText: 'Cancel',
          },
        )
      } catch (_) {
        return
      }

      try {
        if (row.side === 'server') {
          await this.stopServerInstance(row)
        } else {
          await this.stopClientInstance(row)
        }
        ElMessage.success(`Stop requested: ${row.instance_id}`)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to stop instance')
      }
    },

    async stopServerInstance(row) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(row.tool_id)}/server/instances/${encodeURIComponent(row.instance_id)}/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ params: {} }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to stop server instance')
      await this.loadServerInstances(row.tool_id, false)
    },

    async stopClientInstance(row) {
      const deviceId = this.normalizeDeviceId(row.device_id)
      if (!deviceId) throw new Error('Client instance row is missing device_id')
      const res = await fetch(`/api/connections/${encodeURIComponent(deviceId)}/external-tools/${encodeURIComponent(row.tool_id)}/instances/${encodeURIComponent(row.instance_id)}/stop`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({}),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to stop client instance')
      await this.loadClientInstances(row.tool_id, deviceId, false)
    },

    async openInstanceLogs(row) {
      this.currentLogRow = row
      await this.readLogs(row, true)
    },

    async refreshCurrentLogs() {
      if (!this.currentLogRow) return
      await this.readLogs(this.currentLogRow, true)
    },

    async readLogs(row, openDialog = false) {
      try {
        this.logLoading = true
        let data
        if (row.side === 'server') {
          data = await this.readServerLogs(row)
        } else {
          data = await this.readClientLogs(row)
        }
        this.logDialogTitle = `${row.side} ${row.tool_id}/${row.instance_id} logs`
        this.logFilePath = data.log_file || row.stdout || ''
        this.logContent = data.content || ''
        if (openDialog) this.logDialogVisible = true
        this.scrollLogsToBottom()
      } catch (e) {
        ElMessage.error(e.message || 'Failed to read logs')
      } finally {
        this.logLoading = false
      }
    },

    async readServerLogs(row) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(row.tool_id)}/server/instances/${encodeURIComponent(row.instance_id)}/logs?bytes=65536`)
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to read server logs')
      return json.data || {}
    },

    async readClientLogs(row) {
      const deviceId = this.normalizeDeviceId(row.device_id)
      if (!deviceId) throw new Error('Client instance row is missing device_id')
      const res = await fetch(`/api/connections/${encodeURIComponent(deviceId)}/external-tools/${encodeURIComponent(row.tool_id)}/instances/${encodeURIComponent(row.instance_id)}/logs`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ max_bytes: 65536 }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to read client logs')
      return json.data || {}
    },

    scrollLogsToBottom() {
      this.$nextTick(() => {
        const el = this.$refs.logContentRef
        if (el && typeof el.scrollTop === 'number') {
          el.scrollTop = el.scrollHeight || 0
        }
      })
    },




    // url parse
    getBrowserAccessHost() {
  if (typeof window === 'undefined' || !window.location) return '127.0.0.1'
  return window.location.hostname || '127.0.0.1'
},

getBrowserOrigin() {
  if (typeof window === 'undefined' || !window.location) return ''
  return window.location.origin || ''
},

getBrowserProtocol() {
  if (typeof window === 'undefined' || !window.location) return 'http:'
  return window.location.protocol || 'http:'
},

getModuleWebUrlTemplate(module) {
  if (!module) return ''

  if (module.web && typeof module.web === 'object' && module.web.url) {
    return String(module.web.url || '').trim()
  }

  if (module.web_url) {
    return String(module.web_url || '').trim()
  }

  return ''
},

getInstanceWebUrlTemplate(row) {
  return this.getModuleWebUrlTemplate(row?.module)
},

canOpenWebInstance(row) {
  if (!row || row.side !== 'server') return false
  return !!this.getInstanceWebUrlTemplate(row)
},

buildInstanceUrlContext(row) {
  const params = row?.params || {}
  const browserHost = this.getBrowserAccessHost()
  const browserOrigin = this.getBrowserOrigin()
  const protocol = this.getBrowserProtocol()

  const accessHost = params.access_host || params.public_host || params.external_host || browserHost

  return {
    ...params,

    // 推荐给 meta 使用的访问变量。
    access_host: accessHost,
    public_host: params.public_host || accessHost,
    external_host: params.external_host || accessHost,

    // 浏览器上下文。
    browser_host: browserHost,
    browser_origin: browserOrigin,
    browser_protocol: protocol,

    // 监听地址相关变量。注意：这些不一定适合浏览器访问。
    ip: params.ip || params.address || params.host || params.listen_addr || params.bind_addr || browserHost,
    host: params.host || params.address || params.ip || params.listen_addr || params.bind_addr || browserHost,
    address: params.address || params.ip || params.host || params.listen_addr || params.bind_addr || browserHost,
    listen_host: params.listen_host || params.listen_addr || params.address || params.host || '0.0.0.0',

    // 常见端口别名。
    port: params.port || params.listen_port || params.http_port || params.web_port || params.ui_port || params.dashboard_port || '',
    listen_port: params.listen_port || params.port || params.http_port || params.web_port || '',

    // instance 上下文。
    side: row?.side || '',
    tool_id: row?.tool_id || '',
    instance_id: row?.instance_id || '',
    machine_id: row?.machine_id || '',
    hostname: row?.hostname || '',
    status: row?.status || '',
    pid: row?.pid || '',
  }
},

renderInstanceUrlTemplate(template, row) {
  const context = this.buildInstanceUrlContext(row)
  const missing = []

  const url = String(template || '').replace(/{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}/g, (match, key) => {
    const value = context[key]

    if (value === undefined || value === null || value === '') {
      missing.push(key)
      return ''
    }

    return String(value)
  })

  return {
    url: this.normalizeOpenWebUrl(url, context),
    missing,
  }
},

normalizeOpenWebUrl(url, context = {}) {
  const raw = String(url || '').trim()
  if (!raw) return ''

  try {
    const parsed = new URL(raw, this.getBrowserOrigin() || undefined)

    // 防呆：如果模板仍然用了 127.0.0.1 / 0.0.0.0 / localhost，
    // server side 打开时自动换成 access_host。
    const localHosts = new Set(['127.0.0.1', 'localhost', '0.0.0.0', '::1', '[::1]'])
    if (localHosts.has(String(parsed.hostname || '').toLowerCase())) {
      parsed.hostname = context.access_host || this.getBrowserAccessHost()
    }

    return parsed.toString()
  } catch (_) {
    return raw
  }
},

openWebInstance(row) {
  if (!this.canOpenWebInstance(row)) return

  const template = this.getInstanceWebUrlTemplate(row)
  const { url, missing } = this.renderInstanceUrlTemplate(template, row)

  if (!url || missing.length) {
    ElMessage.warning(`Web URL is incomplete. Missing: ${missing.join(', ')}`)
    return
  }

  window.open(url, '_blank', 'noopener,noreferrer')
},


    openInstanceInfo(row) {
      const runtime = row.raw?.runtime || {}
      const params = row.params || {}
      this.showDetailDialog({
        title: `${row.side} ${row.tool_id}/${row.instance_id} info`,
        subtitle: row.machine_label || row.side,
        copyText: row.exec_path || '',
        sections: [
          {
            title: 'Overview',
            rows: [
              { label: 'Side', value: row.side },
              { label: 'Machine', value: row.machine_label || row.machine_id },
              { label: 'Machine ID', value: row.machine_id, mono: true },
              { label: 'Connection ID', value: row.connection_id || '-', mono: true },
              { label: 'Hostname', value: row.hostname || '-' },
              { label: 'Tool', value: row.tool_id, mono: true },
              { label: 'Instance', value: row.instance_id, mono: true },
              { label: 'Status', value: row.status },
              { label: 'PID', value: row.pid || '-' },
              { label: 'Port', value: this.formatPortInfo(row), mono: true },
              { label: 'Started', value: this.shortTime(row.started_at) },
              { label: 'Stopped', value: this.shortTime(row.stopped_at) },
              { label: 'Message', value: row.raw?.message || '-' },
            ],
          },
          {
            title: 'Runtime paths',
            rows: [
              { label: 'Executable', value: row.exec_path || runtime.argv?.[0] || '-', mono: true },
              { label: 'CWD', value: row.cwd || runtime.cwd || '-', mono: true },
              { label: 'Config', value: row.config_path || '-', mono: true },
              { label: 'Log', value: row.stdout || '-', mono: true },
              { label: 'Stderr', value: row.stderr || '-', mono: true },
              { label: 'PID file', value: row.pid_file || '-', mono: true },
              { label: 'State file', value: row.state_file || '-', mono: true },
              { label: 'Argv', value: row.argv?.length ? row.argv : (runtime.argv || []), mono: true, multiline: true },
            ],
          },
          {
            title: 'Params',
            rows: [
              { label: 'Runtime params', value: params, mono: true, multiline: true },
            ],
          },
        ],
      })
    },

    canModifyStoppedInstanceFiles(row) {
      if (!row || row.running) return false
      const status = String(row.status || '').toLowerCase()
      return status === 'stopped' || status === 'not_started' || status === 'error'
    },

    canRestartInstance(row) {
      if (!row || row.running) return false
      const status = String(row.status || '').toLowerCase()
      return status === 'stopped' || status === 'not_started' || status === 'error'
    },

    handleInstanceMoreCommand(command, row) {
      if (command === 'info') return this.openInstanceInfo(row)
        if (command === 'open_web') return this.openWebInstance(row)
      if (command === 'restart') return this.restartInstance(row)
      if (command === 'clear_logs') return this.clearInstanceLogs(row)
      if (command === 'remove') return this.removeInstance(row)
      return null
    },

    async restartInstance(row) {
      if (!this.canRestartInstance(row)) {
        ElMessage.warning('Please stop this instance before restarting it')
        return
      }
      try {
        await ElMessageBox.confirm(
          `Restart ${row.side} instance ${row.tool_id}/${row.instance_id} with the same params?`,
          'Restart External Tool Instance',
          { type: 'warning', confirmButtonText: 'Restart', cancelButtonText: 'Cancel' },
        )
      } catch (_) {
        return
      }

      try {
        if (row.side === 'server') {
          await this.startServerInstance(row.module, row.params || {}, row.instance_id, false)
        } else {
          await this.startClientInstance(row.module, row.params || {}, row.instance_id, false, row.connection_id || row.device_id)
        }
        ElMessage.success(`Restarted: ${row.instance_id}`)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to restart instance')
      }
    },

    async removeInstance(row) {
      if (!this.canModifyStoppedInstanceFiles(row)) {
        ElMessage.warning('Stop this instance first')
        return
      }
      try {
        await ElMessageBox.confirm(
          `Remove runtime files for ${row.side} instance ${row.tool_id}/${row.instance_id}?`,
          'Remove External Tool Instance',
          { type: 'warning', confirmButtonText: 'Remove', cancelButtonText: 'Cancel' },
        )
      } catch (_) {
        return
      }

      try {
        if (row.side === 'server') {
          await this.removeServerInstance(row)
        } else {
          await this.removeClientInstance(row)
        }
        ElMessage.success(`Removed: ${row.instance_id}`)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to remove instance')
      }
    },

    async removeServerInstance(row) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(row.tool_id)}/server/instances/${encodeURIComponent(row.instance_id)}/remove`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to remove server instance')
      await this.loadServerInstances(row.tool_id, false)
    },

    async removeClientInstance(row) {
      const deviceId = this.normalizeDeviceId(row.connection_id || row.device_id)
      if (!deviceId) throw new Error('Client instance row is missing connection_id/device_id')
      const res = await fetch(`/api/connections/${encodeURIComponent(deviceId)}/external-tools/${encodeURIComponent(row.tool_id)}/instances/${encodeURIComponent(row.instance_id)}/remove`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({}),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to remove client instance')
      await this.loadClientInstances(row.tool_id, deviceId, false)
    },

    async clearInstanceLogs(row) {
      if (!this.canModifyStoppedInstanceFiles(row)) {
        ElMessage.warning('Stop this instance first')
        return
      }
      try {
        await ElMessageBox.confirm(
          `Clear log file for ${row.side} instance ${row.tool_id}/${row.instance_id}?`,
          'Clear External Tool Logs',
          { type: 'warning', confirmButtonText: 'Clear Logs', cancelButtonText: 'Cancel' },
        )
      } catch (_) {
        return
      }

      try {
        if (row.side === 'server') {
          await this.clearServerInstanceLogs(row)
        } else {
          await this.clearClientInstanceLogs(row)
        }
        if (this.currentLogRow?.row_key === row.row_key) {
          this.logContent = ''
          this.scrollLogsToBottom()
        }
        ElMessage.success(`Logs cleared: ${row.instance_id}`)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to clear logs')
      }
    },

    async clearServerInstanceLogs(row) {
      const res = await fetch(`/api/external-tools/${encodeURIComponent(row.tool_id)}/server/instances/${encodeURIComponent(row.instance_id)}/clear-logs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to clear server logs')
    },

    async clearClientInstanceLogs(row) {
      const deviceId = this.normalizeDeviceId(row.connection_id || row.device_id)
      if (!deviceId) throw new Error('Client instance row is missing connection_id/device_id')
      const res = await fetch(`/api/connections/${encodeURIComponent(deviceId)}/external-tools/${encodeURIComponent(row.tool_id)}/instances/${encodeURIComponent(row.instance_id)}/clear-logs`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({}),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to clear client logs')
    },

formatVersionLabel(version) {
  const value = String(version || '').trim()
  if (!value) return ''

  // 已经带 v 的标准数字版本，直接返回，避免 vv1.2.3
  if (/^v\d+\.\d+(?:\.\d+)?$/i.test(value)) {
    return value
  }

  // 只有 x.x 或 x.x.x 这种纯数字版本才自动加 v
  if (/^\d+\.\d+(?:\.\d+)?$/.test(value)) {
    return `v${value}`
  }

  // snapshot、commit、custom tag 等原样显示
  return value
}

  },
}
</script>

<style scoped>
.external-tool-body {
  height: 100%;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
  overflow: hidden;
}

.external-tool-toolbar {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 10px;
  align-items: center;
  flex: 0 0 auto;
}

.external-tool-toolbar-left,
.external-tool-toolbar-right {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.external-tool-toolbar-left {
  flex-wrap: wrap;
}

.external-tool-toolbar-right {
  justify-content: flex-end;
}

.external-tool-toolbar :deep(.el-button) {
  height: 32px;
  min-height: 32px;
  padding-inline: 12px;
  border-radius: 10px;
  margin: 0;
}

.external-tool-toolbar :deep(.el-button + .el-button) {
  margin-left: 0;
}

.external-tool-toolbar :deep(.el-input__wrapper),
.external-tool-toolbar :deep(.el-select__wrapper) {
  min-height: 32px;
  height: 32px;
  border-radius: 10px;
  font-size: 12px;
}

.external-tool-filter {
  width: 150px;
}

.external-tool-target-control {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0;
  border: 0;
  border-radius: 0;
  background: transparent;
}

.external-tool-target-label {
  font-size: 12px;
  font-weight: 800;
  letter-spacing: .02em;
  color: var(--muted-2, #94a3b8);
  text-transform: uppercase;
}

.external-tool-target-select {
  width: 320px;
}

.external-tool-device-filter {
  width: 230px;
}

.external-tool-search {
  width: 280px;
}

.external-tool-tabs {
  flex: 1 1 auto;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

.external-tool-tabs :deep(.el-tabs__header) {
  flex: 0 0 auto;
  margin-bottom: 12px;
}

.external-tool-tabs :deep(.el-tabs__content) {
  flex: 1 1 auto;
  min-height: 0;
  overflow: hidden;
}

.external-tool-tabs :deep(.el-tab-pane) {
  height: 100%;
  min-height: 0;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.external-tool-module-list {
  flex: 1 1 auto;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 10px;
  max-height: none;
  overflow: auto;
  padding-right: 4px;
}

.external-tool-package-split {
  flex: 1 1 auto;
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(280px, 360px) minmax(0, 1fr);
  gap: 14px;
  overflow: hidden;
}

.external-tool-package-list-panel,
.external-tool-package-detail-panel {
  min-height: 0;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.external-tool-package-list {
  flex: 1 1 auto;
  min-height: 0;
  overflow: auto;
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-right: 4px;
}

.external-tool-package-list-card {
  cursor: pointer;
  transition: border-color 0.15s ease, box-shadow 0.15s ease, background 0.15s ease;
}

.external-tool-package-list-card.active {
  border-color: rgba(59, 130, 246, 0.45);
  box-shadow: 0 6px 18px rgba(37, 99, 235, 0.12);
  background: #f8fbff;
}

.external-tool-package-list-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--text, #0f172a);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.external-tool-package-list-status {
  margin-top: 8px;
  min-height: 22px;
  display: flex;
  align-items: center;
}

.external-tool-package-list-status {
  margin-top: 8px;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.external-tool-package-list-mobile-meta-tag {
  display: none;
}

.external-tool-package-list-desc {
  margin-top: 8px;
  color: var(--muted, #64748b);
  font-size: 13px;
  line-height: 1.45;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.external-tool-package-mobile-detail {
  display: none;
}

.external-tool-package-detail-tags {
  margin-top: 8px;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.external-tool-package-detail-desc {
  margin-top: 12px;
}

.small-text {
  font-size: 12px;
}

.external-tool-package-detail-card {
  flex: 1 1 auto;
  min-height: 0;
  overflow: auto;
  padding: 16px;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 14px;
  background: #fff;
  box-shadow: 0 4px 14px rgba(15, 23, 42, 0.04);
}

.external-tool-package-detail-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}

.external-tool-package-detail-main {
  min-width: 0;
  flex: 1 1 auto;
}

.external-tool-package-detail-actions {
  flex: 0 0 auto;
}

.external-tool-package-detail-action-row {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
}

.external-tool-package-detail-actions :deep(.el-button.external-tool-package-detail-action-button),
.external-tool-package-detail-actions :deep(.el-dropdown .el-button.external-tool-package-detail-action-button) {
  width: auto;
  min-width: 0;
  height: 26px;
  min-height: 26px;
  padding: 0 9px;
  border-radius: 7px;
  font-size: 12px;
  line-height: 24px;
  margin-left: 0;
}

.external-tool-title.large {
  font-size: 17px;
}

.external-tool-package-detail-section {
  margin-top: 18px;
}

.external-tool-package-modules.detail {
  margin-top: 10px;
}

.external-tool-card {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 14px;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 14px;
  background: #fff;
  box-shadow: 0 4px 14px rgba(15, 23, 42, 0.04);
}

.external-tool-card-main {
  min-width: 0;
  flex: 1;
}

.external-tool-title-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.external-tool-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--text, #0f172a);
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.external-tool-desc {
  margin-top: 8px;
  color: var(--muted, #64748b);
  line-height: 1.45;
}

.external-tool-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 9px;
  color: var(--muted, #64748b);
  font-size: 12px;
}


.external-tool-package-modules {
  margin-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.external-tool-package-module-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 10px;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 10px;
  background: #f8fafc;
}

.external-tool-package-module-main {
  min-width: 0;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.external-tool-modules-panel {
  padding: 14px;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 14px;
  background: #f8fafc;
}

.external-tool-package-module-card {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding: 12px;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 12px;
  background: #fff;
  box-shadow: 0 2px 10px rgba(15, 23, 42, 0.03);
}

.external-tool-package-module-content {
  min-width: 0;
  flex: 1 1 auto;
}

.external-tool-package-module-title-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.external-tool-package-module-desc {
  margin-top: 6px;
  color: var(--muted, #64748b);
  font-size: 13px;
  line-height: 1.45;
}

.strong {
  font-weight: 700;
}

.muted {
  color: var(--muted, #64748b);
}

.external-tool-actions {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  justify-content: flex-start;
  gap: 8px;
  min-width: 0;
  flex: 0 0 auto;
}

.external-tool-action-row {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
}

.external-tool-action-row.single {
  display: flex;
}

.external-tool-action-row :deep(.el-button),
.external-tool-action-row :deep(.el-dropdown),
.external-tool-action-row :deep(.el-dropdown .el-button) {
  width: auto;
  min-width: 0;
  margin-left: 0;
}

.external-tool-action-row :deep(.el-button) {
  height: 32px;
  min-height: 32px;
  border-radius: 10px;
  padding-inline: 14px;
}

.external-tool-table-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.external-tool-table-actions :deep(.el-button + .el-button) {
  margin-left: 0;
}

.external-tool-instance-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex: 0 0 auto;
  margin-bottom: 8px;
}

.external-tool-hint {
  color: var(--muted, #64748b);
  font-size: 12px;
}

.external-tool-instance-table-shell {
  flex: 0 0 auto;
  min-height: 0;
  height: 560px;
  overflow: hidden;
}

.external-tool-instance-table {
  width: 100%;
  height: 100% !important;
  border-radius: 12px;
  overflow: hidden;
}

.external-tool-instance-table :deep(.el-table__inner-wrapper),
.external-tool-instance-table :deep(.el-scrollbar),
.external-tool-instance-table :deep(.el-scrollbar__wrap) {
  height: 100% !important;
}

.external-tool-instance-table :deep(.el-scrollbar__wrap) {
  overflow-y: auto !important;
  overflow-x: auto !important;
}

.external-tool-instance-table :deep(.el-table__body-wrapper) {
  overflow-y: auto !important;
}

.external-tool-instance-table :deep(th.el-table__cell) {
  background: #f8fafc !important;
  color: #475569;
  font-weight: 700;
}

.external-tool-instance-table :deep(.el-table__body td.el-table__cell) {
  padding: 10px 0;
}

.external-tool-instance-table :deep(tr) {
  background: #fff;
}

.external-tool-instance-table :deep(.cell) {
  line-height: 1.55;
}

.external-tool-instance-card-shell,
.external-tool-instance-card-list {
  display: none;
}

.external-tool-instance-card-list {
  grid-template-columns: 1fr;
  gap: 12px;
  height: 100%;
  min-height: 0;
  overflow-y: auto;
  padding-right: 2px;
}

.external-tool-instance-card {
  background: #fff;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 14px;
  padding: 12px;
  box-shadow: 0 4px 14px rgba(15, 23, 42, 0.04);
}

.external-tool-instance-card-top {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  min-width: 0;
}

.external-tool-instance-icon {
  flex: 0 0 auto;
  width: 22px;
  height: 22px;
  margin-top: 2px;
  border-radius: 999px;
  background: #f8fafc;
  border: 1px solid rgba(15, 23, 42, 0.08);
  display: flex;
  align-items: center;
  justify-content: center;
}

.external-tool-instance-icon span {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: var(--muted-2, #94a3b8);
}

.external-tool-instance-icon span.running {
  background: var(--el-color-success);
}

.external-tool-instance-icon span.stale {
  background: var(--el-color-danger);
}

.external-tool-instance-card-main {
  min-width: 0;
  flex: 1;
}

.external-tool-instance-name {
  font-size: 14px;
  font-weight: 700;
  color: var(--text, #0f172a);
  line-height: 1.4;
  word-break: break-word;
}

.external-tool-instance-tags {
  margin-top: 10px;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.external-tool-instance-meta {
  margin-top: 8px;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px 10px;
}

.external-tool-instance-meta-item {
  min-width: 0;
}

.external-tool-instance-meta-label {
  font-size: 11px;
  color: var(--muted-2, #94a3b8);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.external-tool-instance-meta-value {
  margin-top: 2px;
  font-size: 12px;
  color: var(--text, #0f172a);
  word-break: break-word;
  line-height: 1.4;
}

.external-tool-instance-card-actions {
  margin-top: 12px;
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  align-items: stretch;
}

.external-tool-instance-card-actions :deep(.el-button),
.external-tool-instance-card-actions :deep(.el-dropdown),
.external-tool-instance-card-actions :deep(.el-dropdown .el-button) {
  width: 100%;
  min-width: 0;
  margin: 0;
}

.external-tool-instance-card-actions :deep(.el-button) {
  min-height: 32px;
  height: 32px;
  border-radius: 10px;
  padding-inline: 12px;
  justify-content: center;
}

.external-tool-instance-card-actions :deep(.el-dropdown) {
  display: block;
}

.path-line {
  max-width: 320px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.external-tool-empty {
  flex: 1 1 auto;
  min-height: 0;
  padding: 64px 16px;
  text-align: center;
  color: var(--muted, #64748b);
}

.external-tool-empty.small {
  padding: 20px 8px;
}

.external-tool-run-body {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.external-tool-run-summary {
  padding: 12px;
  border-radius: 10px;
  background: #f8fafc;
  line-height: 1.6;
}

.external-tool-param-form {
  max-height: 460px;
  overflow: auto;
  padding-right: 4px;
}

.external-tool-number {
  width: 100%;
}

.external-tool-param-help {
  margin-top: 4px;
  color: var(--muted, #64748b);
  font-size: 12px;
  line-height: 1.45;
}

.external-tool-log-path {
  margin-bottom: 8px;
  padding: 8px 10px;
  border-radius: 8px;
  background: #f8fafc;
  color: var(--muted, #64748b);
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.external-tool-log-content {
  max-height: 560px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 12px;
  border-radius: 10px;
  background: #050505;
  color: #d9e2ff;
  border: 1px solid rgba(255,255,255,.12);
  scrollbar-color: #303544 #050505;
  scrollbar-width: thin;
}

.external-tool-log-content::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}

.external-tool-log-content::-webkit-scrollbar-track {
  background: #050505;
  border-radius: 999px;
}

.external-tool-log-content::-webkit-scrollbar-thumb {
  background: #303544;
  border-radius: 999px;
  border: 2px solid #050505;
}

.external-tool-log-content::-webkit-scrollbar-thumb:hover {
  background: #495064;
}

.external-tool-detail-body {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.external-tool-detail-subtitle {
  padding: 0;
  border-radius: 0;
  background: transparent;
  color: var(--muted, #64748b);
  font-size: 12px;
}

.external-tool-detail-section {
  border: 0;
  border-radius: 0;
  overflow: visible;
  background: transparent;
}

.external-tool-detail-section-title {
  padding: 0 0 8px;
  font-weight: 700;
  border-bottom: 0;
  background: transparent;
}

.external-tool-detail-grid {
  display: grid;
  grid-template-columns: 1fr;
}

.external-tool-detail-row {
  display: grid;
  grid-template-columns: 150px minmax(0, 1fr);
  gap: 12px;
  padding: 7px 0;
  border-bottom: 0;
}

.external-tool-detail-row:last-child {
  border-bottom: 0;
}

.external-tool-detail-label {
  color: var(--muted, #64748b);
  font-size: 12px;
}

.external-tool-detail-value {
  min-width: 0;
  overflow: hidden;
}

.external-tool-detail-value.multiline {
  white-space: normal;
  overflow: visible;
}

.external-tool-detail-pre {
  margin: 0;
  max-height: 260px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 10px;
  border-radius: 8px;
  background: #050505;
  border: 1px solid rgba(255,255,255,.10);
  color: #d9e2ff;
  scrollbar-color: #303544 #050505;
  scrollbar-width: thin;
}

.external-tool-detail-pre::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}

.external-tool-detail-pre::-webkit-scrollbar-track {
  background: #050505;
  border-radius: 999px;
}

.external-tool-detail-pre::-webkit-scrollbar-thumb {
  background: #303544;
  border-radius: 999px;
  border: 2px solid #050505;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}

.strong {
  font-weight: 700;
}

.muted {
  color: var(--muted, #64748b);
}

@media (max-width: 960px) {
  .external-tool-toolbar {
    grid-template-columns: 1fr;
  }

  .external-tool-toolbar-left,
  .external-tool-toolbar-right {
    width: 100%;
  }

  .external-tool-toolbar-right {
    justify-content: flex-start;
  }

  .external-tool-search {
    width: 100%;
  }

  .external-tool-package-split {
    display: block;
    overflow: auto;
    padding-right: 4px;
  }

  .external-tool-package-list-panel {
    min-height: 0;
    max-height: none;
    overflow: visible;
  }

  .external-tool-package-list {
    overflow: visible;
    padding-right: 0;
  }

  .external-tool-package-detail-panel {
    display: none;
  }

  .external-tool-package-mobile-detail {
    display: block;
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid rgba(15, 23, 42, 0.08);
  }

  .external-tool-package-list-mobile-meta-tag {
    display: inline-flex;
  }

  .external-tool-package-mobile-actions {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px;
    margin-top: 12px;
  }

  .external-tool-package-mobile-actions :deep(.el-button),
  .external-tool-package-mobile-actions :deep(.el-dropdown),
  .external-tool-package-mobile-actions :deep(.el-dropdown .el-button) {
    width: 100%;
    min-width: 0;
    margin: 0;
  }

  .external-tool-package-mobile-actions :deep(.el-button) {
    min-height: 32px;
    height: 32px;
    border-radius: 10px;
    padding-inline: 12px;
    justify-content: center;
  }

  .external-tool-package-mobile-actions :deep(.el-dropdown) {
    display: block;
  }

  .external-tool-package-mobile-modules {
    margin-top: 12px;
  }

  .external-tool-package-mobile-modules .external-tool-package-module-card {
    flex-direction: column;
    align-items: stretch;
  }

  .external-tool-package-mobile-modules .external-tool-package-module-card > .el-button {
    width: 100%;
    min-height: 32px;
    height: 32px;
    border-radius: 10px;
    padding-inline: 12px;
    justify-content: center;
    margin-left: 0;
  }

}

@media (max-width: 768px), (max-height: 720px) {
  .external-tool-instance-table-shell {
    display: none !important;
  }

  .external-tool-instance-card-shell {
    display: flex !important;
    flex: 1 1 auto !important;
    min-height: 0 !important;
    overflow: hidden !important;
  }

  .external-tool-instance-card-list {
    display: grid !important;
    flex: 1 1 auto !important;
    min-height: 0 !important;
    overflow-y: auto !important;
  }
}

@media (max-width: 640px) {
  .external-tool-toolbar-left {
    align-items: stretch;
  }

  .external-tool-toolbar-left > .el-button,
  .external-tool-target-control,
  .external-tool-target-select,
  .external-tool-toolbar-left :deep(.el-checkbox),
  .external-tool-toolbar-right,
  .external-tool-search {
    width: 100%;
    min-width: 0;
  }

  .external-tool-card {
    flex-direction: column;
    gap: 12px;
  }

  .external-tool-title {
    flex: 0 0 100%;
    max-width: 100%;
  }

  
.external-tool-package-modules {
  margin-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.external-tool-package-module-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 10px;
  border: 1px solid rgba(15, 23, 42, 0.06);
  border-radius: 10px;
  background: #f8fafc;
}

.external-tool-package-module-main {
  min-width: 0;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.strong {
  font-weight: 700;
}

.muted {
  color: var(--muted, #64748b);
}

.external-tool-actions {
    width: 100%;
    align-items: stretch;
    min-width: 0;
  }

  .external-tool-action-row,
  .external-tool-action-row.single {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    justify-content: stretch;
    width: 100%;
  }

  .external-tool-action-row :deep(.el-button),
  .external-tool-action-row :deep(.el-dropdown),
  .external-tool-action-row :deep(.el-dropdown .el-button) {
    width: 100%;
  }

  .external-tool-package-module-card {
    flex-direction: column;
  }

  .external-tool-package-module-card > .el-button {
    width: 100%;
  }

  .external-tool-instance-meta {
    grid-template-columns: 1fr;
  }

  .external-tool-instance-card-actions {
    grid-template-columns: 1fr;
    gap: 6px;
  }

  .external-tool-detail-row {
    grid-template-columns: 1fr;
    gap: 4px;
  }
}
</style>

<style>
/* ExternalToolManagerDialog: 固定桌面高度，移动端全屏，只让表格/卡片区域滚动。 */
.external-tool-overlay .el-overlay-dialog {
  overflow: hidden !important;
}

.external-tool-overlay .el-dialog {
  height: 78vh !important;
  max-height: 78vh !important;
  margin-top: 5vh !important;
  display: flex !important;
  flex-direction: column !important;
  overflow: hidden !important;
}

.external-tool-overlay .el-dialog__header {
  flex: 0 0 auto !important;
}

.external-tool-overlay .el-dialog__body {
  flex: 1 1 auto !important;
  min-height: 0 !important;
  overflow: hidden !important;
  padding-top: 12px !important;
  padding-bottom: 12px !important;
}

.external-tool-overlay .fixed-dialog-body {
  height: 100% !important;
  min-height: 0 !important;
  overflow: hidden !important;
  display: flex !important;
  flex-direction: column !important;
}

.external-tool-overlay .external-tool-instance-table-shell {
  flex: 0 0 auto !important;
  min-height: 0 !important;
  height: 560px !important;
  max-height: 560px !important;
  overflow: hidden !important;
}

.external-tool-overlay .external-tool-instance-table,
.external-tool-overlay .external-tool-instance-table .el-table__inner-wrapper,
.external-tool-overlay .external-tool-instance-table .el-scrollbar,
.external-tool-overlay .external-tool-instance-table .el-scrollbar__wrap {
  height: 100% !important;
}

.external-tool-overlay .external-tool-instance-table .el-scrollbar__wrap {
  overflow-y: auto !important;
  overflow-x: auto !important;
}

.external-tool-info-overlay .el-overlay-dialog {
  overflow: auto !important;
}

.external-tool-info-overlay .external-tool-info-dialog {
  margin-top: 6vh !important;
  max-height: 86vh !important;
  display: flex !important;
  flex-direction: column !important;
}

.external-tool-info-overlay .external-tool-info-dialog .el-dialog__header,
.external-tool-info-overlay .external-tool-info-dialog .el-dialog__footer {
  flex: 0 0 auto !important;
}

.external-tool-info-overlay .external-tool-info-dialog .el-dialog__body {
  flex: 1 1 auto !important;
  min-height: 0 !important;
  overflow: auto !important;
  padding-top: 12px !important;
}

@media (max-width: 768px), (max-height: 720px) {
  .external-tool-overlay .el-dialog {
    width: 100vw !important;
    max-width: 100vw !important;
    height: 100dvh !important;
    max-height: 100dvh !important;
    margin: 0 !important;
    border-radius: 0 !important;
  }

  .external-tool-overlay .el-dialog__header {
    padding: 14px 16px 10px !important;
  }

  .external-tool-overlay .el-dialog__body {
    padding: 10px 12px 12px !important;
  }

  .external-tool-overlay .external-tool-instance-table-shell {
    display: none !important;
  }

  .external-tool-overlay .external-tool-instance-card-shell {
    display: flex !important;
    flex: 1 1 auto !important;
    min-height: 0 !important;
    overflow: hidden !important;
  }

  .external-tool-overlay .external-tool-instance-card-list {
    display: grid !important;
    height: 100% !important;
    min-height: 0 !important;
    overflow-y: auto !important;
  }

  .external-tool-info-overlay .external-tool-info-dialog {
    width: 100vw !important;
    max-width: 100vw !important;
    height: 100dvh !important;
    max-height: 100dvh !important;
    margin: 0 !important;
    border-radius: 0 !important;
  }

  .external-tool-info-overlay .external-tool-info-dialog .el-dialog__header {
    padding: 14px 16px 10px !important;
  }

  .external-tool-info-overlay .external-tool-info-dialog .el-dialog__body {
    padding: 10px 16px 12px !important;
  }

  .external-tool-info-overlay .external-tool-info-dialog .el-dialog__footer {
    padding: 10px 16px 14px !important;
  }
}



</style>
