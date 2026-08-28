<template>
  <div class="terminal-topbar">
    <div class="terminal-topbar-left">
<!--      <span class="dot dot-red"></span>-->
<!--      <span class="dot dot-yellow"></span>-->
<!--      <span class="dot dot-green"></span>-->

<!--      <span class="dot dot-red"></span>-->
<!--<span class="dot dot-yellow"></span>-->
<!--<button-->
<!--  class="dot dot-green dot-action"-->
<!--  type="button"-->
<!--  title="Toggle connection info"-->
<!--  aria-label="Toggle connection info"-->
<!--  @click="$emit('toggle-connection-info')"-->
<!--/>-->


      <span class="dot dot-red"></span>
<span class="dot dot-yellow"></span>

<el-dropdown
  trigger="click"
  placement="bottom-start"
  popper-class="terminal-layout-dropdown"
  @command="handleLayoutCommand"
>
  <button
    class="dot dot-green dot-action"
    type="button"
    title="Layout quick actions"
    aria-label="Layout quick actions"
  />

  <template #dropdown>
    <el-dropdown-menu>
      <el-dropdown-item command="toggle-device-sidebar">
        {{ deviceSidebarCollapsed ? 'Show device sidebar' : 'Hide device sidebar' }}
      </el-dropdown-item>

      <el-dropdown-item command="toggle-connection-info">
        {{ connectionInfoCollapsed ? 'Show connection info card' : 'Hide connection info card' }}
      </el-dropdown-item>

      <el-dropdown-item
        command="hide-both"
        divided
        :disabled="deviceSidebarCollapsed && connectionInfoCollapsed"
      >
        Hide both
      </el-dropdown-item>
    </el-dropdown-menu>
  </template>
</el-dropdown>






      <span class="terminal-title">Interactive Shell</span>
    </div>

    <div class="terminal-tools">
      <template v-for="action in toolbarActions" :key="action.id">
        <el-button
          size="small"
          :class="['tool-btn', 'ml-0', { 'tool-btn-accent': action.accent }]"
          :disabled="isActionDisabled(action.id)"
          @click="runAction(action.id)"
        >
          {{ action.label }}
        </el-button>
      </template>

      <el-dropdown
        trigger="click"
        @command="handleMoreCommand"
      >
        <el-button
          size="small"
          class="tool-btn tool-btn-accent"
        >
          More
        </el-button>

        <template #dropdown>
          <el-dropdown-menu>
            <template v-for="action in moreActions" :key="action.id">
              <el-dropdown-item
                :command="`action:${action.id}`"
                :disabled="isActionDisabled(action.id)"
              >
                {{ action.label }}
              </el-dropdown-item>
            </template>

            <el-dropdown-item command="manage-toolbar" :divided="moreActions.length > 0">
              Manage Toolbar
            </el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>

      <el-button
        size="small"
        class="tool-btn tool-btn-danger"
        @click="killConnection"
        :disabled="deviceActionDisabled"
      >
        Disconnect
      </el-button>

      <span class="terminal-tool-separator"></span>

      <el-button
        size="small"
        class="tool-btn"
        @click="$emit('clear')"
      >
        Clear
      </el-button>

      <el-button
        size="small"
        class="tool-btn ml-0"
        @click="$emit('bottom')"
      >
        Bottom
      </el-button>
    </div>
  </div>

  <el-dialog
    v-model="manageToolbarVisible"
    title="Manage Toolbar"
    width="720px"
    :close-on-click-modal="false"
    append-to-body
  >
    <div class="toolbar-manager-note">
      Order items inside each section. Move less-used actions to More.
    </div>

    <div class="toolbar-manager-grid">
      <section class="toolbar-manager-section">
        <div class="toolbar-manager-title">Toolbar</div>
        <div class="toolbar-manager-list">
          <div
            v-for="(actionId, index) in draftPreferences.toolbar"
            :key="`toolbar-${actionId}`"
            class="toolbar-manager-row"
          >
            <span class="toolbar-manager-label">{{ actionLabel(actionId) }}</span>
            <div class="toolbar-manager-actions">
              <el-button size="small" text :disabled="index === 0" @click="moveDraftItem('toolbar', index, -1)">↑</el-button>
              <el-button size="small" text :disabled="index === draftPreferences.toolbar.length - 1" @click="moveDraftItem('toolbar', index, 1)">↓</el-button>
              <el-button size="small" @click="moveDraftItemAcross('toolbar', index)">To More</el-button>
            </div>
          </div>
        </div>
      </section>

      <section class="toolbar-manager-section">
        <div class="toolbar-manager-title">More</div>
        <div class="toolbar-manager-list">
          <div
            v-for="(actionId, index) in draftPreferences.more"
            :key="`more-${actionId}`"
            class="toolbar-manager-row"
          >
            <span class="toolbar-manager-label">{{ actionLabel(actionId) }}</span>
            <div class="toolbar-manager-actions">
              <el-button size="small" text :disabled="index === 0" @click="moveDraftItem('more', index, -1)">↑</el-button>
              <el-button size="small" text :disabled="index === draftPreferences.more.length - 1" @click="moveDraftItem('more', index, 1)">↓</el-button>
              <el-button size="small" @click="moveDraftItemAcross('more', index)">To Toolbar</el-button>
            </div>
          </div>
        </div>
      </section>
    </div>

    <template #footer>
      <div class="toolbar-manager-footer">
        <el-button @click="resetDraftPreferences">Reset Default</el-button>
        <span class="toolbar-manager-footer-spacer"></span>
        <el-button @click="manageToolbarVisible = false">Cancel</el-button>
        <el-button type="primary" :loading="savingToolbarPreferences" @click="saveManagedToolbar">
          Save
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script>
import { ElMessage, ElMessageBox } from 'element-plus'
import { killConnection as killConnectionApi } from '../api/connectionsApi.js'
import {
  loadToolbarPreferences,
  saveToolbarPreferences,
} from '../api/toolbarPreferencesApi.js'

const ACTION_CATALOG = [
  { id: 'remote-files', label: 'Remote Files', accent: true },
  { id: 'artifacts', label: 'Artifacts', accent: true },
  { id: 'info', label: 'Info' },
  { id: 'scripts', label: 'Scripts' },
  { id: 'history', label: 'History' },
  { id: 'pty', label: 'PTY' },
  { id: 'screen-view', label: 'Screen View' },
  { id: 'clipboard', label: 'Clipboard' },
  { id: 'external-tools', label: 'External Tools' },
  { id: 'jobs', label: 'Jobs' },
  { id: 'agents', label: 'Agents' },
  { id: 'processes', label: 'Processes' },
  { id: 'keychains', label: 'Keychains' },
  { id: 'one-liners', label: 'One-liners' },
]

const DEFAULT_TOOLBAR_PREFERENCES = {
  toolbar: [
    'remote-files',
    'artifacts',
    'info',
    'scripts',
    'history',
    'pty',
    'screen-view',
    'clipboard',
  ],
  more: [
    'external-tools',
    'jobs',
    'agents',
    'processes',
    'keychains',
    'one-liners',
  ],
}

function cloneToolbarPreferences(preferences) {
  return {
    toolbar: [...(preferences?.toolbar || [])],
    more: [...(preferences?.more || [])],
  }
}

export default {
  name: 'TerminalToolbar',

  props: {
    selectedId: {
      type: [String, Number],
      default: '',
    },
    currentConnectionOffline: {
      type: Boolean,
      default: false,
    },

    deviceSidebarCollapsed: {
      type: Boolean,
      default: false,
    },

    connectionInfoCollapsed: {
      type: Boolean,
      default: false,
    },
  },

  emits: [
    'layout-command',
    'open-remote-files',
    'open-artifacts',
    'open-external-tools',
    'open-keychains',
    'open-info',
    'open-jobs',
    'open-scripts',
    'open-agents',
    'open-history',
    'open-pty',
    'open-screen-view',
    'open-clipboard',
    'open-processes',
    'open-one-liners',
    'clear',
    'bottom',
  ],

  data() {
    const preferences = cloneToolbarPreferences(DEFAULT_TOOLBAR_PREFERENCES)
    return {
      toolbarPreferences: preferences,
      draftPreferences: cloneToolbarPreferences(preferences),
      manageToolbarVisible: false,
      savingToolbarPreferences: false,
    }
  },

  computed: {
    deviceActionDisabled() {
      return !this.selectedId || this.currentConnectionOffline
    },
    toolbarActions() {
      return this.actionsForIds(this.toolbarPreferences.toolbar)
    },
    moreActions() {
      return this.actionsForIds(this.toolbarPreferences.more)
    },
  },

  mounted() {
    this.loadManagedToolbar()
  },

  methods: {
    clonePreferences(preferences) {
      return cloneToolbarPreferences(preferences)
    },
    normalizePreferences(preferences) {
      const allowed = new Set(ACTION_CATALOG.map((item) => item.id))
      const used = new Set()
      const normalizeList = (value) => {
        if (!Array.isArray(value)) return []
        const result = []
        value.forEach((item) => {
          const id = String(item || '').trim()
          if (!allowed.has(id) || used.has(id)) return
          used.add(id)
          result.push(id)
        })
        return result
      }

      const normalized = {
        toolbar: normalizeList(preferences?.toolbar),
        more: normalizeList(preferences?.more),
      }

      ACTION_CATALOG.forEach((action) => {
        if (used.has(action.id)) return
        const section = DEFAULT_TOOLBAR_PREFERENCES.toolbar.includes(action.id) ? 'toolbar' : 'more'
        normalized[section].push(action.id)
        used.add(action.id)
      })

      return normalized
    },
    actionsForIds(ids) {
      const byId = new Map(ACTION_CATALOG.map((item) => [item.id, item]))
      return (ids || []).map((id) => byId.get(id)).filter(Boolean)
    },
    actionLabel(actionId) {
      return ACTION_CATALOG.find((item) => item.id === actionId)?.label || actionId
    },
    isActionDisabled(actionId) {
      return [
        'remote-files',
        'pty',
        'screen-view',
        'clipboard',
        'processes',
      ].includes(actionId) && this.deviceActionDisabled
    },
    async loadManagedToolbar() {
      try {
        const preferences = this.normalizePreferences(await loadToolbarPreferences())
        this.toolbarPreferences = preferences
        this.draftPreferences = this.clonePreferences(preferences)
      } catch (e) {
        this.toolbarPreferences = this.clonePreferences(DEFAULT_TOOLBAR_PREFERENCES)
        this.draftPreferences = this.clonePreferences(this.toolbarPreferences)
        ElMessage.warning(e.message || 'Failed to load toolbar preferences; using defaults')
      }
    },
    openManageToolbar() {
      this.draftPreferences = this.clonePreferences(this.toolbarPreferences)
      this.manageToolbarVisible = true
    },
    moveDraftItem(section, index, direction) {
      const items = this.draftPreferences[section]
      const targetIndex = index + direction
      if (!Array.isArray(items) || targetIndex < 0 || targetIndex >= items.length) return
      const next = [...items]
      const [item] = next.splice(index, 1)
      next.splice(targetIndex, 0, item)
      this.draftPreferences = {
        ...this.draftPreferences,
        [section]: next,
      }
    },
    moveDraftItemAcross(section, index) {
      const targetSection = section === 'toolbar' ? 'more' : 'toolbar'
      const sourceItems = [...(this.draftPreferences[section] || [])]
      const targetItems = [...(this.draftPreferences[targetSection] || [])]
      const [item] = sourceItems.splice(index, 1)
      if (!item) return
      targetItems.push(item)
      this.draftPreferences = {
        ...this.draftPreferences,
        [section]: sourceItems,
        [targetSection]: targetItems,
      }
    },
    resetDraftPreferences() {
      this.draftPreferences = this.clonePreferences(DEFAULT_TOOLBAR_PREFERENCES)
    },
    async saveManagedToolbar() {
      if (this.savingToolbarPreferences) return
      this.savingToolbarPreferences = true
      try {
        const saved = this.normalizePreferences(
          await saveToolbarPreferences(this.draftPreferences),
        )
        this.toolbarPreferences = saved
        this.draftPreferences = this.clonePreferences(saved)
        this.manageToolbarVisible = false
        ElMessage.success('Toolbar updated')
      } catch (e) {
        ElMessage.error(e.message || 'Failed to save toolbar preferences')
      } finally {
        this.savingToolbarPreferences = false
      }
    },

    async killConnection() {
      if (!this.selectedId) {
        ElMessage.warning('Please select a device')
        return
      }

      try {
        await ElMessageBox.confirm(
            'Disconnect current device?',
            'Confirm Disconnect',
            {
              type: 'warning',
              confirmButtonText: 'Disconnect',
              cancelButtonText: 'Cancel',
              confirmButtonClass: 'el-button--danger',
            },
        )

        await killConnectionApi(this.selectedId)

        ElMessage.success('Disconnect command sent')
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.message === 'cancel') {
          return
        }

        ElMessage.error(e.message || 'Disconnect failed')
      }
    },

    handleLayoutCommand(command) {
      this.$emit('layout-command', command)
    },

    runAction(actionId) {
      const normalizedAction = String(actionId || '').trim().toLowerCase()
      const resourceActions = [
        'external-tools',
        'keychains',
        'jobs',
        'agents',
        'processes',
        'one-liners',
      ]
      if (resourceActions.includes(normalizedAction)) {
        this.handleResourceCommand(normalizedAction)
        return
      }

      const eventMap = {
        'remote-files': 'open-remote-files',
        artifacts: 'open-artifacts',
        info: 'open-info',
        scripts: 'open-scripts',
        history: 'open-history',
        pty: 'open-pty',
        'screen-view': 'open-screen-view',
        clipboard: 'open-clipboard',
      }
      const eventName = eventMap[normalizedAction]
      if (!eventName) {
        ElMessage.warning('Unknown toolbar action')
        return
      }
      this.$emit(eventName)
    },
    handleMoreCommand(command) {
      const normalizedCommand = String(command || '').trim().toLowerCase()
      if (normalizedCommand === 'manage-toolbar') {
        this.openManageToolbar()
        return
      }
      if (normalizedCommand.startsWith('action:')) {
        this.runAction(normalizedCommand.slice('action:'.length))
        return
      }
      ElMessage.warning('Unknown toolbar action')
    },

    // Resources 下拉只负责打开资源类弹窗，不承载执行控制逻辑。
    handleResourceCommand(command) {
      const normalizedCommand = String(command || '').trim().toLowerCase()
      const eventMap = {
        'external-tools': 'open-external-tools',
        keychains: 'open-keychains',
        jobs: 'open-jobs',
        agents: 'open-agents',
        processes: 'open-processes',
        'one-liners': 'open-one-liners',
      }
      const eventName = eventMap[normalizedCommand]

      if (!eventName) {
        ElMessage.warning('Unknown resource action')
        return
      }

      this.$emit(eventName)
    },

    // Ops 下拉包含本地管理入口和通过 HTTP 独立通道下发的控制命令。
    async handleOpsCommand(command) {
      const normalizedCommand = String(command || '').trim().toLowerCase()

      const httpCommandMap = {
        'http-stop': 'stop',
        'http-restart': 'restart',
        'http-start': 'start',
      }
      const httpCommand = httpCommandMap[normalizedCommand]
      if (httpCommand) {
        await this.sendHttpControlCommand(httpCommand)
        return
      }

      ElMessage.warning('Unknown ops action')
    },
  }
}
</script>

<style scoped>
/* ========== 终端工具栏 ========== */
.terminal-topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 15px;
  border-bottom: 1px solid var(--terminal-line);
  background: rgba(255, 255, 255, 0.03);
  flex-shrink: 0;
}

.terminal-topbar-left {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
  flex-shrink: 0;
}

.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

.dot-red {
  background: #fb7185;
}

.dot-yellow {
  background: #fbbf24;
}

.dot-green {
  background: #34d399;
}

.terminal-title {
  margin-left: 4px;
  color: #e2e8f0;
  font-size: 13px;
  font-weight: 650;
  white-space: nowrap;
}

.terminal-tools {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  flex-wrap: wrap;
  min-width: 0;
}

.terminal-tool-separator {
  width: 1px;
  height: 18px;
  background: rgba(255, 255, 255, 0.12);
  flex: 0 0 auto;
}

.tool-btn.el-button {
  flex: 0 0 auto;
  min-height: 30px;
  height: 30px;
  padding-inline: 10px;
  font-size: 12px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.04);
  border-color: rgba(255, 255, 255, 0.08);
  color: #dbe4f3;
  margin: 0;
}

.tool-btn.tool-btn-accent.el-button {
  background: rgba(59, 130, 246, 0.16);
  border-color: rgba(96, 165, 250, 0.22);
  color: #dbeafe;
}

.tool-btn.tool-btn-danger.el-button {
  background: rgba(220, 38, 38, 0.12);
  border-color: rgba(248, 113, 113, 0.18);
  color: #fecaca;
}

@media (max-width: 1200px) {
  .terminal-topbar {
    align-items: flex-start;
    flex-direction: column;
  }

  .terminal-topbar-left,
  .terminal-tools {
    width: 100%;
  }

  .terminal-tools {
    justify-content: flex-start;
  }
}

@media (max-width: 640px) {
  .terminal-tools {
    gap: 6px;
  }

  .terminal-tool-separator {
    display: none;
  }

  .tool-btn.el-button {
    height: 30px;
    min-height: 30px;
    padding-inline: 10px;
    font-size: 12px;
  }
}

/*dot actions*/
.dot-action {
  padding: 0;
  border: none;
  appearance: none;
  cursor: pointer;
  flex: 0 0 auto;
  transition:
      transform 0.14s ease,
      filter 0.14s ease,
      box-shadow 0.14s ease;
}

.dot-action:hover {
  transform: scale(1.14);
  filter: brightness(1.08);
  box-shadow: 0 0 0 3px rgba(52, 211, 153, 0.14);
}

.dot-action:active {
  transform: scale(0.96);
}



/*disabled toolbar button*/
.tool-btn.el-button.is-disabled,
.tool-btn.el-button.is-disabled:hover,
.tool-btn.el-button.is-disabled:focus {
  background: rgba(148, 163, 184, 0.055) !important;
  border-color: rgba(148, 163, 184, 0.09) !important;
  color: rgba(203, 213, 225, 0.34) !important;
  opacity: 0.58;
  cursor: not-allowed;
  filter: grayscale(0.45);
  box-shadow: none;
}

.tool-btn.tool-btn-accent.el-button.is-disabled,
.tool-btn.tool-btn-accent.el-button.is-disabled:hover,
.tool-btn.tool-btn-accent.el-button.is-disabled:focus {
  background: rgba(59, 130, 246, 0.045) !important;
  border-color: rgba(96, 165, 250, 0.08) !important;
  color: rgba(191, 219, 254, 0.32) !important;
}

.tool-btn.tool-btn-danger.el-button.is-disabled,
.tool-btn.tool-btn-danger.el-button.is-disabled:hover,
.tool-btn.tool-btn-danger.el-button.is-disabled:focus {
  background: rgba(220, 38, 38, 0.045) !important;
  border-color: rgba(248, 113, 113, 0.08) !important;
  color: rgba(254, 202, 202, 0.32) !important;
}


.toolbar-manager-note {
  margin-bottom: 14px;
  font-size: 12px;
  opacity: .65;
}

.toolbar-manager-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 14px;
}

.toolbar-manager-section {
  min-width: 0;
  border: 1px solid var(--el-border-color-light);
  border-radius: 9px;
  overflow: hidden;
}

.toolbar-manager-title {
  padding: 10px 12px;
  font-size: 12px;
  font-weight: 650;
  border-bottom: 1px solid var(--el-border-color-lighter);
  background: var(--el-fill-color-light);
}

.toolbar-manager-list {
  min-height: 120px;
}

.toolbar-manager-row,
.toolbar-manager-actions,
.toolbar-manager-footer {
  display: flex;
  align-items: center;
}

.toolbar-manager-row {
  min-height: 44px;
  padding: 7px 10px 7px 12px;
  gap: 8px;
  border-bottom: 1px solid var(--el-border-color-lighter);
}

.toolbar-manager-row:last-child {
  border-bottom: 0;
}

.toolbar-manager-label {
  min-width: 0;
  flex: 1;
  font-size: 12px;
}

.toolbar-manager-actions {
  gap: 2px;
  flex: 0 0 auto;
}

.toolbar-manager-footer {
  width: 100%;
  gap: 8px;
}

.toolbar-manager-footer-spacer {
  flex: 1;
}
</style>