<template>
  <el-dialog
    v-model="visible"
    title="External Tool Manager"
    width="1120px"
    top="6vh"
    class="fixed-dialog external-tool-dialog"
    @closed="handleClosed"
  >
    <div class="external-tool-body" v-loading="loading">
      <div class="external-tool-toolbar">
        <div class="external-tool-toolbar-left">
          <el-button size="small" type="primary" plain :loading="loading" @click="loadCatalog">
            Refresh
          </el-button>
          <el-select v-model="sideFilter" size="small" class="external-tool-filter" placeholder="Side">
            <el-option label="All sides" value="" />
            <el-option label="Server" value="server" />
            <el-option label="Client" value="client" />
          </el-select>
          <el-select v-model="platformFilter" size="small" class="external-tool-filter" placeholder="Platform">
            <el-option label="All platforms" value="" />
            <el-option label="Current client" value="current" />
            <el-option label="Linux" value="linux" />
            <el-option label="macOS" value="mac" />
            <el-option label="Windows" value="win" />
            <el-option label="iOS" value="ios" />
          </el-select>
        </div>

        <div class="external-tool-toolbar-right">
          <el-input
            v-model="searchText"
            size="small"
            clearable
            class="external-tool-search"
            placeholder="Search external tools"
          />
        </div>
      </div>

      <div v-if="filteredItems.length" class="external-tool-list">
        <div
          v-for="item in filteredItems"
          :key="item.id"
          class="external-tool-card"
        >
          <div class="external-tool-card-main">
            <div class="external-tool-title-row">
              <div class="external-tool-title" :title="item.display_name || item.id">
                {{ item.display_name || item.id }}
              </div>
              <el-tag size="small" :type="item.side === 'server' ? 'success' : 'warning'">
                {{ item.side || '-' }}
              </el-tag>
              <el-tag size="small" type="info">
                {{ formatPlatforms(item.platforms) }}
              </el-tag>
              <el-tag v-if="item.version" size="small" type="info">
                v{{ item.version }}
              </el-tag>
              <el-tag v-if="item.arch" size="small" type="info">
                {{ item.arch }}
              </el-tag>
            </div>

            <div class="external-tool-desc" :title="item.description || ''">
              {{ item.description || 'No description' }}
            </div>

            <div class="external-tool-meta mono">
              <span>ID: {{ item.id }}</span>
              <span v-if="item.package?.filename">Package: {{ item.package.filename }}</span>
              <span v-if="item.package?.executable_rel_path">Exec: {{ item.package.executable_rel_path }}</span>
            </div>
          </div>

          <div class="external-tool-actions">
            <el-button size="small" plain @click="downloadTool(item)">
              Download Zip
            </el-button>

            <el-button
              v-if="item.side === 'server'"
              size="small"
              type="primary"
              plain
              :disabled="!isServerPlatformSupported(item)"
              @click="openRunDialog(item, 'server')"
            >
              Install & Run on Server
            </el-button>

            <el-button
              v-if="item.side === 'client'"
              size="small"
              type="primary"
              plain
              :disabled="!selectedId || !isClientPlatformSupported(item)"
              @click="openRunDialog(item, 'client')"
            >
              Install & Run on Client
            </el-button>
          </div>
        </div>
      </div>

      <div v-else class="external-tool-empty">
        {{ searchText ? 'No matching external tools' : 'No external tool meta files found' }}
      </div>
    </div>
  </el-dialog>

  <el-dialog
    v-model="runDialogVisible"
    :title="runDialogTitle"
    width="620px"
    append-to-body
    @closed="resetRunDialog"
  >
    <div v-if="pendingItem" class="external-tool-run-body">
      <div class="external-tool-run-summary">
        <div><strong>{{ pendingItem.display_name || pendingItem.id }}</strong></div>
        <div class="mono">{{ pendingItem.id }} / {{ pendingTargetSide }}</div>
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
            :min="param.min"
            :max="param.max"
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
      <el-button size="small" @click="runDialogVisible = false">Cancel</el-button>
      <el-button size="small" type="primary" :loading="submitting" @click="confirmRun">
        Install & Run
      </el-button>
    </template>
  </el-dialog>
</template>

<script>
import { ElMessage } from 'element-plus'

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
    getTabScopedHeaders: {
      type: Function,
      default: null,
    },
  },

  emits: [
    'append-output',
    'set-active-task',
  ],

  data() {
    return {
      visible: false,
      loading: false,
      submitting: false,
      items: [],
      searchText: '',
      sideFilter: '',
      platformFilter: '',
      runDialogVisible: false,
      pendingToolId: '',
      pendingTargetSide: '',
      paramForm: {},
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

    filteredItems() {
      const keyword = String(this.searchText || '').trim().toLowerCase()
      const side = String(this.sideFilter || '').trim().toLowerCase()
      const platform = String(this.platformFilter || '').trim().toLowerCase()
      return (this.items || []).filter((item) => {
        if (side && item.side !== side) return false
        if (platform) {
          const target = platform === 'current' ? this.currentClientPlatform : platform
          if (target && !this.doesPlatformMatch(item, target)) return false
        }
        if (!keyword) return true
        const values = [
          item.id,
          item.name,
          item.display_name,
          item.description,
          item.package?.filename,
          item.package?.executable_rel_path,
          (item.tags || []).join(' '),
        ].map(value => String(value || '').toLowerCase())
        return values.some(value => value.includes(keyword))
      })
    },

    pendingItem() {
      const target = String(this.pendingToolId || '').trim()
      return (this.items || []).find(item => String(item.id || '').trim() === target) || null
    },

    pendingParams() {
      return Array.isArray(this.pendingItem?.params) ? this.pendingItem.params : []
    },

    runDialogTitle() {
      const item = this.pendingItem
      const name = item ? (item.display_name || item.id) : 'External Tool'
      const side = this.pendingTargetSide === 'server' ? 'Server' : 'Client'
      return `Install & Run ${name} on ${side}`
    },
  },

  methods: {
    async open() {
      this.visible = true
      await this.loadCatalog()
    },

    isOpen() {
      return this.visible
    },

    async refreshIfOpen() {
      if (!this.visible) return
      await this.loadCatalog()
    },

    handleClosed() {
      this.resetRunDialog()
    },

    buildJsonHeaders(extra = {}) {
      if (typeof this.getTabScopedHeaders === 'function') {
        return this.getTabScopedHeaders(extra)
      }
      return extra
    },

    async loadCatalog() {
      this.loading = true
      try {
        const res = await fetch('/api/external-tools/catalog')
        const json = await res.json()
        if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to load external tools')
        const catalog = json.data || {}
        this.items = Array.isArray(catalog.items) ? catalog.items : []
      } catch (e) {
        ElMessage.error(e.message || 'Failed to load external tools')
      } finally {
        this.loading = false
      }
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
      const platforms = this.normalizePlatforms(item?.platforms || item?.platform)
      if (!target || platforms.includes('*')) return true
      return platforms.includes(target)
    },

    isServerPlatformSupported(item) {
      // Browser platform is not necessarily the server platform.
      // Keep server-side actions enabled and let the backend validate the real server OS.
      return !!item
    },

    isClientPlatformSupported(item) {
      return this.doesPlatformMatch(item, this.currentClientPlatform)
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

    normalizeParamType(type) {
      const value = String(type || 'string').trim().toLowerCase()
      if (value === 'int' || value === 'number') return 'integer'
      if (value === 'bool') return 'boolean'
      return value || 'string'
    },

    formatParamLabel(param) {
      const required = param.required ? ' *' : ''
      return `${param.name}${required}`
    },

    buildParamDefaults(item) {
      const form = {}
      for (const param of item?.params || []) {
        const name = String(param?.name || '').trim()
        if (!name) continue
        if (param.default !== undefined && param.default !== null) {
          form[name] = param.default
        } else if (this.normalizeParamType(param.type) === 'boolean') {
          form[name] = false
        } else {
          form[name] = ''
        }
      }
      return form
    },

    buildRunParams() {
      const params = {}
      for (const param of this.pendingParams || []) {
        const name = String(param?.name || '').trim()
        if (!name) continue
        const value = this.paramForm[name]
        if (param.required && (value === '' || value === undefined || value === null)) {
          throw new Error(`Param ${name} is required`)
        }
        params[name] = value
      }
      return params
    },

    openRunDialog(item, side) {
      this.pendingToolId = String(item?.id || '').trim()
      this.pendingTargetSide = side
      this.paramForm = this.buildParamDefaults(item)
      this.runDialogVisible = true
    },

    resetRunDialog() {
      this.runDialogVisible = false
      this.submitting = false
      this.pendingToolId = ''
      this.pendingTargetSide = ''
      this.paramForm = {}
    },

    downloadTool(item) {
      const id = String(item?.id || '').trim()
      if (!id) return
      window.open(`/api/external-tools/${encodeURIComponent(id)}/download`, '_blank')
    },

    async confirmRun() {
      const item = this.pendingItem
      if (!item) {
        this.resetRunDialog()
        return
      }

      try {
        this.submitting = true
        const params = this.buildRunParams()
        if (this.pendingTargetSide === 'server') {
          await this.runOnServer(item, params)
        } else {
          await this.runOnClient(item, params)
        }
        this.resetRunDialog()
      } catch (e) {
        ElMessage.error(e.message || 'Failed to run external tool')
      } finally {
        this.submitting = false
      }
    },

    async runOnServer(item, params) {
      this.$emit('append-output', this.selectedId, `> [External Tool: Server] ${item.display_name || item.id}`, 'command')
      const res = await fetch(`/api/external-tools/${encodeURIComponent(item.id)}/server/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ params }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to run server tool')
      const data = json.data || {}
      this.$emit('append-output', this.selectedId, `[External Tool Started] pid=${data.pid || '-'} log=${data.runtime?.stdout || '-'}`, 'info')
      ElMessage.success(data.message || 'External tool started on server')
    },

    async runOnClient(item, params) {
      if (!this.selectedId) {
        throw new Error('Please select a device')
      }
      this.$emit('append-output', this.selectedId, `> [External Tool: Client] ${item.display_name || item.id}`, 'command')
      const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/external-tools/${encodeURIComponent(item.id)}/run`, {
        method: 'POST',
        headers: this.buildJsonHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ params }),
      })
      const json = await res.json()
      if (!res.ok || json.code !== 0) throw new Error(json.message || 'Failed to run client tool')
      const taskId = json.data && json.data.task_id
      this.$emit('set-active-task', this.selectedId, taskId || '')
      ElMessage.success(`Run request submitted: ${item.display_name || item.id}`)
    },
  },
}
</script>

<style scoped>
.external-tool-body {
  min-height: 520px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.external-tool-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.external-tool-toolbar-left,
.external-tool-toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.external-tool-filter {
  width: 150px;
}

.external-tool-search {
  width: 260px;
}

.external-tool-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  max-height: 540px;
  overflow: auto;
  padding-right: 4px;
}

.external-tool-card {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding: 14px;
  border: 1px solid var(--terminal-line, rgba(255,255,255,.12));
  border-radius: 12px;
  background: rgba(255,255,255,.035);
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
  max-width: 360px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.external-tool-desc {
  margin-top: 8px;
  color: var(--terminal-muted, #8f9bb3);
  line-height: 1.45;
}

.external-tool-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 9px;
  color: var(--terminal-muted, #8f9bb3);
  font-size: 12px;
}

.external-tool-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 8px;
  min-width: 280px;
}

.external-tool-empty {
  padding: 48px 16px;
  text-align: center;
  color: var(--terminal-muted, #8f9bb3);
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
  background: rgba(255,255,255,.045);
  line-height: 1.6;
}

.external-tool-param-form {
  max-height: 420px;
  overflow: auto;
  padding-right: 4px;
}

.external-tool-number {
  width: 100%;
}

.external-tool-param-help {
  margin-top: 4px;
  color: var(--terminal-muted, #8f9bb3);
  font-size: 12px;
  line-height: 1.4;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
}
</style>
