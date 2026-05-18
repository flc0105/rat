<template>
  <div class="command-row">
    <div class="command-box command-box-full">
      <div class="command-autocomplete-shell">
<el-autocomplete
  ref="commandInputRef"
  :model-value="commandText"
  :fetch-suggestions="queryCommandCandidates"
  :fit-input-width="true"
  popper-class="command-autocomplete-popper"
  class="command-autocomplete"
  value-key="value"
  placeholder="Enter a command."
  autocomplete="off"
  @update:model-value="handleCommandTextUpdate"
  @select="handleCandidateSelect"
  @keydown.capture="handleCommandInputKeydown"
>
          <template #default="{ item }">
            <div class="command-autocomplete-item">
              <div class="command-autocomplete-item-main">
                <div
                  class="command-autocomplete-item-name"
                  :title="item.template || item.value || '-'"
                >
                  {{ item.template || item.value || '-' }}
                </div>

                <div
                  v-if="item.help"
                  class="command-autocomplete-item-desc"
                  :title="item.help"
                >
                  {{ item.help }}
                </div>
              </div>

              <div
                v-if="item.groupLabel"
                class="command-autocomplete-item-group"
              >
                {{ item.groupLabel }}
              </div>
            </div>
          </template>
        </el-autocomplete>
      </div>

      <button
        class="run-button"
        :disabled="sending || hasRunningWebTask"
        @click="sendCommand"
      >
        <span v-if="!sending && !hasRunningWebTask">Run</span>
        <span v-else-if="sending">...</span>
        <span v-else>Busy</span>
      </button>

      <el-button
        class="run-button cancel-button"
        :disabled="!hasRunningWebTask"
        :loading="cancelSending"
        @click="cancelCurrentTask"
      >
        Cancel
      </el-button>
    </div>
  </div>
</template>

<script>
import { ElMessage } from 'element-plus'
import {
  sendCommand as sendCommandApi,
  getCommandCandidates,
  getCommandHistory,
  getCdDirectoryCandidates,
} from '../api/connectionsApi.js'
import { cancelTask } from '../api/tasksApi.js'
import {
  formatTerminalCancelRequestedLine,
  formatTerminalCommandFailedLine,
} from '../composables/terminalMarkers.js'

export default {
  name: 'CommandInputBar',


  props: {
    selectedId: {
      type: [String, Number],
      default: '',
    },

    currentConnection: {
      type: Object,
      default: null,
    },

    currentActiveTaskId: {
      type: [String, Number],
      default: '',
    },

    tabId: {
      type: String,
      default: '',
    },
  },

  emits: [
    'append-output',
    'set-active-task',
    'clear-output',
  ],

  data() {
    return {
      commandText: '',
      sending: false,
      cancelSending: false,
      commandCandidates: [],
      commandCandidatesLoadedFor: '',
      commandCandidatesLoadPromise: null,
      cdDirectoryCandidatesByContext: {},
      cdDirectoryCandidatesLoadPromises: {},
      cdDirectoryCandidateDebounceTimer: null,
      cdDirectoryCandidateDebounceResolve: null,
      cdDirectoryCandidateDebounceToken: 0,
      autocompleteCandidateItems: [],
      autocompleteCandidateQueryText: '',
      autocompleteNavigationBaseText: '',
      autocompleteNavigationIndex: -1,
      autocompleteNavigationPreviewActive: false,
    }
  },

  computed: {
    hasRunningWebTask() {
      return !!String(this.currentActiveTaskId || '').trim()
    },
  },

  watch: {
    selectedId: {
      immediate: true,
      handler(value, oldValue) {
        if (value !== oldValue) {
          this.cancelSending = false
          this.commandCandidates = []
          this.commandCandidatesLoadedFor = ''
          this.clearCdDirectoryCandidateCache()
        }

        if (value) {
          this.reloadCommandCandidates({ reset: true, silent: true })
        }
      },
    },

    currentActiveTaskId(value) {
      if (!value) {
        this.cancelSending = false
      }
    },

    'currentConnection.machine_id'(value, oldValue) {
      if (value !== oldValue && this.selectedId) {
        this.reloadCommandCandidates({ reset: true, silent: true })
      }
    },

    'currentConnection.cwd'(value, oldValue) {
      if (value !== oldValue) {
        this.clearCdDirectoryCandidateCache()
      }
    },
  },

  beforeUnmount() {
    this.clearCdDirectoryCandidateCache()
  },

  methods: {

    async sendCommand() {
  const command = String(this.commandText || '').trim()

  // add 暂时关闭命令自动补全下拉 2026-04-07
  this.closeAutocomplete()
  this.clearAutocompleteNavigationState()

  if (!command) {
    ElMessage.warning('Please enter a command')
    return
  }

  if (!this.selectedId) {
    ElMessage.warning('Please select a device')
    return
  }

  if (this.handleLocalFrontendCommand(command)) {
    return
  }

  this.sending = true
  this.$emit('append-output', this.selectedId, '> ' + command, 'command')

  try {
    const data = await sendCommandApi(this.selectedId, command, this.getTabScopedHeaders())
    const taskId = data && data.task_id
    this.$emit('set-active-task', this.selectedId, taskId || '')

    this.commandText = ''
    this.commandCandidatesLoadedFor = ''
    await this.loadCommandCandidates(this.selectedId)
  } catch (e) {
    this.$emit('append-output', this.selectedId, formatTerminalCommandFailedLine(e.message || 'unknown error'), 'error')
    ElMessage.error(e.message || 'Command failed')
    this.commandText = ''
  } finally {
    this.sending = false
  }
},

    // async sendCommand() {
    //   const command = String(this.commandText || '').trim()
    //
    //   // add 暂时关闭命令自动补全下拉 2026-04-07
    //   this.closeAutocomplete()
    //
    //   if (!this.selectedId) {
    //     ElMessage.warning('Please select a device')
    //     return
    //   }
    //
    //   if (!command) {
    //     ElMessage.warning('Please enter a command')
    //     return
    //   }
    //
    //   this.sending = true
    //   this.$emit('append-output', this.selectedId, '> ' + command, 'command')
    //
    //   try {
    //     const data = await sendCommandApi(this.selectedId, command, this.getTabScopedHeaders())
    //     const taskId = data && data.task_id
    //     this.$emit('set-active-task', this.selectedId, taskId || '')
    //
    //     this.commandText = ''
    //     this.commandCandidatesLoadedFor = ''
    //     await this.loadCommandCandidates(this.selectedId)
    //   } catch (e) {
    //     this.$emit('append-output', this.selectedId, formatTerminalCommandFailedLine(e.message || 'unknown error'), 'error')
    //     ElMessage.error(e.message || 'Command failed')
    //     this.commandText = ''
    //   } finally {
    //     this.sending = false
    //   }
    // },


    handleLocalFrontendCommand(command) {
  const normalizedCommand = String(command || '').trim().toLowerCase()

  const localCommandHandlers = {
    clear: () => {
      this.$emit('clear-output')
      this.commandText = ''
      ElMessage.success('Console cleared')
    },

    cls: () => {
      this.$emit('clear-output')
      this.commandText = ''
      ElMessage.success('Console cleared')
    },
  }

  const handler = localCommandHandlers[normalizedCommand]

  if (!handler) {
    return false
  }

  handler()
  return true
},

    async runCommandText(command) {
  const normalizedCommand = String(command || '').trim()
  if (!normalizedCommand) {
    ElMessage.warning('No command to run')
    return
  }

  this.commandText = normalizedCommand
  await this.sendCommand()
},

    async cancelCurrentTask() {
      if (!this.selectedId) {
        ElMessage.warning('Please select a device')
        return
      }

      const taskId = String(this.currentActiveTaskId || '').trim()
      if (!taskId) {
        ElMessage.warning('No running task')
        return
      }

      this.cancelSending = true

      try {
        await cancelTask(taskId)

        this.$emit('append-output', this.selectedId, formatTerminalCancelRequestedLine(taskId), 'info')
        ElMessage.success('Cancel request sent')
      } catch (e) {
        this.cancelSending = false
        ElMessage.error(e.message || 'Cancel failed')
      }
    },

    async queryCommandCandidates(queryString, callback) {
      const effectiveQueryString = this.getAutocompleteCandidateQueryString(queryString)
      const emitCandidates = (items) => {
        const list = Array.isArray(items) ? items : []
        this.setAutocompleteCandidateItems(list, effectiveQueryString)
        callback(list)
      }
      const cdQuery = this.parseCdDirectoryCandidateQuery(effectiveQueryString)

      if (cdQuery) {
        emitCandidates(await this.buildCdDirectoryCandidates(cdQuery))
        return
      }

      await this.ensureCommandCandidatesLoaded()

      const keyword = String(effectiveQueryString || '').trim().toLowerCase()
      const sourceList = Array.isArray(this.commandCandidates) ? this.commandCandidates : []
      const visibleCandidates = this.filterExecScriptCandidatesByCurrentOs(sourceList)

      const quickHistoryShortcutCandidates = this.sortQuickHistoryShortcutCandidates(
        visibleCandidates.filter(item => item && item.source === 'quick_history_shortcut'),
      )
      const normalCandidates = visibleCandidates.filter(item => !(item && item.source === 'quick_history_shortcut'))

      if (!keyword) {
        emitCandidates(normalCandidates)
        return
      }

      if (keyword.startsWith('!')) {
        emitCandidates(this.sortQuickHistoryShortcutCandidates(
          this.filterCandidatesByTitle(quickHistoryShortcutCandidates, keyword),
        ))
        return
      }

      emitCandidates(this.filterCandidatesByTitle(normalCandidates, keyword))
    },

    parseCdDirectoryCandidateQuery(queryString) {
      const rawText = String(queryString || '')
      const leftTrimmedText = rawText.trimStart()
      const match = leftTrimmedText.match(/^cd(?:\s+(.*))?$/i)

      if (!match) {
        return null
      }

      const argumentText = String(match[1] || '').trim()
      const pathParts = this.splitCdDirectoryCandidatePath(argumentText)

      return {
        rawText,
        argumentText,
        lookupPath: pathParts.lookupPath,
        candidatePrefix: pathParts.candidatePrefix,
        searchText: pathParts.searchText.toLowerCase(),
      }
    },

    splitCdDirectoryCandidatePath(argumentText) {
      const text = String(argumentText || '').trim()

      if (!text) {
        return {
          lookupPath: '',
          candidatePrefix: '',
          searchText: '',
        }
      }

      const lastForwardSlashIndex = text.lastIndexOf('/')
      const lastBackwardSlashIndex = text.lastIndexOf('\\')
      const lastSeparatorIndex = Math.max(lastForwardSlashIndex, lastBackwardSlashIndex)

      if (lastSeparatorIndex < 0) {
        return {
          lookupPath: '',
          candidatePrefix: '',
          searchText: text,
        }
      }

      const hasTrailingSeparator = lastSeparatorIndex === text.length - 1

      if (hasTrailingSeparator) {
        return {
          // 输入 cd a/b/ 时，候选目录应来自 a/b。
          lookupPath: text,
          candidatePrefix: text,
          searchText: '',
        }
      }

      return {
        // 输入 cd a/bc 时，候选目录应来自 a，并用 bc 做本地过滤。
        lookupPath: text.slice(0, lastSeparatorIndex),
        candidatePrefix: text.slice(0, lastSeparatorIndex + 1),
        searchText: text.slice(lastSeparatorIndex + 1),
      }
    },

    async buildCdDirectoryCandidates(cdQuery) {
      const cacheKey = this.buildCdDirectoryCandidateCacheKey(cdQuery.lookupPath)
      const cachedCandidates = this.cdDirectoryCandidatesByContext[cacheKey]

      if (Array.isArray(cachedCandidates)) {
        return this.filterCdDirectoryCandidates(cachedCandidates, cdQuery)
      }

      if (this.hasRunningWebTask) {
        return []
      }

      const shouldLoad = await this.waitForCdDirectoryCandidateDebounce()
      if (!shouldLoad || !this.isCurrentCdDirectoryCandidateQuery(cdQuery) || cacheKey !== this.buildCdDirectoryCandidateCacheKey(cdQuery.lookupPath)) {
        return []
      }

      const loadedCandidates = await this.loadCdDirectoryCandidatesForContext(cacheKey, cdQuery.lookupPath)
      if (!this.isCurrentCdDirectoryCandidateQuery(cdQuery) || cacheKey !== this.buildCdDirectoryCandidateCacheKey(cdQuery.lookupPath)) {
        return []
      }

      return this.filterCdDirectoryCandidates(loadedCandidates, cdQuery)
    },

    async waitForCdDirectoryCandidateDebounce() {
      this.cdDirectoryCandidateDebounceToken += 1
      const token = this.cdDirectoryCandidateDebounceToken

      if (this.cdDirectoryCandidateDebounceTimer) {
        clearTimeout(this.cdDirectoryCandidateDebounceTimer)
        this.cdDirectoryCandidateDebounceTimer = null
      }

      if (typeof this.cdDirectoryCandidateDebounceResolve === 'function') {
        this.cdDirectoryCandidateDebounceResolve(false)
      }

      return new Promise((resolve) => {
        this.cdDirectoryCandidateDebounceResolve = resolve
        this.cdDirectoryCandidateDebounceTimer = setTimeout(() => {
          this.cdDirectoryCandidateDebounceTimer = null
          this.cdDirectoryCandidateDebounceResolve = null
          resolve(token === this.cdDirectoryCandidateDebounceToken)
        }, 260)
      })
    },

    isCurrentCdDirectoryCandidateQuery(cdQuery) {
      const currentText = this.getAutocompleteCandidateQueryString(this.commandText)
      const currentQuery = this.parseCdDirectoryCandidateQuery(currentText)

      if (!currentQuery) {
        return false
      }

      return (
        currentQuery.lookupPath === cdQuery.lookupPath &&
        currentQuery.candidatePrefix === cdQuery.candidatePrefix &&
        currentQuery.searchText === cdQuery.searchText
      )
    },

    buildCdDirectoryCandidateCacheKey(lookupPath = '') {
      return [
        String(this.selectedId || '').trim(),
        this.getCurrentConnectionCwd(),
        String(lookupPath || '').trim(),
      ].join('::')
    },

    getCurrentConnectionCwd() {
      return String(this.currentConnection?.cwd || '').trim()
    },

    async loadCdDirectoryCandidatesForContext(cacheKey, lookupPath = '') {
      if (!this.selectedId || this.hasRunningWebTask) {
        return []
      }

      if (Array.isArray(this.cdDirectoryCandidatesByContext[cacheKey])) {
        return this.cdDirectoryCandidatesByContext[cacheKey]
      }

      if (this.cdDirectoryCandidatesLoadPromises[cacheKey]) {
        return this.cdDirectoryCandidatesLoadPromises[cacheKey]
      }

      // cd 候选按“当前正在补全的父目录”懒加载，避免输入每个字符都请求远端。
      this.cdDirectoryCandidatesLoadPromises[cacheKey] = getCdDirectoryCandidates(this.selectedId, lookupPath)
        .then((items) => {
          const normalizedItems = (Array.isArray(items) ? items : [])
            .map(item => this.normalizeCandidateItem(item))
            .filter(item => item.name)

          this.cdDirectoryCandidatesByContext = {
            ...this.cdDirectoryCandidatesByContext,
            [cacheKey]: normalizedItems,
          }

          return normalizedItems
        })
        .catch(() => [])
        .finally(() => {
          const nextPromises = { ...this.cdDirectoryCandidatesLoadPromises }
          delete nextPromises[cacheKey]
          this.cdDirectoryCandidatesLoadPromises = nextPromises
        })

      return this.cdDirectoryCandidatesLoadPromises[cacheKey]
    },

    buildCdDirectoryCandidateForDisplay(item, cdQuery) {
      const name = String(item?.name || '').trim()
      const candidatePath = `${String(cdQuery?.candidatePrefix || '')}${name}`
      const template = `cd ${candidatePath}`.trim()
      const helpTarget = String(item?.path || candidatePath).trim()

      return this.normalizeCandidateItem({
        ...item,
        name,
        template,
        value: template,
        help: helpTarget ? `Change directory -> ${helpTarget}` : 'Change directory',
        group: item?.group || 'filesystem',
        source: item?.source || 'cd_directory',
        cdCandidatePath: candidatePath,
      })
    },

    filterCdDirectoryCandidates(candidates, cdQuery) {
      const keyword = String(cdQuery?.searchText || '').trim().toLowerCase()
      const list = Array.isArray(candidates) ? candidates : []

      if (!keyword) {
        return list
          .slice(0, 50)
          .map(item => this.buildCdDirectoryCandidateForDisplay(item, cdQuery))
      }

      const prefixMatches = []
      const textMatches = []

      list.forEach((item) => {
        const displayItem = this.buildCdDirectoryCandidateForDisplay(item, cdQuery)
        const directoryName = String(displayItem.name || '').toLowerCase()
        const titleText = this.getCandidateTitleSearchText(displayItem)

        if (directoryName.startsWith(keyword)) {
          prefixMatches.push(displayItem)
          return
        }

        if (titleText.includes(keyword)) {
          textMatches.push(displayItem)
        }
      })

      return [
        ...prefixMatches,
        ...textMatches,
      ].slice(0, 50)
    },

    clearCdDirectoryCandidateCache() {
      if (this.cdDirectoryCandidateDebounceTimer) {
        clearTimeout(this.cdDirectoryCandidateDebounceTimer)
        this.cdDirectoryCandidateDebounceTimer = null
      }

      if (typeof this.cdDirectoryCandidateDebounceResolve === 'function') {
        this.cdDirectoryCandidateDebounceResolve(false)
      }

      this.cdDirectoryCandidateDebounceResolve = null
      this.cdDirectoryCandidatesByContext = {}
      this.cdDirectoryCandidatesLoadPromises = {}
    },

    handleCommandTextUpdate(value) {
      this.clearAutocompleteNavigationState()
      this.autocompleteCandidateQueryText = ''
      this.commandText = String(value || '')
    },

    handleCommandInputKeydown(event) {
      const key = String(event?.key || '')

      if (key === 'ArrowDown' || key === 'ArrowUp') {
        if (this.previewAutocompleteCandidateByArrowKey(key)) {
          event.preventDefault()
          event.stopPropagation()
        }
        return
      }

      if (key === 'Escape' && this.autocompleteNavigationPreviewActive) {
        event.preventDefault()
        event.stopPropagation()
        this.restoreAutocompleteNavigationBaseText()
        return
      }

      if (key === 'Enter' && !event?.isComposing) {
        event.preventDefault()
        event.stopPropagation()
        this.handleCommandEnterKeydown()
      }
    },

    handleCommandEnterKeydown() {
      if (this.autocompleteNavigationPreviewActive) {
        this.clearAutocompleteNavigationState()
        this.closeAutocomplete()
        this.sendCommand()
        return
      }

      const highlightedCandidate = this.getHighlightedAutocompleteCandidate()

      if (highlightedCandidate) {
        this.applyAutocompleteCandidateToInput(highlightedCandidate)
        this.closeAutocomplete()
        return
      }

      this.sendCommand()
    },

    handleCandidateSelect(item) {
      if (!item) return
      this.applyAutocompleteCandidateToInput(item)
    },

    getAutocompleteCandidateQueryString(queryString) {
      if (this.autocompleteNavigationPreviewActive) {
        return this.autocompleteNavigationBaseText
      }

      return String(queryString || '')
    },

    setAutocompleteCandidateItems(items, queryString = '') {
      this.autocompleteCandidateItems = Array.isArray(items) ? items : []
      this.autocompleteCandidateQueryText = String(queryString || '')
    },

    clearAutocompleteNavigationState() {
      this.autocompleteNavigationBaseText = ''
      this.autocompleteNavigationIndex = -1
      this.autocompleteNavigationPreviewActive = false
    },

    restoreAutocompleteNavigationBaseText() {
      const baseText = this.autocompleteNavigationBaseText
      this.clearAutocompleteNavigationState()
      this.commandText = baseText
      this.closeAutocomplete()
    },

    previewAutocompleteCandidateByArrowKey(key) {
      const candidates = Array.isArray(this.autocompleteCandidateItems) ? this.autocompleteCandidateItems : []

      const expectedQueryString = this.getAutocompleteCandidateQueryString(this.commandText)

      if (!candidates.length || this.autocompleteCandidateQueryText !== expectedQueryString) {
        return false
      }

      const currentIndex = this.autocompleteNavigationPreviewActive
        ? this.autocompleteNavigationIndex
        : this.getAutocompleteHighlightedIndex()
      const nextIndex = key === 'ArrowUp'
        ? this.getPreviousAutocompleteCandidateIndex(currentIndex, candidates.length)
        : this.getNextAutocompleteCandidateIndex(currentIndex, candidates.length)
      const nextCandidate = candidates[nextIndex]
      const nextCommandText = this.getCandidateInsertText(nextCandidate)

      if (!nextCommandText) {
        return false
      }

      // 导航预览只改 input 展示，候选列表仍按原始输入过滤，避免选不到后续项。
      if (!this.autocompleteNavigationPreviewActive) {
        this.autocompleteNavigationBaseText = String(this.commandText || '')
      }

      this.autocompleteNavigationPreviewActive = true
      this.autocompleteNavigationIndex = nextIndex
      this.commandText = nextCommandText
      this.highlightAutocompleteCandidate(nextIndex)

      return true
    },

    getPreviousAutocompleteCandidateIndex(currentIndex, total) {
      if (!Number.isInteger(currentIndex) || currentIndex <= 0) {
        return total - 1
      }

      return currentIndex - 1
    },

    getNextAutocompleteCandidateIndex(currentIndex, total) {
      if (!Number.isInteger(currentIndex) || currentIndex < 0 || currentIndex >= total - 1) {
        return 0
      }

      return currentIndex + 1
    },

    getHighlightedAutocompleteCandidate() {
      const candidates = Array.isArray(this.autocompleteCandidateItems) ? this.autocompleteCandidateItems : []
      const index = this.getAutocompleteHighlightedIndex()

      if (index < 0 || index >= candidates.length) {
        return null
      }

      return candidates[index]
    },

    getAutocompleteHighlightedIndex() {
      const input = this.$refs.commandInputRef
      const index = Number.parseInt(input?.highlightedIndex, 10)

      if (Number.isInteger(index)) {
        return index
      }

      return -1
    },

    highlightAutocompleteCandidate(index) {
      this.$nextTick(() => {
        const input = this.$refs.commandInputRef

        if (input && typeof input.highlight === 'function') {
          input.highlight(index)
        }
      })
    },

    applyAutocompleteCandidateToInput(item) {
      const text = this.getCandidateInsertText(item)

      if (!text) return

      this.clearAutocompleteNavigationState()
      this.commandText = text
      this.focusInput()
    },

    getCandidateInsertText(item) {
      return String(item?.template || item?.value || item?.name || '').trim()
    },

    filterCandidatesByTitle(candidates, keyword) {
      const normalizedKeyword = String(keyword || '').trim().toLowerCase()
      const exactMatches = []
      const prefixMatches = []
      const textMatches = []

      ;(Array.isArray(candidates) ? candidates : []).forEach((item) => {
        const titleText = this.getCandidateTitleSearchText(item)

        if (!titleText) return

        if (titleText === normalizedKeyword) {
          exactMatches.push(item)
          return
        }

        if (titleText.startsWith(normalizedKeyword)) {
          prefixMatches.push(item)
          return
        }

        if (titleText.includes(normalizedKeyword)) {
          textMatches.push(item)
        }
      })

      return [
        ...exactMatches,
        ...prefixMatches,
        ...textMatches,
      ]
    },

    getCandidateTitleText(item) {
      return String(item?.template || item?.value || item?.name || '').trim()
    },

    getCandidateTitleSearchText(item) {
      return this.getCandidateTitleText(item).toLowerCase()
    },

    async ensureCommandCandidatesLoaded() {
      if (!this.selectedId) return

      if (this.commandCandidatesLoadedFor === this.selectedId && this.commandCandidates.length) {
        return
      }

      await this.loadCommandCandidates(this.selectedId)
    },

    async reloadCommandCandidates(options = {}) {
      if (options?.reset) {
        this.commandCandidatesLoadedFor = ''
      }

      if (!this.selectedId) return

      await this.loadCommandCandidates(this.selectedId)
    },

    async loadCommandCandidates(clientId) {
      if (!clientId) return

      if (this.commandCandidatesLoadPromise) {
        return this.commandCandidatesLoadPromise
      }

      this.commandCandidatesLoadPromise = this.loadCommandCandidatesInternal(clientId)
        .finally(() => {
          this.commandCandidatesLoadPromise = null
        })

      return this.commandCandidatesLoadPromise
    },

    async loadCommandCandidatesInternal(clientId) {
      const historyMachineId = this.resolveCommandHistoryMachineId(clientId)

      try {
        const [candidateData, historyData] = await Promise.all([
          getCommandCandidates(clientId),
          getCommandHistory(historyMachineId),
        ])

        const systemCandidates = Array.isArray(candidateData) ? candidateData : []
const historyItems = Array.isArray(historyData) ? historyData : []
const pinnedHistoryItems = historyItems.filter(item => item && item.is_pinned)

        // const systemCandidates = Array.isArray(candidateJson.data) ? candidateJson.data : []
        // const historyItems = Array.isArray(historyJson.data) ? historyJson.data : []

        const merged = []
        const seen = new Set()

        const pushUniqueCandidate = (item) => {
          const normalized = this.normalizeCandidateItem(item)
          const template = normalized.template

          if (!template || seen.has(template)) return
          seen.add(template)
          merged.push(normalized)
        }

        const visibleSystemCandidates = systemCandidates.filter(item => item.suggest !== false)

        const clientCandidates = visibleSystemCandidates.filter(
          item => item.source === 'client' && item.group !== 'acmd',
        )
        const acmdCandidates = visibleSystemCandidates.filter(
          item => item.source === 'client' && item.group === 'acmd',
        )
        const serverCandidates = visibleSystemCandidates.filter(item => item.source === 'server')
        const aliasCandidates = visibleSystemCandidates.filter(item => item.source === 'alias')
        const scriptCandidates = visibleSystemCandidates.filter(item => item.source === 'script')
        const commonOpsCandidates = this.buildCommonOpsCandidates()

        clientCandidates.forEach(pushUniqueCandidate)
        acmdCandidates.forEach(pushUniqueCandidate)
        serverCandidates.forEach(pushUniqueCandidate)
        commonOpsCandidates.forEach(pushUniqueCandidate)
        aliasCandidates.forEach(pushUniqueCandidate)
        scriptCandidates.forEach(pushUniqueCandidate)

        // historyItems.forEach((item) => {
        //   const command = String(item.command || '').trim()
        //   if (!command || seen.has(command)) return
        //
        //   seen.add(command)
        //   merged.push(this.normalizeCandidateItem({
        //     name: command,
        //     template: command,
        //     help: 'Recent command',
        //     source: 'history',
        //     group: 'history',
        //   }))
        // })

        pinnedHistoryItems.forEach((item) => {
  const command = String(item.command || '').trim()
  if (!command || seen.has(command)) return

  seen.add(command)
  merged.push(this.normalizeCandidateItem({
    name: command,
    template: command,
    help: 'Pinned recent command',
    source: 'history',
    group: 'history',
  }))
})

        // this.buildQuickHistoryShortcutCandidates(historyItems).forEach((item) => {
        //   merged.push(item)
        // })


        this.buildQuickHistoryShortcutCandidates(pinnedHistoryItems).forEach((item) => {
  merged.push(item)
})

        this.commandCandidates = merged
        this.commandCandidatesLoadedFor = clientId
      } catch (_error) {
        this.commandCandidates = []
        this.commandCandidatesLoadedFor = ''
      }
    },

    resolveCommandHistoryMachineId(clientId) {
      if (String(this.currentConnection?.client_id || '') !== String(clientId || '')) {
        return ''
      }

      return String(this.currentConnection?.machine_id || '').trim()
    },

    buildCommonOpsCandidates() {
      return [
        {
          name: 'whoami',
          template: 'whoami',
          help: 'Show current user',
          source: 'common_ops',
          group: 'common_ops',
        },
        {
          name: 'hostname',
          template: 'hostname',
          help: 'Show host name',
          source: 'common_ops',
          group: 'common_ops',
        },
        {
          name: 'mkdir',
          template: 'mkdir ',
          help: 'Create a directory',
          source: 'common_ops',
          group: 'common_ops',
        },
        {
          name: 'rmdir',
          template: 'rmdir ',
          help: 'Remove an empty directory',
          source: 'common_ops',
          group: 'common_ops',
        },
      ]
    },

    buildCandidateGroupLabel(item) {
      const groupText = String(item.group || item.source || '').trim()
      if (!groupText) return ''
      return groupText
    },

    normalizeCandidateItem(item) {
      const rawValue = String(item.value || '').trim()
      const template = String(item.template || rawValue || '').trim()
      const name = String(item.name || template || rawValue || '').trim()
      const help = String(item.help || '').trim()
      const group = String(item.group || '').trim()
      const source = String(item.source || '').trim()
      const groupLabel = this.buildCandidateGroupLabel(item)
      const titleText = this.getCandidateTitleText({ template, value: rawValue, name })

      return {
        ...item,
        value: template,
        name,
        template,
        help,
        group,
        source,
        groupLabel,
        searchText: titleText.toLowerCase(),
      }
    },

    buildQuickHistoryShortcutCandidates(historyItems) {
      const items = Array.isArray(historyItems) ? historyItems : []

      return items
        .map((item) => {
          const indexValue = Number.parseInt(item && item.index, 10)
          const commandText = String((item && item.command) || '').trim()

          if (!Number.isInteger(indexValue) || indexValue <= 0 || !commandText) {
            return null
          }

          const shortcutText = `!${indexValue}`
          return {
            name: shortcutText,
            value: shortcutText,
            template: shortcutText,
            help: commandText,
            source: 'quick_history_shortcut',
            group: 'quick_history',
            groupLabel: 'quick_history',
            quickHistoryIndex: indexValue,
            quickHistoryCommand: commandText,
            searchText: shortcutText.toLowerCase(),
          }
        })
        .filter(Boolean)
    },

    filterExecScriptCandidatesByCurrentOs(candidates) {
      const currentOsAlias = this.normalizeCurrentOsAlias(this.currentConnection?.os_alias)

      if (!currentOsAlias) {
        return Array.isArray(candidates) ? candidates : []
      }

      return (Array.isArray(candidates) ? candidates : []).filter(item => {
        return this.shouldShowCandidateForCurrentOs(item, currentOsAlias)
      })
    },

    shouldShowCandidateForCurrentOs(item, currentOsAlias) {
      if (!this.isExecScriptCandidate(item)) {
        return true
      }

      const scriptRoot = this.getExecScriptRoot(item)
      if (!scriptRoot) {
        return false
      }

      const normalizedRoot = this.normalizeExecScriptRoot(scriptRoot)

      return normalizedRoot === 'common' || normalizedRoot === currentOsAlias
    },

    isExecScriptCandidate(item) {
      if (!item) return false

      const source = String(item.source || '').trim().toLowerCase()
      const group = String(item.group || '').trim().toLowerCase()
      const groupLabel = String(item.groupLabel || '').trim().toLowerCase()
      const commandText = this.getCandidateCommandText(item)

      return (
        source === 'script' ||
        group === 'script' ||
        groupLabel === 'script' ||
        /^exec\s+/i.test(commandText)
      )
    },

    getCandidateCommandText(item) {
      return String(item?.template || item?.value || item?.name || '').trim()
    },

    getExecScriptRoot(item) {
      const commandText = this.getCandidateCommandText(item)
      const match = commandText.match(/^exec\s+(.+)$/i)

      if (!match) return ''

      const scriptPath = this.stripCommandArgumentQuotes(match[1])
        .replace(/\\/g, '/')
        .trim()

      return scriptPath.split('/').filter(Boolean)[0] || ''
    },

    stripCommandArgumentQuotes(value) {
      const text = String(value || '').trim()
      if (!text) return ''

      const firstChar = text[0]
      const quoteChars = ['"', "'"]

      if (!quoteChars.includes(firstChar)) {
        return text.split(/\s+/)[0] || ''
      }

      const endIndex = text.indexOf(firstChar, 1)
      if (endIndex === -1) {
        return text.slice(1)
      }

      return text.slice(1, endIndex)
    },

    normalizeCurrentOsAlias(value) {
      const text = String(value || '').trim().toLowerCase()

      if (!text) return ''
      if (['windows', 'win', 'win32', 'nt'].includes(text)) return 'win'
      if (['darwin', 'mac', 'macos', 'osx'].includes(text)) return 'mac'
      if (['linux', 'ubuntu', 'debian', 'centos', 'fedora', 'redhat', 'rhel', 'alpine', 'arch'].includes(text)) return 'linux'
      if (['ios', 'iphone', 'ipad', 'iphoneos', 'ipados'].includes(text)) return 'ios'

      if (text.includes('win')) return 'win'
      if (text.includes('darwin') || text.includes('mac')) return 'mac'
      if (text.includes('linux')) return 'linux'
      if (/(ubuntu|debian|centos|fedora|redhat|rhel|alpine|arch)/.test(text)) return 'linux'
      if (text.includes('ios') || text.includes('iphone') || text.includes('ipad')) return 'ios'

      return text
    },

    normalizeExecScriptRoot(value) {
      const text = String(value || '').trim().toLowerCase()

      if (!text) return ''
      if (['common', 'shared'].includes(text)) return 'common'
      if (['windows', 'win', 'win32', 'nt'].includes(text)) return 'win'
      if (['darwin', 'mac', 'macos', 'osx'].includes(text)) return 'mac'
      if (['linux', 'ubuntu', 'debian', 'centos', 'fedora', 'redhat', 'rhel', 'alpine', 'arch'].includes(text)) return 'linux'
      if (['ios', 'iphone', 'ipad', 'iphoneos', 'ipados'].includes(text)) return 'ios'

      return text
    },

    sortQuickHistoryShortcutCandidates(items) {
      const list = Array.isArray(items) ? [...items] : []

      return list.sort((a, b) => {
        const ai = Number.parseInt(a && a.quickHistoryIndex, 10)
        const bi = Number.parseInt(b && b.quickHistoryIndex, 10)

        const av = Number.isInteger(ai) ? ai : Number.MAX_SAFE_INTEGER
        const bv = Number.isInteger(bi) ? bi : Number.MAX_SAFE_INTEGER

        return av - bv
      })
    },

    getTabScopedHeaders(extra = {}) {
      const headers = { ...extra }
      const normalizedTabId = String(this.tabId || '').trim()

      if (normalizedTabId) {
        headers['X-Tab-Id'] = normalizedTabId
      }

      return headers
    },

    setCommandText(value) {
      this.commandText = String(value || '')
      this.focusInput()
    },

    focusInput() {
      const input = this.$refs.commandInputRef

      if (input && typeof input.focus === 'function') {
        input.focus()
      }
    },

    closeAutocomplete() {
      const input = this.$refs.commandInputRef

      if (input && typeof input.close === 'function') {
        input.close()
      }
    },
  },
}
</script>

<style scoped>
/* 命令输入栏 */
.command-row {
  display: block;
  padding: 14px 15px;
  border-bottom: 1px solid var(--terminal-line);
  background: rgba(2, 6, 23, 0.34);
  flex-shrink: 0;
}

.command-box {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 88px 88px;
  gap: 10px;
  align-items: center;
  min-width: 0;
}

.command-box-full {
  width: 100%;
}

.command-autocomplete-shell {
  width: 100%;
  min-width: 0;
}

.run-button {
  width: 88px;
  height: 42px;
  border: none;
  outline: none;
  border-radius: 12px;
  background: #2563eb;
  color: #fff;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
}

.run-button:not(:disabled):not(.is-disabled):hover {
  background: #1d4ed8;
}

.run-button:disabled,
.run-button.is-disabled {
  background: rgba(71, 85, 105, 0.72) !important;
  border: 1px solid rgba(148, 163, 184, 0.16) !important;
  color: rgba(226, 232, 240, 0.52) !important;
  cursor: not-allowed !important;
  opacity: 1 !important;
  box-shadow: none !important;
}

.cancel-button {
  background: #dc2626 !important;
  color: #fff !important;
}

.cancel-button:not(:disabled):not(.is-disabled):not(.is-loading):hover {
  background: #b91c1c !important;
  color: #fff !important;
}

.cancel-button:disabled,
.cancel-button.is-disabled {
  background: rgba(127, 29, 29, 0.34) !important;
  border: 1px solid rgba(248, 113, 113, 0.16) !important;
  color: rgba(254, 202, 202, 0.46) !important;
  cursor: not-allowed !important;
  opacity: 1 !important;
  box-shadow: none !important;
}

.cancel-button.is-loading {
  background: #b91c1c !important;
  color: #fff !important;
  cursor: default !important;
  opacity: 1 !important;
}

@media (max-width: 640px) {
  .command-box {
    grid-template-columns: minmax(0, 1fr) 80px 80px;
  }

  .run-button {
    width: 80px;
  }
}

@media (max-width: 960px) {
  .command-row {
    position: sticky;
    top: 0;
    top: env(safe-area-inset-top, 0px);
    z-index: 80;
    padding: 12px 12px 14px;
    background: rgba(2, 6, 23, 0.92);
    -webkit-backdrop-filter: blur(12px);
    backdrop-filter: blur(12px);
    box-shadow: 0 10px 24px rgba(2, 6, 23, 0.22);
  }

  .command-box {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: 10px;
    align-items: stretch;
  }

  .command-autocomplete-shell {
    grid-column: 1 / -1;
    width: 100%;
    min-width: 0;
  }

  .run-button {
    width: 100%;
    height: 38px;
  }

  .run-button:not(.cancel-button) {
    grid-column: 1 / 2;
  }

  .cancel-button {
    grid-column: 2 / 3;
    margin-left: 0 !important;
  }
}
</style>

<style>
/* CommandInputBar: Element Plus 内部输入框样式必须放非 scoped，避免 el-input 内部 DOM 吃不到样式。 */
.command-autocomplete,
.command-autocomplete .el-input,
.command-autocomplete .el-input__wrapper {
  width: 100%;
  min-width: 0;
}

.command-autocomplete .el-input__wrapper {
  height: 42px;
  padding: 0 14px;
  border-radius: 12px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  outline: none;
  background: rgba(255, 255, 255, 0.06) !important;
  box-shadow: none !important;
}

.command-autocomplete .el-input__wrapper:hover {
  box-shadow: none !important;
}

.command-autocomplete .el-input__wrapper.is-focus {
  border-color: rgba(96, 165, 250, 0.5);
  box-shadow: none !important;
}

.command-autocomplete .el-input__inner {
  height: 100%;
  color: #f8fafc !important;
  font-size: 14px;
  background: transparent !important;
}

.command-autocomplete .el-input__inner::placeholder {
  color: #8ea2c0 !important;
}

.command-autocomplete-popper {
  background: #0f172a !important;
  border: 1px solid rgba(255, 255, 255, 0.08) !important;
  border-radius: 12px !important;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35) !important;
  overflow: hidden;
}

.command-autocomplete-popper .el-autocomplete-suggestion__wrap {
  padding: 8px 0;
  background: #0f172a !important;
}

.command-autocomplete-popper .el-scrollbar,
.command-autocomplete-popper .el-scrollbar__wrap,
.command-autocomplete-popper .el-scrollbar__view {
  background: #0f172a !important;
}

.command-autocomplete-popper li {
  padding: 0 12px !important;
  line-height: normal !important;
  background: #0f172a !important;
}

.command-autocomplete-popper li:hover,
.command-autocomplete-popper li.highlighted {
  background: rgba(96, 165, 250, 0.12) !important;
}

.command-autocomplete-popper .command-autocomplete-item {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 2px;
}

.command-autocomplete-popper .command-autocomplete-item-main {
  min-width: 0;
  flex: 1;
}

.command-autocomplete-popper .command-autocomplete-item-name,
.command-autocomplete-popper .command-autocomplete-item-desc {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.command-autocomplete-popper .command-autocomplete-item-name {
  max-width: 520px;
  color: #f8fafc !important;
  font-size: 14px;
  line-height: 1.5;
  font-weight: 600;
}

.command-autocomplete-popper .command-autocomplete-item-desc {
  max-width: 640px;
  margin-top: 4px;
  color: #8ea2c0 !important;
  font-size: 12px;
  line-height: 1.5;
}

.command-autocomplete-popper .command-autocomplete-item-group {
  flex-shrink: 0;
  align-self: center;
  color: #60a5fa !important;
  font-size: 12px;
  line-height: 1.4;
  padding: 2px 8px;
  border-radius: 999px;
  background: rgba(37, 99, 235, 0.12) !important;
  border: 1px solid rgba(96, 165, 250, 0.18);
}

/*
//@media (max-width: 960px) {
//  .command-autocomplete,
//  .command-autocomplete .el-input,
//  .command-autocomplete .el-input__wrapper,
//  .command-autocomplete .el-textarea,
//  .command-autocomplete .el-textarea__inner {
//    width: 100%;
//    min-width: 0;
//  }
//
//  .command-autocomplete .el-input__wrapper {
//    height: 44px;
//  }
//
//  .command-autocomplete .el-textarea__inner,
//  .command-autocomplete-shell textarea {
//    min-height: 44px !important;
//    height: auto !important;
//    max-height: none !important;
//    overflow-y: hidden !important;
//    resize: none !important;
//  }
//}
*/

@media (max-width: 960px) {
  .command-autocomplete,
  .command-autocomplete .el-input,
  .command-autocomplete .el-input__wrapper,
  .command-autocomplete .el-textarea,
  .command-autocomplete .el-textarea__inner {
    width: 100%;
    min-width: 0;
  }

  .command-autocomplete .el-input__wrapper {
    height: 44px;
  }

  .command-autocomplete .el-textarea__inner,
  .command-autocomplete-shell textarea {
    min-height: 44px !important;
    height: auto !important;
    max-height: none !important;
    overflow-y: hidden !important;
    resize: none !important;
  }

  .command-autocomplete-popper {
    width: calc(100vw - 24px) !important;
    max-width: calc(100vw - 24px) !important;
    min-width: 0 !important;
    box-sizing: border-box;
  }

  .command-autocomplete-popper .el-autocomplete-suggestion,
  .command-autocomplete-popper .el-autocomplete-suggestion__wrap,
  .command-autocomplete-popper .el-scrollbar,
  .command-autocomplete-popper .el-scrollbar__wrap,
  .command-autocomplete-popper .el-scrollbar__view {
    width: 100% !important;
    max-width: 100% !important;
    min-width: 0 !important;
    box-sizing: border-box;
  }

  .command-autocomplete-popper .command-autocomplete-item-name,
  .command-autocomplete-popper .command-autocomplete-item-desc {
    max-width: calc(100vw - 120px);
  }
}
</style>