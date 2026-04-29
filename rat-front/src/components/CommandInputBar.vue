<template>
  <div class="command-row">
    <div class="command-box command-box-full">
      <div class="command-autocomplete-shell">
        <el-autocomplete
          ref="commandInputRef"
          :model-value="modelValue"
          :fetch-suggestions="queryCommandCandidates"
          popper-class="command-autocomplete-popper"
          class="command-autocomplete"
          value-key="value"
          placeholder="Enter a command."
          autocomplete="off"
          @update:model-value="$emit('update:modelValue', $event)"
          @select="handleCandidateSelect"
          @keyup.enter="$emit('run')"
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
        @click="$emit('run')"
      >
        <span v-if="!sending && !hasRunningWebTask">Run</span>
        <span v-else-if="sending">...</span>
        <span v-else>Busy</span>
      </button>

      <el-button
        class="run-button cancel-button"
        :disabled="!hasRunningWebTask"
        :loading="currentTaskIsCancelling"
        @click="$emit('cancel')"
      >
        Cancel
      </el-button>
    </div>
  </div>
</template>

<script>
export default {
  name: 'CommandInputBar',

  props: {
    modelValue: {
      type: String,
      default: '',
    },

    sending: {
      type: Boolean,
      default: false,
    },

    hasRunningWebTask: {
      type: Boolean,
      default: false,
    },

    currentTaskIsCancelling: {
      type: Boolean,
      default: false,
    },

    commandCandidates: {
      type: Array,
      default: () => [],
    },

    currentConnection: {
      type: Object,
      default: null,
    },
  },

  emits: [
    'update:modelValue',
    'run',
    'cancel',
  ],

  methods: {
    queryCommandCandidates(queryString, callback) {
      const keyword = String(queryString || '').trim().toLowerCase()
      const sourceList = Array.isArray(this.commandCandidates) ? this.commandCandidates : []
      const visibleCandidates = this.filterExecScriptCandidatesByCurrentOs(sourceList)

      const quickHistoryShortcutCandidates = this.sortQuickHistoryShortcutCandidates(
        visibleCandidates.filter(item => item && item.source === 'quick_history_shortcut')
      )
      const normalCandidates = visibleCandidates.filter(item => !(item && item.source === 'quick_history_shortcut'))

      if (!keyword) {
        callback(normalCandidates)
        return
      }

      if (keyword.startsWith('!')) {
        if (keyword === '!') {
          callback(quickHistoryShortcutCandidates)
          return
        }

        const exactMatches = []
        const prefixMatches = []
        const textMatches = []

        quickHistoryShortcutCandidates.forEach(item => {
          const shortcutText = String(item.template || item.value || '').trim().toLowerCase()
          const commandText = String(item.quickHistoryCommand || item.help || '').trim().toLowerCase()
          const searchText = String(item.searchText || '').toLowerCase()

          if (shortcutText === keyword) {
            exactMatches.push(item)
            return
          }

          if (shortcutText.startsWith(keyword)) {
            prefixMatches.push(item)
            return
          }

          if (commandText.includes(keyword) || searchText.includes(keyword)) {
            textMatches.push(item)
          }
        })

        callback([
          ...this.sortQuickHistoryShortcutCandidates(exactMatches),
          ...this.sortQuickHistoryShortcutCandidates(prefixMatches),
          ...this.sortQuickHistoryShortcutCandidates(textMatches),
        ])
        return
      }

      const result = normalCandidates.filter(item => {
        const searchText = String(item.searchText || '').toLowerCase()
        return searchText.includes(keyword)
      })

      callback(result)
    },

    handleCandidateSelect(item) {
      if (!item) return
      this.$emit('update:modelValue', String(item.template || item.value || ''))
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
  display: flex;
  gap: 8px;
  align-items: center;
  min-width: 0;
}

.command-box-full {
  width: 100%;
}

.command-autocomplete-shell {
  flex: 1;
  width: 100%;
  min-width: 0;
}

.command-autocomplete,
.command-autocomplete :deep(.el-input),
.command-autocomplete :deep(.el-input__wrapper) {
  width: 100%;
  min-width: 0;
}

.command-autocomplete :deep(.el-input__wrapper) {
  height: 42px;
  padding: 0 14px;
  border-radius: 12px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  outline: none;
  background: rgba(255, 255, 255, 0.06) !important;
  box-shadow: none !important;
}

.command-autocomplete :deep(.el-input__wrapper:hover) {
  box-shadow: none !important;
}

.command-autocomplete :deep(.el-input__wrapper.is-focus) {
  border-color: rgba(96, 165, 250, 0.5);
  box-shadow: none !important;
}

.command-autocomplete :deep(.el-input__inner) {
  height: 100%;
  color: #f8fafc !important;
  font-size: 14px;
  background: transparent !important;
}

.command-autocomplete :deep(.el-input__inner::placeholder) {
  color: #8ea2c0 !important;
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
  border: 1px solid rgba(248, 113, 113, 0.36) !important;
  color: #fff !important;
}

.cancel-button:not(:disabled):not(.is-disabled):not(.is-loading):hover {
  background: #b91c1c !important;
  border-color: rgba(248, 113, 113, 0.52) !important;
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
  border-color: rgba(248, 113, 113, 0.42) !important;
  color: #fff !important;
  cursor: default !important;
  opacity: 1 !important;
}

:global(.command-autocomplete-popper) {
  background: #0f172a !important;
  border: 1px solid rgba(255, 255, 255, 0.08) !important;
  border-radius: 12px !important;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35) !important;
  overflow: hidden;
}

:global(.command-autocomplete-popper .el-autocomplete-suggestion__wrap) {
  padding: 8px 0;
  background: #0f172a !important;
}

:global(.command-autocomplete-popper .el-scrollbar),
:global(.command-autocomplete-popper .el-scrollbar__wrap),
:global(.command-autocomplete-popper .el-scrollbar__view) {
  background: #0f172a !important;
}

:global(.command-autocomplete-popper li) {
  padding: 0 12px !important;
  line-height: normal !important;
  background: #0f172a !important;
}

:global(.command-autocomplete-popper li:hover),
:global(.command-autocomplete-popper li.highlighted) {
  background: rgba(96, 165, 250, 0.12) !important;
}

:global(.command-autocomplete-popper .command-autocomplete-item) {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 2px;
}

:global(.command-autocomplete-popper .command-autocomplete-item-main) {
  min-width: 0;
  flex: 1;
}

:global(.command-autocomplete-popper .command-autocomplete-item-name) {
  max-width: 520px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #f8fafc !important;
  font-size: 14px;
  line-height: 1.5;
  font-weight: 600;
}

:global(.command-autocomplete-popper .command-autocomplete-item-desc) {
  max-width: 640px;
  margin-top: 4px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #8ea2c0 !important;
  font-size: 12px;
  line-height: 1.5;
}

:global(.command-autocomplete-popper .command-autocomplete-item-group) {
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

@media (max-width: 640px) {


  .run-button {
    width: 80px;
  }
}

/*
@media (max-width: 960px) {
  .command-row {
    position: sticky;
    top: 0;
    top: env(safe-area-inset-top, 0px);
    z-index: 80;
    background: rgba(2, 6, 23, 0.92);
    -webkit-backdrop-filter: blur(12px);
    backdrop-filter: blur(12px);
    box-shadow: 0 10px 24px rgba(2, 6, 23, 0.22);
  }


}
*/

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
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: 10px;
    align-items: stretch;
  }

  .command-autocomplete-shell {
    grid-column: 1 / -1;
    width: 100%;
    min-width: 0;
  }

  .command-autocomplete,
  .command-autocomplete :deep(.el-input),
  .command-autocomplete :deep(.el-input__wrapper),
  .command-autocomplete :deep(.el-textarea),
  .command-autocomplete :deep(.el-textarea__inner) {
    width: 100%;
    min-width: 0;
  }

  .command-autocomplete :deep(.el-input__wrapper) {
    height: 44px;
  }

  .command-autocomplete :deep(.el-textarea__inner),
  .command-autocomplete-shell textarea {
    min-height: 44px !important;
    height: auto !important;
    max-height: none !important;
    overflow-y: hidden !important;
    resize: none !important;
  }

  .run-button {
    width: 100%;
    height: 38px;
    /*height: 44px;*/
  }

  .run-button:not(.cancel-button) {
    grid-column: 1 / 2;
  }

  .cancel-button {
    grid-column: 2 / 3;
    margin-left: 0 !important;
  }
}

/*
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
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    align-items: stretch;
  }

  .command-autocomplete-shell {
    grid-column: 1 / -1;
    width: 100%;
  }

  .run-button {
    width: 100%;
    height: 44px;
  }

  .run-button:not(.cancel-button) {
    grid-column: 1 / 2;
  }

  .cancel-button {
    grid-column: 2 / 3;
    margin-left: 0 !important;
  }
}
 */
</style>