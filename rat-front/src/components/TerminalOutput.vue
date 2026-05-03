<template>
  <div
    class="terminal-output"
    :class="{ 'terminal-output-empty': !lines.length }"
    ref="terminalOutputRef"
  >
    <div v-if="!lines.length" class="terminal-empty">
      <div class="terminal-empty-title">Console ready</div>
      <div class="terminal-empty-text">
        Run a command to start streaming output from the selected device.
      </div>
    </div>

    <template v-else>
      <div
        v-for="block in terminalBlocks"
        :key="block.key"
        class="terminal-command-block"
        :class="{ 'terminal-command-block-actionable': canUseTerminalBlockActions(block) }"
      >
        <div
          v-if="block.commandLine"
          class="terminal-block-command-row"
        >
          <div
            class="terminal-line terminal-line-command"
            :class="`line-${block.commandLine.line.kind || 'default'}`"
          >
            <span class="terminal-prefix">$</span>
            <span class="terminal-text">{{ block.commandLine.line.text }}</span>
          </div>

          <el-dropdown
            v-if="canUseTerminalBlockActions(block)"
            trigger="click"
            placement="bottom-end"
            popper-class="terminal-output-action-dropdown"
            @command="handleTerminalBlockCommand(block, $event)"
          >
            <button
              class="terminal-block-more"
              type="button"
              title="Output actions"
              aria-label="Output actions"
              @click.stop
            >
              ⋯
            </button>

            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="copy-output">
                  Copy output
                </el-dropdown-item>
                <el-dropdown-item
                  command="save-output"
                  :disabled="isSavingTerminalBlock(block)"
                >
                  Save output
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>

        <template
          v-for="entry in block.bodyLines"
          :key="entry.index"
        >
          <template v-if="isCommandFinishedLine(entry.line)">
            <div
              v-if="getTerminalTailActionItems(lines, entry.index).length > 0"
              class="terminal-line"
              :class="`line-${entry.line.kind || 'default'}`"
            >
              <a
                v-for="(actionItem, actionIndex) in getTerminalTailActionItems(lines, entry.index)"
                :key="actionItem.key"
                href="#"
                class="table-action-link-aux terminal-text"
                :class="{ 'terminal-action-link-spaced': actionIndex > 0 }"
                @click.prevent.stop="handleTerminalActionClick(actionItem)"
              >
                [ {{ actionItem.type === 'preview' ? 'Preview' : 'View JSON' }} ]
              </a>
            </div>

            <div
              class="terminal-line"
              :class="`line-${entry.line.kind || 'default'}`"
            >
              <span class="terminal-text">{{ entry.line.text }}</span>
            </div>
          </template>

          <div
            v-else
            class="terminal-line"
            :class="`line-${entry.line.kind || 'default'}`"
          >
            <span
              v-if="entry.line.kind === 'command'"
              class="terminal-prefix"
            >$</span>

            <span class="terminal-text">{{ entry.line.text }}</span>

            <a
              v-for="(actionItem, actionIndex) in getTerminalInlineActionItems(lines, entry.index)"
              :key="actionItem.key"
              href="#"
              class="table-action-link-aux terminal-text"
              :class="{ 'terminal-action-link-spaced': actionIndex > 0 }"
              @click.prevent.stop="handleTerminalActionClick(actionItem)"
            >
              [ {{ actionItem.type === 'preview' ? 'Preview' : 'JSON' }} ]
            </a>
          </div>
        </template>
      </div>
    </template>
  </div>
</template>

<script>
import { ElMessage } from 'element-plus'

export default {
  name: 'TerminalOutput',

  props: {
    lines: {
      type: Array,
      default: () => [],
    },

    selectedId: {
      type: [String, Number],
      default: '',
    },

    currentConnection: {
      type: Object,
      default: null,
    },
  },

  emits: ['preview-artifact', 'open-json', 'artifact-saved'],

  data() {
    return {
      savingOutputBlockKeys: {},
    }
  },

    computed: {
    terminalBlocks() {
      const safeLines = Array.isArray(this.lines) ? this.lines : []
      const blocks = []
      let currentBlock = null

      safeLines.forEach((line, index) => {
        const entry = { line, index }
        const shouldStartNewBlock =
          !currentBlock ||
          line?.kind === 'command' ||
          this.isCommandFinishedLine(currentBlock.lines[currentBlock.lines.length - 1]?.line)

        if (shouldStartNewBlock) {
          currentBlock = {
            key: `terminal-block-${index}`,
            startIndex: index,
            commandLine: line?.kind === 'command' ? entry : null,
            lines: [],
          }
          blocks.push(currentBlock)
        }

        currentBlock.lines.push(entry)

        if (!currentBlock.commandLine && line?.kind === 'command') {
          currentBlock.commandLine = entry
        }
      })

      return blocks.map(block => {
        return {
          ...block,
          bodyLines: block.lines.filter(entry => entry.index !== block.commandLine?.index),
          endIndex: block.lines.length ? block.lines[block.lines.length - 1].index : block.startIndex,
        }
      })
    },
  },

  methods: {
    isFileReadyLine(line) {
      const text = line?.text || ''
      return text.startsWith('[File Ready]')
    },

    isCommandFinishedLine(line) {
      const text = line?.text || ''

      return (
        text.startsWith('[Command finished]') ||
        text.startsWith('[命令结束]')
      )
    },

    getTerminalInlineActionItems(lines, index) {
      const line = lines[index]
      if (!line) return []

      if (!this.isFileReadyLine(line)) return []

      const groupItems = this.getTerminalCommandGroupActionItems(lines, index) || []
      const usedKeysBefore = this.getUsedInlineActionKeysBeforeLine(lines, index)

      const previewItem = groupItems.find(item => {
        return item.type === 'preview' && !usedKeysBefore.has(item.key)
      })

      return previewItem ? [previewItem] : []
    },

    getTerminalTailActionItems(lines, index) {
      const line = lines[index]
      if (!line || !this.isCommandFinishedLine(line)) return []

      const groupItems = this.getTerminalCommandGroupActionItems(lines, index) || []
      const usedKeysUpToCurrent = this.getUsedInlineActionKeysUpToLine(lines, index)

      return groupItems.filter(item => !usedKeysUpToCurrent.has(item.key))
    },

    getUsedInlineActionKeysBeforeLine(lines, endIndexExclusive) {
      const used = new Set()

      for (let i = 0; i < endIndexExclusive; i += 1) {
        const line = lines[i]
        if (!this.isFileReadyLine(line)) continue

        const groupItems = this.getTerminalCommandGroupActionItems(lines, i) || []
        const previewItem = groupItems.find(item => item.type === 'preview' && !used.has(item.key))

        if (previewItem) {
          used.add(previewItem.key)
        }
      }

      return used
    },

    getUsedInlineActionKeysUpToLine(lines, endIndexInclusive) {
      const used = new Set()

      for (let i = 0; i <= endIndexInclusive; i += 1) {
        const line = lines[i]
        if (!this.isFileReadyLine(line)) continue

        const groupItems = this.getTerminalCommandGroupActionItems(lines, i) || []
        const previewItem = groupItems.find(item => item.type === 'preview' && !used.has(item.key))

        if (previewItem) {
          used.add(previewItem.key)
        }
      }

      return used
    },

    getTerminalCommandGroupStartIndex(lines, endIndex) {
      const safeLines = Array.isArray(lines) ? lines : []

      for (let i = endIndex; i >= 0; i -= 1) {
        const line = safeLines[i]
        if (!line) continue

        if (line.kind === 'command') {
          return i
        }

        if (i < endIndex && this.isCommandFinishedLine(line)) {
          return i + 1
        }
      }

      return 0
    },

    getTerminalCommandGroupLines(lines, endIndex) {
      const safeLines = Array.isArray(lines) ? lines : []
      if (!safeLines.length || endIndex < 0) return []

      const startIndex = this.getTerminalCommandGroupStartIndex(safeLines, endIndex)
      return safeLines.slice(startIndex, endIndex + 1)
    },

    getTerminalCommandGroupActionItems(lines, endIndex) {
      const groupLines = this.getTerminalCommandGroupLines(lines, endIndex)
      const result = []

      groupLines.forEach((item, itemIndex) => {
        if (!item) return

        if (item.isArtifactMessage && item.artifactInfo && item.artifactInfo.artifact_id) {
          result.push({
            type: 'preview',
            key: `preview:${item.artifactInfo.artifact_id}:${itemIndex}`,
            line: item,
          })
        }

        if (item.isJsonMessage) {
          result.push({
            type: 'json',
            key: `json:${endIndex}:${itemIndex}`,
            line: item,
          })
        }
      })

      return result
    },

    handleTerminalActionClick(actionItem) {
      if (!actionItem || !actionItem.line) return

      if (actionItem.type === 'preview') {
        this.previewTerminalArtifact(actionItem.line)
        return
      }

      if (actionItem.type === 'json') {
        this.$emit('open-json', actionItem.line)
      }
    },

    previewTerminalArtifact(line) {
      if (!line || !line.artifactInfo || !line.artifactInfo.artifact_id) {
        ElMessage.warning('No preview available')
        return
      }

      this.$emit('preview-artifact', line.artifactInfo)
    },

    scrollToBottom() {
      this.$nextTick(() => {
        const el = this.$refs.terminalOutputRef
        const isMobileLayout =
          typeof window !== 'undefined' &&
          window.matchMedia &&
          window.matchMedia('(max-width: 960px)').matches

        if (isMobileLayout) {
          const appScrollRoot = document.getElementById('app')
          const scrollRoot = appScrollRoot || document.scrollingElement || document.documentElement

          if (scrollRoot) {
            scrollRoot.scrollTop = scrollRoot.scrollHeight
          } else if (typeof window !== 'undefined') {
            window.scrollTo(0, document.documentElement.scrollHeight)
          }

          return
        }

        if (el) {
          el.scrollTop = el.scrollHeight
        }
      })
    },

    // terminal block

        getTerminalBlockCommandText(block) {
      const raw = String(block?.commandLine?.line?.text || '').trim()
      return raw.replace(/^>\s*/, '').trim()
    },

    normalizeTerminalOutputLineText(text) {
      const value = String(text ?? '')
      return value === ' ' ? '' : value
    },

    isTerminalScriptRunBlock(block) {
  const commandText = this.getTerminalBlockCommandText(block)
  return /^\[Run Script\]/i.test(commandText)
},

getTerminalBlockArtifactCategory(block) {
  return this.isTerminalScriptRunBlock(block)
    ? 'script_output'
    : 'command_output'
},

    getTerminalBlockOutputLineEntries(block) {
      const entries = Array.isArray(block?.bodyLines) ? block.bodyLines : []

      return entries.filter(entry => {
        const line = entry?.line
        if (!line) return false
        if (line.kind === 'command') return false
        if (this.isCommandFinishedLine(line)) return false
        return true
      })
    },

    getTerminalBlockOutputText(block) {
      return this.getTerminalBlockOutputLineEntries(block)
        .map(entry => this.normalizeTerminalOutputLineText(entry.line?.text))
        .join('\n')
    },

    canUseTerminalBlockActions(block) {
      if (!block || !block.commandLine) return false
      return this.getTerminalBlockOutputText(block).trim().length > 0
    },

    getTerminalBlockKey(block) {
      return String(block?.key || '')
    },

    isSavingTerminalBlock(block) {
      const key = this.getTerminalBlockKey(block)
      return !!(key && this.savingOutputBlockKeys[key])
    },

    setTerminalBlockSaving(block, value) {
      const key = this.getTerminalBlockKey(block)
      if (!key) return

      this.savingOutputBlockKeys = {
        ...this.savingOutputBlockKeys,
        [key]: !!value,
      }
    },

    handleTerminalBlockCommand(block, command) {
      const normalizedCommand = String(command || '').trim()

      if (normalizedCommand === 'copy-output') {
        this.copyTerminalBlockOutput(block)
        return
      }

      if (normalizedCommand === 'save-output') {
        this.saveTerminalBlockOutput(block)
      }
    },

    async copyTerminalBlockOutput(block) {
      const outputText = this.getTerminalBlockOutputText(block)

      if (!outputText.trim()) {
        ElMessage.warning('No output to copy')
        return
      }

      try {
        await this.copyTextToClipboard(outputText)
        ElMessage.success('Output copied')
      } catch (e) {
        ElMessage.error(e.message || 'Copy failed')
      }
    },

    async copyTextToClipboard(text) {
      if (
        typeof navigator !== 'undefined' &&
        navigator.clipboard &&
        typeof navigator.clipboard.writeText === 'function'
      ) {
        await navigator.clipboard.writeText(text)
        return
      }

      const textarea = document.createElement('textarea')
      textarea.value = text
      textarea.setAttribute('readonly', 'readonly')
      textarea.style.position = 'fixed'
      textarea.style.left = '-9999px'
      textarea.style.top = '-9999px'
      document.body.appendChild(textarea)
      textarea.select()

      const ok = document.execCommand('copy')
      document.body.removeChild(textarea)

      if (!ok) {
        throw new Error('Copy failed')
      }
    },

   buildTerminalOutputFilename(block) {
  const commandText = this.getTerminalBlockCommandText(block)
  const now = new Date()
  const pad = value => String(value).padStart(2, '0')
  const timestamp = [
    now.getFullYear(),
    pad(now.getMonth() + 1),
    pad(now.getDate()),
  ].join('') + '_' + [
    pad(now.getHours()),
    pad(now.getMinutes()),
    pad(now.getSeconds()),
  ].join('')

  const rawName = this.isTerminalScriptRunBlock(block)
    ? commandText.replace(/^\[Run Script\]\s*/i, '')
    : commandText

  const slug = String(rawName || 'output')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_.-]+/g, '_')
    .replace(/^[_\-.]+|[_\-.]+$/g, '')
    .slice(0, 48) || 'output'

  const prefix = this.isTerminalScriptRunBlock(block) ? 'script' : 'cmd'
  return `${prefix}_${timestamp}_${slug}.txt`
},

    buildTerminalOutputArtifactExtra(block) {
      const sourceCommand = this.getTerminalBlockCommandText(block)
      const outputEntries = this.getTerminalBlockOutputLineEntries(block)

return {
  source: this.isTerminalScriptRunBlock(block)
    ? 'script_terminal_inline_action'
    : 'terminal_inline_action',
  source_command: sourceCommand,
  wrapper_command: '',
  source_history_entry_id: '',
  source_task_id: '',
  saved_from: 'terminal_output',
  category: this.getTerminalBlockArtifactCategory(block),
  line_count: outputEntries.length,
  saved_at: new Date().toISOString(),
}
    },

    async saveTerminalBlockOutput(block) {
      if (this.isSavingTerminalBlock(block)) return

      const outputText = this.getTerminalBlockOutputText(block)
      if (!outputText.trim()) {
        ElMessage.warning('No output to save')
        return
      }

      const commandText = this.getTerminalBlockCommandText(block)
      const filename = this.buildTerminalOutputFilename(block)
const artifactCategory = this.getTerminalBlockArtifactCategory(block)
      const formData = new FormData()
      const blob = new Blob([outputText], { type: 'text/plain;charset=utf-8' })

      formData.append('file', blob, filename)
      formData.append('artifact_type', 'command_output')
      formData.append('category', artifactCategory)
      formData.append('client_id', String(this.selectedId || ''))
      formData.append('hostname', String(this.currentConnection?.hostname || ''))
      formData.append('machine_id', String(this.currentConnection?.machine_id || ''))
      formData.append('extra', JSON.stringify(this.buildTerminalOutputArtifactExtra(block)))

      this.setTerminalBlockSaving(block, true)

      try {
        const res = await fetch('/api/files/upload', {
          method: 'POST',
          body: formData,
        })
        const json = await res.json()

        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Save failed')
        }

        ElMessage.success('Saved to Command Output')
        this.$emit('artifact-saved', json.data || null)
      } catch (e) {
        ElMessage.error(e.message || 'Save failed')
      } finally {
        this.setTerminalBlockSaving(block, false)
      }
    },

    // scrollToBottom() {
    //   this.$nextTick(() => {
    //     const el = this.$refs.terminalOutputRef
    //     if (el) {
    //       el.scrollTop = el.scrollHeight
    //     }
    //   })
    // },
  },
}
</script>

<style scoped>
/* ========== 终端输出区 ========== */
.terminal-output {
  flex: 1;
  min-height: 0;
  overflow: auto;
  padding: 18px 18px 22px;
  color: var(--terminal-text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
  line-height: 1.7;
  scrollbar-width: thin;
  scrollbar-color: rgba(148, 163, 184, 0.35) rgba(15, 23, 42, 0.4);
}

.terminal-output::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}

.terminal-output::-webkit-scrollbar-track {
  background: rgba(15, 23, 42, 0.45);
}

.terminal-output::-webkit-scrollbar-thumb {
  background: rgba(148, 163, 184, 0.32);
  border-radius: 999px;
  border: 2px solid rgba(15, 23, 42, 0.45);
}

.terminal-output::-webkit-scrollbar-thumb:hover {
  background: rgba(148, 163, 184, 0.48);
}

.terminal-empty {
  min-height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  color: #8ea2c0;
  text-align: center;
}

.terminal-empty-title {
  font-size: 15px;
  font-weight: 700;
  color: #d7e2f2;
}

.terminal-empty-text {
  margin-top: 8px;
  max-width: 420px;
  line-height: 1.7;
}

.terminal-line {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 1px 0;
}


.terminal-action-link-spaced {
  margin-left: 10px;
}

.terminal-prefix {
  color: #60a5fa;
  font-weight: 700;
  flex-shrink: 0;
}

.terminal-text {
  min-width: 0;
}

.line-command .terminal-text {
  color: #bfdbfe;
}

.line-success .terminal-text {
  color: #86efac;
}

.line-error .terminal-text {
  color: #fda4af;
}

.line-info .terminal-text {
  color: #fcd34d;
}

.line-default .terminal-text {
  color: var(--terminal-text);
}



@media (max-width: 960px) {
  .terminal-output {
    min-height: 340px;
  }

  .terminal-output.terminal-output-empty .terminal-empty {
    min-height: 340px;
  }
}

/*terminal block*/
.terminal-command-block {
  position: relative;
  border-radius: 10px;
  margin: 0 -8px 2px;
  padding: 0 8px;
}

.terminal-command-block-actionable:hover {
  background: rgba(15, 23, 42, 0.22);
}

.terminal-block-command-row {
  position: relative;
  display: flex;
  align-items: flex-start;
  min-width: 0;
  padding-right: 28px;
}

.terminal-block-command-row .terminal-line {
  flex: 1;
  min-width: 0;
}

.terminal-line-command {
  padding-right: 28px;
}

.terminal-block-more {
  position: absolute;
  top: 4px;
  right: 0;
  width: 22px;
  height: 22px;
  padding: 0;
  border: 1px solid rgba(148, 163, 184, 0.12);
  border-radius: 999px;
  background: rgba(15, 23, 42, 0.32);
  color: rgba(203, 213, 225, 0.54);
  cursor: pointer;
  opacity: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  line-height: 18px;
  font-size: 15px;
  transform: translateY(-1px);
  transition:
      opacity 0.14s ease,
      background 0.14s ease,
      color 0.14s ease,
      border-color 0.14s ease;
}

.terminal-command-block:hover .terminal-block-more,
.terminal-block-more:focus-visible,
.terminal-block-more[aria-expanded='true'] {
  opacity: 1;
}

.terminal-block-more:hover,
.terminal-block-more:focus-visible {
  background: rgba(30, 41, 59, 0.92);
  color: rgba(248, 250, 252, 0.9);
  border-color: rgba(148, 163, 184, 0.28);
  outline: none;
}

:global(.terminal-output-action-dropdown .el-dropdown-menu__item) {
  font-size: 12px;
  padding: 0 13px;
}
</style>