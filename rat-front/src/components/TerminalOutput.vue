<template>
  <div class="terminal-output" ref="terminalOutputRef">
    <div v-if="!lines.length" class="terminal-empty">
      <div class="terminal-empty-title">Console ready</div>
      <div class="terminal-empty-text">
        Run a command to start streaming output from the selected device.
      </div>
    </div>

    <template v-else>
      <template v-for="(line, index) in lines" :key="index">
        <template v-if="isCommandFinishedLine(line)">
          <div
            v-if="getTerminalTailActionItems(lines, index).length > 0"
            class="terminal-line"
            :class="`line-${line.kind || 'default'}`"
          >
            <a
              v-for="(actionItem, actionIndex) in getTerminalTailActionItems(lines, index)"
              :key="actionItem.key"
              href="#"
              class="table-action-link-aux terminal-text"
              :class="{ 'terminal-action-link-spaced': actionIndex > 0 }"
              @click.prevent.stop="$emit('action-click', actionItem)"
            >
              [ {{ actionItem.type === 'preview' ? 'Preview' : 'View JSON' }} ]
            </a>
          </div>

          <div
            class="terminal-line"
            :class="`line-${line.kind || 'default'}`"
          >
            <span class="terminal-text">{{ line.text }}</span>
          </div>
        </template>

        <div
          v-else
          class="terminal-line"
          :class="[
            `line-${line.kind || 'default'}`,
            {
              'terminal-line-with-inline-action':
                getTerminalInlineActionItems(lines, index).length > 0,
            },
          ]"
        >
          <div class="terminal-line-content">
            <span
              v-if="line.kind === 'command'"
              class="terminal-prefix"
            >
              $
            </span>

            <span class="terminal-text">{{ line.text }}</span>
          </div>

          <div
            v-if="getTerminalInlineActionItems(lines, index).length > 0"
            class="terminal-line-inline-actions"
          >
            <a
              v-for="(actionItem, actionIndex) in getTerminalInlineActionItems(lines, index)"
              :key="actionItem.key"
              href="#"
              class="table-action-link-aux terminal-text"
              :class="{ 'terminal-action-link-spaced': actionIndex > 0 }"
              @click.prevent.stop="$emit('action-click', actionItem)"
            >
              [ {{ actionItem.type === 'preview' ? 'Preview' : 'JSON' }} ]
            </a>
          </div>
        </div>
      </template>
    </template>
  </div>
</template>

<script>
export default {
  name: 'TerminalOutput',

  props: {
    lines: {
      type: Array,
      default: () => [],
    },
  },

  emits: ['action-click'],

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

    scrollToBottom() {
      this.$nextTick(() => {
        const el = this.$refs.terminalOutputRef
        if (el) {
          el.scrollTop = el.scrollHeight
        }
      })
    },
  },
}
</script>

<style scoped>
/* 终端输出滚动容器 */
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
  margin-left: 12px;
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

@media (max-width: 640px) {
  .terminal-output {
    min-height: 340px;
    padding-bottom: calc(22px + env(safe-area-inset-bottom, 0px) + 24px);
  }
}
</style>