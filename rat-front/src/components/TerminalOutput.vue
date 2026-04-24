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
              :style="actionIndex > 0 ? 'margin-left: 12px;' : ''"
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
              :style="actionIndex > 0 ? 'margin-left: 12px;' : ''"
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

    getTerminalTailActionItems: {
      type: Function,
      required: true,
    },

    getTerminalInlineActionItems: {
      type: Function,
      required: true,
    },
  },

  emits: ['action-click'],

  methods: {
    isCommandFinishedLine(line) {
      const text = line?.text || ''

      return (
        text.startsWith('[Command finished]') ||
        text.startsWith('[命令结束]')
      )
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