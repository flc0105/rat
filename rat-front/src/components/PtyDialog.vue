<template>
  <el-dialog
    :model-value="visible"
    title="Remote PTY"
    width="900px"
    top="6vh"
    class="fixed-dialog pty-dialog"
    @update:model-value="$emit('update:visible', $event)"
    @closed="$emit('closed')"
  >
    <div class="pty-shell">
      <div class="pty-toolbar">
        <div class="pty-toolbar-left">
          <span class="pty-badge">
            {{ currentConnection ? (currentConnection.hostname || currentConnection.client_id) : 'No device' }}
          </span>

          <span class="pty-badge pty-badge-status">
            {{ ptyStatus || 'idle' }}
          </span>

          <span
            v-if="ptyError"
            class="pty-error-text"
          >
            {{ ptyError }}
          </span>
        </div>

        <div class="pty-toolbar-right">
          <el-input
            :model-value="shellPath"
            size="small"
            placeholder="Optional shell path"
            class="pty-shell-input"
            @update:model-value="$emit('update:shell-path', $event)"
          />

          <el-button
            size="small"
            @click="$emit('focus')"
          >
            Focus
          </el-button>

          <el-button
            size="small"
            @click="$emit('close')"
          >
            Close
          </el-button>
        </div>
      </div>

      <div
        class="pty-screen-shell xterm-shell"
        @click="$emit('focus')"
      >
        <div
          ref="ptyTerminalRef"
          class="pty-terminal-host"
        />
      </div>

      <div class="pty-hint">
        Powered by xterm.js. Supports ANSI control sequences, vim/less/top style full-screen apps, sudo prompts, paste and resize.
      </div>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'PtyDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    currentConnection: {
      type: Object,
      default: null,
    },

    ptyStatus: {
      type: String,
      default: '',
    },

    ptyError: {
      type: String,
      default: '',
    },

    shellPath: {
      type: String,
      default: '',
    },
  },

  emits: [
    'update:visible',
    'update:shell-path',
    'closed',
    'focus',
    'close',
  ],

  methods: {
    getTerminalHost() {
      return this.$refs.ptyTerminalRef || null
    },
  },
}
</script>