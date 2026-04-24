<template>
  <div class="terminal-topbar">
    <div class="terminal-topbar-left">
      <span class="dot dot-red"></span>
      <span class="dot dot-yellow"></span>
      <span class="dot dot-green"></span>
      <span class="terminal-title">Interactive Shell</span>
    </div>

    <div class="terminal-tools">
      <el-button
        size="small"
        class="tool-btn tool-btn-accent"
        @click="$emit('open-remote-files')"
      >
        Remote Files
      </el-button>

      <el-button
        size="small"
        class="tool-btn tool-btn-accent ml-0"
        @click="$emit('open-artifacts')"
      >
        Artifacts
      </el-button>

      <el-button
        size="small"
        class="tool-btn ml-0"
        @click="$emit('open-info')"
      >
        Info
      </el-button>

      <el-button
        size="small"
        class="tool-btn ml-0"
        @click="$emit('open-jobs')"
      >
        Jobs
      </el-button>

      <el-button
        size="small"
        class="tool-btn ml-0"
        @click="$emit('open-scripts')"
      >
        Scripts
      </el-button>

      <el-button
        size="small"
        class="tool-btn ml-0"
        @click="$emit('open-agents')"
      >
        Agents
      </el-button>

      <el-button
        size="small"
        class="tool-btn ml-0"
        @click="$emit('open-history')"
      >
        History
      </el-button>

      <el-button
        size="small"
        class="tool-btn ml-0"
        :disabled="!selectedId"
        @click="$emit('open-pty')"
      >
        PTY
      </el-button>

      <el-button
        size="small"
        class="tool-btn tool-btn-accent ml-0"
        @click="$emit('open-processes')"
      >
        Processes
      </el-button>

      <el-dropdown
        trigger="click"
        @command="$emit('control-action', $event)"
      >
        <el-button size="small" class="tool-btn tool-btn-accent">
          Control
        </el-button>

        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="kill">Force Kill</el-dropdown-item>
            <el-dropdown-item command="reset">Force Reset</el-dropdown-item>
            <el-dropdown-item command="spawn">Force Spawn</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>

      <el-button
        size="small"
        class="tool-btn tool-btn-danger"
        @click="$emit('disconnect')"
      >
        Disconnect
      </el-button>

      <span class="tool-separator"></span>

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
</template>

<script>
export default {
  name: 'TerminalToolbar',

  props: {
    selectedId: {
      type: [String, Number],
      default: '',
    },
  },

  emits: [
    'open-remote-files',
    'open-artifacts',
    'open-info',
    'open-jobs',
    'open-scripts',
    'open-agents',
    'open-history',
    'open-pty',
    'open-processes',
    'control-action',
    'disconnect',
    'clear',
    'bottom',
  ],
}
</script>