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
      <el-button
        size="small"
        class="tool-btn tool-btn-accent"
        @click="$emit('open-remote-files')"
        :disabled="deviceActionDisabled"
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
        @click="$emit('open-scripts')"
      >
        Scripts
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
        :disabled="deviceActionDisabled"
        @click="$emit('open-pty')"
      >
        PTY
      </el-button>

            <el-dropdown
        trigger="click"
        @command="handleResourceCommand"
      >
        <el-button
          size="small"
          class="tool-btn tool-btn-accent"
        >
          More
        </el-button>

        <template #dropdown>
          <el-dropdown-menu>

            <el-dropdown-item command="external-tools">External Tools</el-dropdown-item>
            <el-dropdown-item command="jobs">Jobs</el-dropdown-item>
            <el-dropdown-item command="agents">Agents</el-dropdown-item>
            <el-dropdown-item command="processes" :disabled="deviceActionDisabled">Processes</el-dropdown-item>
            <el-dropdown-item command="keychains">Keychains</el-dropdown-item>

          </el-dropdown-menu>
        </template>
      </el-dropdown>

<!--      <el-dropdown-->
<!--        trigger="click"-->
<!--        @command="handleOpsCommand"-->
<!--      >-->
<!--        <el-button-->
<!--          size="small"-->
<!--          class="tool-btn tool-btn-accent"-->
<!--        >-->
<!--          Ops-->
<!--        </el-button>-->

<!--        <template #dropdown>-->
<!--          <el-dropdown-menu>-->
<!--            <el-dropdown-item command="processes">Processes</el-dropdown-item>-->
<!--&lt;!&ndash;            <el-dropdown-item divided disabled>HTTP Cmd</el-dropdown-item>&ndash;&gt;-->
<!--<el-dropdown-item divided command="http-stop">HTTP Stop</el-dropdown-item>-->
<!--<el-dropdown-item command="http-restart">HTTP Restart</el-dropdown-item>-->
<!--<el-dropdown-item command="http-start">HTTP Start</el-dropdown-item>-->
<!--          </el-dropdown-menu>-->
<!--        </template>-->
<!--      </el-dropdown>-->

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
</template>

<script>
import { ElMessage, ElMessageBox } from 'element-plus'

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
    'open-processes',
    'clear',
    'bottom',
  ],

  computed: {
    deviceActionDisabled() {
      return !this.selectedId || this.currentConnectionOffline
    },
  },

  methods: {

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

        const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/kill`, {
          method: 'POST',
        })

        const json = await res.json()
        if (!res.ok || json.code !== 0) {
          throw new Error(json.message || 'Disconnect failed')
        }

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


    // async killConnection() {
    //   if (!this.selectedId) {
    //     ElMessage.warning('Please select a device')
    //     return
    //   }
    //
    //   try {
    //     const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/kill`, {
    //       method: 'POST',
    //     })
    //
    //     const json = await res.json()
    //     if (!res.ok || json.code !== 0) {
    //       throw new Error(json.message || 'Disconnect failed')
    //     }
    //
    //     ElMessage.success('Disconnect command sent')
    //   } catch (e) {
    //     ElMessage.error(e.message || 'Disconnect failed')
    //   }
    // },

    // Resources 下拉只负责打开资源类弹窗，不承载执行控制逻辑。
    handleResourceCommand(command) {
      const normalizedCommand = String(command || '').trim().toLowerCase()
      const eventMap = {
        'external-tools': 'open-external-tools',
        keychains: 'open-keychains',
        jobs: 'open-jobs',
        agents: 'open-agents',
        processes: 'open-processes',
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

      // if (normalizedCommand === 'processes') {
      //   this.$emit('open-processes')
      //   return
      // }

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

//     // add http control toolbar actions 2026-04-10 00:00
//     async sendHttpControlCommand(command) {
//       if (!this.selectedId) {
//         ElMessage.warning('Please select a device')
//         return
//       }
//
//       const normalizedCommand = String(command || '').trim().toLowerCase()
//       if (!normalizedCommand) {
//         ElMessage.warning('Invalid control command')
//         return
//       }
//
//       const actionMap = {
//         kill: 'Force Kill',
//         spawn: 'Force Spawn',
//         reset: 'Force Reset',
//       }
//       const actionLabel = actionMap[normalizedCommand]
//
//       try {
//         await ElMessageBox.confirm(
//           `Send ${actionLabel} to current device?\n\nThis action is delivered by polling and may take a short delay before the client receives it.`,
//           'Control Confirmation',
//           {
//             type: 'warning',
//             confirmButtonText: 'Confirm',
//             cancelButtonText: 'Cancel',
//           },
//         )
//
//         const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/control`, {
//           method: 'POST',
//           headers: { 'Content-Type': 'application/json' },
//           body: JSON.stringify({ command: normalizedCommand }),
//         })
//
//         const json = await res.json()
//         if (!res.ok || json.code !== 0) {
//           throw new Error(json.message || `${actionLabel} failed`)
//         }
//
//         ElMessage.success(`${actionLabel} command queued. This may take a short delay because the client checks by polling.`)
//       } catch (e) {
//         if (e === 'cancel' || e === 'close' || e?.message === 'cancel') {
//           return
//         }
//
//         ElMessage.error(e.message || 'Control command failed')
//       }
//     },
//   },
// }
//
// async sendHttpControlCommand(action) {
//   if (!this.selectedId) {
//     ElMessage.warning('Please select a device')
//     return
//   }
//
//   const normalizedAction = String(action || '').trim().toLowerCase()
//   const actionMap = {
//     stop: {
//       label: 'HTTP Stop',
//       wireCommand: 'kill',
//       description: 'stop the current client through the independent HTTP control channel',
//     },
//     restart: {
//       label: 'HTTP Restart',
//       wireCommand: 'reset',
//       description: 'restart the current client through the independent HTTP control channel',
//     },
//     start: {
//       label: 'HTTP Start',
//       wireCommand: 'spawn',
//       description: 'start a new client instance through the independent HTTP control channel',
//     },
//   }
//
//   const actionSpec = actionMap[normalizedAction]
//   if (!actionSpec) {
//     ElMessage.warning('Unsupported HTTP control action')
//     return
//   }
//
//   try {
//     await ElMessageBox.confirm(
//       `Send ${actionSpec.label} to current device?\n\nThis will ${actionSpec.description}. The client receives it through polling, so there may be a short delay.`,
//       'HTTP Control Confirmation',
//       {
//         type: 'warning',
//         confirmButtonText: 'Confirm',
//         cancelButtonText: 'Cancel',
//       },
//     )
//
//     const res = await fetch(`/api/connections/${encodeURIComponent(this.selectedId)}/control`, {
//       method: 'POST',
//       headers: { 'Content-Type': 'application/json' },
//       body: JSON.stringify({ command: actionSpec.wireCommand }),
//     })
//
//     const json = await res.json()
//     if (!res.ok || json.code !== 0) {
//       throw new Error(json.message || `${actionSpec.label} failed`)
//     }
//
//     ElMessage.success(`${actionSpec.label} queued through the HTTP control channel`)
//   } catch (e) {
//     if (e === 'cancel' || e === 'close' || e?.message === 'cancel') {
//       return
//     }
//
//     ElMessage.error(e.message || 'HTTP control action failed')
//   }
// },
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
</style>