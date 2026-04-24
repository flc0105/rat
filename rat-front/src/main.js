import * as Vue from 'vue'
import { createApp } from 'vue'
import ElementPlus, {
  ElMessage,
  ElMessageBox,
  ElNotification,
  ElLoading,
} from 'element-plus'

import 'element-plus/dist/index.css'
import './assets/app.css'

import AppStateModule from './legacy/core/state.js'
import AppUtilsModule from './legacy/modules/utils.js'
import AppCommandsModule from './legacy/modules/commands.js'
import AppFilesModule from './legacy/modules/files.js'
import AppJobsModule from './legacy/modules/jobs.js'
import AppScriptsModule from './legacy/modules/scripts.js'
import AppSseModule from './legacy/modules/sse.js'
import AppAgentModule from './legacy/modules/agent.js'
import AppProcessModule from './legacy/modules/process.js'
import AppConnectionModule from './legacy/modules/connection.js'
import AppTaskModule from './legacy/modules/task.js'
import AppTerminalModule from './legacy/modules/terminal.js'
import AppPtyModule from './legacy/modules/pty.js'
import AppCandidatesModule from './legacy/modules/candidates.js'
import AppHistoryModule from './legacy/modules/history.js'
import AppArtifactsModule from './legacy/modules/artifacts.js'
import AppPreviewModule from './legacy/modules/preview.js'


window.Vue = Vue
// 先保留这个全局变量，因为很多旧模块里还在用 ElementPlus.ElMessage / ElMessageBox
window.ElementPlus = {
  ...ElementPlus,
  ElMessage,
  ElMessageBox,
  ElNotification,
  ElLoading,
}

createApp({
  data() {
    return {
      ...AppStateModule.data(),
      ...AppArtifactsModule.data(),
      ...AppAgentModule.data(),
      ...AppProcessModule.data(),
      ...AppFilesModule.data(),
      ...AppPreviewModule.data(),
      ...AppJobsModule.data(),
      ...AppScriptsModule.data(),
      ...AppCandidatesModule.data(),
      ...AppHistoryModule.data(),
      ...AppTerminalModule.data(),
      ...AppPtyModule.data(),
      ...AppConnectionModule.data(),
      ...AppCommandsModule.data(),
      ...AppTaskModule.data(),
      ...AppSseModule.data(),
    }
  },

  computed: {
    ...AppStateModule.computed,
    ...AppProcessModule.computed,
    ...AppAgentModule.computed,
    ...AppPreviewModule.computed,
    ...AppConnectionModule.computed,
    ...AppTerminalModule.computed,
    ...AppTaskModule.computed,
    ...AppHistoryModule.computed,
    ...AppFilesModule.computed,
    ...AppArtifactsModule.computed,
    ...AppJobsModule.computed,
    ...AppScriptsModule.computed,
  },

  watch: {
    ...AppStateModule.watch,
    ...AppAgentModule.watch,
    ...AppProcessModule.watch,
    ...AppTerminalModule.watch,
    ...AppPreviewModule.watch,
    ...AppFilesModule.watch,
    ...AppArtifactsModule.watch,
    ...AppJobsModule.watch,
    ...AppScriptsModule.watch,
    ...AppHistoryModule.watch,
  },

  methods: {
    ...AppUtilsModule.methods,
    ...AppCommandsModule.methods,
    ...AppFilesModule.methods,
    ...AppJobsModule.methods,
    ...AppScriptsModule.methods,
    ...AppSseModule.methods,
    ...AppAgentModule.methods,
    ...AppProcessModule.methods,
    ...AppConnectionModule.methods,
    ...AppTaskModule.methods,
    ...AppTerminalModule.methods,
    ...AppPtyModule.methods,
    ...AppCandidatesModule.methods,
    ...AppHistoryModule.methods,
    ...AppArtifactsModule.methods,
    ...AppPreviewModule.methods,
  },

  mounted() {
    this.ensureTabId()
    this.loadConnections()
    this.initSSE()

    this.statusTickTimer = setInterval(() => {
      this.statusNowTick = Date.now()
    }, 30 * 1000)
  },

  beforeUnmount() {
    if (this.eventSource) this.eventSource.close()

    if (this.backgroundJobsRefreshTimer) {
      clearTimeout(this.backgroundJobsRefreshTimer)
      this.backgroundJobsRefreshTimer = null
    }

    if (this.statusTickTimer) {
      clearInterval(this.statusTickTimer)
      this.statusTickTimer = null
    }
  },
})
  .use(ElementPlus)
  .mount('#app')