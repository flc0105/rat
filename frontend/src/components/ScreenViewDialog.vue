<template>
  <el-dialog
    v-model="visible"
    title="Screen View"
    :width="screenDialogWidth"
    :top="screenDialogTop"
    append-to-body
    :class="screenDialogClass"
    modal-class="screen-view-overlay"
    @close="handleDialogClose"
    @closed="handleDialogClosed"
  >
    <div class="screen-view-body">
      <div class="screen-view-toolbar">
        <div class="screen-view-toolbar-left">
          <span class="screen-view-target" :title="targetLabel">{{ targetLabel }}</span>
          <el-tag size="small" :type="statusTagType">{{ displayStatus }}</el-tag>
          <span v-if="frameWidth && frameHeight" class="screen-view-meta">
            {{ frameWidth }}×{{ frameHeight }}
          </span>
          <span v-if="frameBytes" class="screen-view-meta">{{ formatFrameBytes(frameBytes) }}/frame</span>
        </div>

        <div class="screen-view-toolbar-right">
          <span class="screen-view-control-label">FPS</span>
          <el-select
            v-model="fps"
            size="small"
            class="screen-view-fps-select"
            :disabled="!screenSessionId || settingsSaving"
            @change="applySettings"
          >
            <el-option v-for="value in fpsOptions" :key="value" :label="`${value} fps`" :value="value" />
          </el-select>

          <span class="screen-view-control-label">Quality</span>
          <el-select
            v-model="quality"
            size="small"
            class="screen-view-quality-select"
            :disabled="!screenSessionId || settingsSaving"
            @change="applySettings"
          >
            <el-option
              v-for="item in qualityOptions"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>

          <span class="screen-view-control-label">Control</span>
          <el-switch
            v-model="controlEnabled"
            size="small"
            :disabled="!controlAvailable"
            @change="handleControlToggle"
          />

          <el-button size="small" :loading="loading" @click="restartView">
            Restart
          </el-button>
          <el-button size="small" @click="toggleFullscreen">
            {{ fullscreen ? 'Exit Fullscreen' : 'Fullscreen' }}
          </el-button>
        </div>
      </div>

      <div
        ref="screenCanvas"
        class="screen-view-canvas"
        :class="{ 'screen-view-canvas-control': controlEnabled }"
        :tabindex="controlEnabled ? 0 : -1"
        v-loading="loading && !frameSrc"
        @pointermove="handlePointerMove"
        @pointerdown="handlePointerDown"
        @pointerup="handlePointerUp"
        @pointercancel="handlePointerCancel"
        @wheel="handleWheel"
        @keydown="handleKeyDown"
        @keyup="handleKeyUp"
        @blur="handleCanvasBlur"
        @contextmenu="handleContextMenu"
      >
        <img
          v-if="frameSrc"
          :src="frameSrc"
          alt="Remote screen preview"
          class="screen-view-image"
          draggable="false"
        >

        <div v-else-if="screenError" class="screen-view-empty screen-view-error">
          <div class="screen-view-empty-title">Screen preview unavailable</div>
          <div class="screen-view-empty-text">{{ screenError }}</div>
          <div class="screen-view-empty-hint">
            The client may need OS screen-recording permission or an active desktop session.
          </div>
        </div>

        <div v-else class="screen-view-empty">
          <div class="screen-view-empty-title">Waiting for screen frames…</div>
          <div class="screen-view-empty-text">View mode is active. Enable Control to send mouse and keyboard input.</div>
        </div>
      </div>
    </div>

    <template #footer>
      <el-button size="small" @click="visible = false">Close</el-button>
    </template>
  </el-dialog>
</template>

<script>
import { ElMessage } from 'element-plus'
import * as screenViewApi from '../api/screenViewApi.js'

export default {
  name: 'ScreenViewDialog',

  props: {
    selectedId: {
      type: [String, Number],
      default: '',
    },
    currentConnection: {
      type: Object,
      default: null,
    },
  },

  data() {
    return {
      visible: false,
      fullscreen: false,
      loading: false,
      settingsSaving: false,
      screenSessionId: '',
      screenWs: null,
      screenWsPath: '',
      screenWsReady: false,
      screenStatus: 'idle',
      screenError: '',
      frameSrc: '',
      frameSeq: 0,
      frameWidth: 0,
      frameHeight: 0,
      frameBytes: 0,
      controlEnabled: false,
      controlError: '',
      pendingPointerMove: null,
      pointerMoveTimer: null,
      lastPointerMoveSentAt: 0,
      fps: 4,
      quality: 60,
      targetClientId: '',
      targetLabel: '-',
      userClosing: false,
      fallbackPollTimer: null,
      fpsOptions: [1, 2, 4, 6, 10],
      qualityOptions: [
        { value: 30, label: 'Low · 30' },
        { value: 45, label: 'Medium · 45' },
        { value: 60, label: 'Balanced · 60' },
        { value: 75, label: 'High · 75' },
        { value: 90, label: 'Very High · 90' },
      ],
    }
  },

  computed: {
    screenDialogClass() {
      return [
        'fixed-dialog',
        'screen-view-dialog',
        { 'screen-view-dialog-fullscreen': this.fullscreen },
      ]
    },

    screenDialogWidth() {
      return this.fullscreen ? '100vw' : '1120px'
    },

    screenDialogTop() {
      return this.fullscreen ? '0' : '4vh'
    },

    controlAvailable() {
      return !!(
        this.screenSessionId &&
        this.screenWsReady &&
        this.screenStatus === 'open' &&
        this.frameSrc
      )
    },

    displayStatus() {
      const value = String(this.screenStatus || '').trim().toLowerCase()
      if (!value || value === 'idle') return 'Idle'
      return value.charAt(0).toUpperCase() + value.slice(1)
    },

    statusTagType() {
      if (this.screenStatus === 'open') return 'success'
      if (this.screenStatus === 'error') return 'danger'
      if (this.screenStatus === 'opening' || this.screenStatus === 'closing') return 'warning'
      return 'info'
    },
  },

  beforeUnmount() {
    this.removeControlSafetyListeners()
    this.clearPointerMoveTimer()
    this.stopFallbackPolling()
    this.closeScreenSocket()
    this.closeRemoteSession(false)
  },

  methods: {
    async open() {
      const clientId = String(this.selectedId || '').trim()
      if (!clientId) {
        ElMessage.warning('Please select an online device')
        return
      }

      this.targetClientId = clientId
      this.targetLabel = this.buildTargetLabel()
      this.visible = true
      await this.startView()
    },

    buildTargetLabel() {
      const connection = this.currentConnection || {}
      const hostname = String(connection.hostname || '').trim()
      const machineId = String(connection.machine_id || '').trim()
      if (hostname && machineId) return `${hostname} · ${machineId}`
      return hostname || machineId || String(this.selectedId || '').trim() || '-'
    },

    async startView() {
      if (!this.targetClientId || this.loading) return
      this.loading = true
      this.userClosing = false
      this.screenError = ''
      this.screenStatus = 'opening'
      this.frameSrc = ''
      this.frameSeq = 0
      this.frameWidth = 0
      this.frameHeight = 0
      this.frameBytes = 0
      this.controlEnabled = false
      this.controlError = ''
      this.screenWsReady = false
      this.removeControlSafetyListeners()
      this.clearPointerMoveTimer()
      this.stopFallbackPolling()
      this.closeScreenSocket()

      try {
        const result = await screenViewApi.openScreenView(this.targetClientId, {
          fps: this.fps,
          quality: this.quality,
        })
        this.screenSessionId = String(result.screen_session_id || '').trim()
        this.screenStatus = result.status || 'opening'
        this.screenWsPath = String(result.ws_path || '').trim()
        this.openScreenSocket()
      } catch (e) {
        this.screenStatus = 'error'
        this.screenError = e?.message || 'Failed to open screen view'
        ElMessage.error(this.screenError)
      } finally {
        this.loading = false
      }
    },

    async restartView() {
      await this.closeRemoteSession(false)
      await this.startView()
    },

    toggleFullscreen() {
      this.fullscreen = !this.fullscreen
    },

    async handleControlToggle(enabled) {
      if (!enabled) {
        this.sendScreenWsMessage({ type: 'control', enabled: false })
        this.disableControl(false)
        return
      }

      if (!this.controlAvailable) {
        this.controlEnabled = false
        ElMessage.warning('Screen control requires an active WebSocket preview')
        return
      }

      this.controlError = ''
      if (!this.sendScreenWsMessage({ type: 'control', enabled: true })) {
        this.controlEnabled = false
        ElMessage.warning('Screen control connection is unavailable')
        return
      }

      this.installControlSafetyListeners()
      this.$nextTick(() => {
        this.$refs.screenCanvas?.focus?.()
      })
    },

    disableControl(sendRemote = true) {
      const wasEnabled = this.controlEnabled
      if (sendRemote && wasEnabled) {
        this.sendScreenWsMessage({ type: 'control', enabled: false })
      }
      this.controlEnabled = false
      this.pendingPointerMove = null
      this.clearPointerMoveTimer()
      this.removeControlSafetyListeners()
      this.$refs.screenCanvas?.blur?.()
    },

    applyControlPayload(payload = {}) {
      const error = String(payload.control_error || '').trim()
      if (!error || error === this.controlError) return
      this.controlError = error
      this.disableControl(false)
      ElMessage.error(error)
    },

    sendScreenWsMessage(payload) {
      const ws = this.screenWs
      if (!ws || !this.screenWsReady || ws.readyState !== WebSocket.OPEN) return false
      try {
        ws.send(JSON.stringify(payload || {}))
        return true
      } catch (_) {
        return false
      }
    },

    sendScreenInput(event) {
      if (!this.controlEnabled || !event) return false
      return this.sendScreenWsMessage({ type: 'input', event })
    },

    releaseRemoteInputs() {
      if (!this.controlEnabled) return
      this.pendingPointerMove = null
      this.clearPointerMoveTimer()
      this.sendScreenInput({ action: 'release_all' })
    },

    installControlSafetyListeners() {
      window.addEventListener('blur', this.handleWindowBlur)
    },

    removeControlSafetyListeners() {
      window.removeEventListener('blur', this.handleWindowBlur)
    },

    handleWindowBlur() {
      this.releaseRemoteInputs()
    },

    handleCanvasBlur() {
      this.releaseRemoteInputs()
    },

    handlePointerMove(event) {
      if (!this.controlEnabled || event.pointerType === 'touch') return
      const point = this.resolveRemotePointer(event, true)
      if (!point) return
      event.preventDefault()
      this.queuePointerMove(point)
    },

    handlePointerDown(event) {
      if (!this.controlEnabled || event.pointerType === 'touch') return
      const point = this.resolveRemotePointer(event)
      const button = this.normalizePointerButton(event.button)
      if (!point || !button) return

      event.preventDefault()
      this.$refs.screenCanvas?.focus?.()
      try {
        event.currentTarget?.setPointerCapture?.(event.pointerId)
      } catch (_) {
        // Pointer capture is best-effort and does not affect screen viewing.
      }
      this.sendScreenInput({
        action: 'mouse_down',
        button,
        x: point.x,
        y: point.y,
      })
    },

    handlePointerUp(event) {
      if (!this.controlEnabled || event.pointerType === 'touch') return
      const point = this.resolveRemotePointer(event, true)
      const button = this.normalizePointerButton(event.button)
      if (point && button) {
        event.preventDefault()
        this.sendScreenInput({
          action: 'mouse_up',
          button,
          x: point.x,
          y: point.y,
        })
      }
      try {
        event.currentTarget?.releasePointerCapture?.(event.pointerId)
      } catch (_) {
        // Ignore pointer-capture release failures.
      }
    },

    handlePointerCancel(event) {
      if (!this.controlEnabled) return
      event.preventDefault()
      this.releaseRemoteInputs()
    },

    handleWheel(event) {
      if (!this.controlEnabled) return
      const point = this.resolveRemotePointer(event)
      if (!point) return
      event.preventDefault()

      const rawDelta = Number(event.deltaY || 0)
      if (!rawDelta) return
      const magnitude = Math.max(1, Math.min(5, Math.round(Math.abs(rawDelta) / 100) || 1))
      this.sendScreenInput({
        action: 'mouse_wheel',
        x: point.x,
        y: point.y,
        delta: rawDelta > 0 ? -magnitude : magnitude,
      })
    },

    handleContextMenu(event) {
      if (!this.controlEnabled) return
      event.preventDefault()
    },

    handleKeyDown(event) {
      if (!this.controlEnabled || event.isComposing) return
      event.preventDefault()
      const key = this.normalizeKeyboardKey(event.key)
      if (!key) return
      this.sendScreenInput({
        action: 'key_down',
        key,
        repeat: !!event.repeat,
      })
    },

    handleKeyUp(event) {
      if (!this.controlEnabled || event.isComposing) return
      event.preventDefault()
      const key = this.normalizeKeyboardKey(event.key)
      if (!key) return
      this.sendScreenInput({ action: 'key_up', key })
    },

    normalizeKeyboardKey(value) {
      const original = String(value || '')
      const aliases = {
        ' ': 'space',
        Control: 'ctrl',
        Shift: 'shift',
        Alt: 'alt',
        Meta: 'meta',
        Enter: 'enter',
        Backspace: 'backspace',
        Tab: 'tab',
        Escape: 'esc',
        Delete: 'delete',
        Insert: 'insert',
        Home: 'home',
        End: 'end',
        PageUp: 'pgup',
        PageDown: 'pgdn',
        ArrowUp: 'up',
        ArrowDown: 'down',
        ArrowLeft: 'left',
        ArrowRight: 'right',
        CapsLock: 'capslock',
        NumLock: 'numlock',
        ScrollLock: 'scrolllock',
        PrintScreen: 'printscreen',
        Pause: 'pause',
      }
      if (aliases[original]) return aliases[original]
      if (/^F\d{1,2}$/i.test(original)) return original.toLowerCase()
      if (original.length === 1 && /^[\x20-\x7E]$/.test(original)) return original.toLowerCase()
      return ''
    },

    normalizePointerButton(value) {
      if (value === 0) return 'left'
      if (value === 1) return 'middle'
      if (value === 2) return 'right'
      return ''
    },

    resolveRemotePointer(event, allowClamp = false) {
      if (!this.frameWidth || !this.frameHeight) return null
      const canvas = this.$refs.screenCanvas
      if (!canvas) return null

      const rect = canvas.getBoundingClientRect()
      if (!rect.width || !rect.height) return null

      const scale = Math.min(rect.width / this.frameWidth, rect.height / this.frameHeight)
      const displayWidth = this.frameWidth * scale
      const displayHeight = this.frameHeight * scale
      const left = rect.left + ((rect.width - displayWidth) / 2)
      const top = rect.top + ((rect.height - displayHeight) / 2)
      const localX = Number(event.clientX || 0) - left
      const localY = Number(event.clientY || 0) - top
      if (!allowClamp && (localX < 0 || localY < 0 || localX > displayWidth || localY > displayHeight)) return null

      return {
        x: Math.max(0, Math.min(1, localX / displayWidth)),
        y: Math.max(0, Math.min(1, localY / displayHeight)),
      }
    },

    queuePointerMove(point) {
      this.pendingPointerMove = point
      const now = performance.now()
      const elapsed = now - Number(this.lastPointerMoveSentAt || 0)
      const interval = 33
      if (elapsed >= interval) {
        this.flushPointerMove()
        return
      }
      if (this.pointerMoveTimer) return
      this.pointerMoveTimer = window.setTimeout(() => {
        this.pointerMoveTimer = null
        this.flushPointerMove()
      }, Math.max(1, interval - elapsed))
    },

    flushPointerMove() {
      if (!this.controlEnabled || !this.pendingPointerMove) return
      const point = this.pendingPointerMove
      this.pendingPointerMove = null
      this.lastPointerMoveSentAt = performance.now()
      this.sendScreenInput({ action: 'mouse_move', x: point.x, y: point.y })
    },

    clearPointerMoveTimer() {
      if (!this.pointerMoveTimer) return
      window.clearTimeout(this.pointerMoveTimer)
      this.pointerMoveTimer = null
    },

    openScreenSocket() {
      if (!this.screenWsPath || !this.screenSessionId) {
        this.startFallbackPolling()
        return
      }

      this.closeScreenSocket()

      try {
        const url = new URL(this.screenWsPath, window.location.href)
        url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
        const ws = new WebSocket(url.toString())
        this.screenWs = ws

        ws.onopen = () => {
          if (this.screenWs === ws) this.screenWsReady = true
        }

        ws.onmessage = (event) => {
          let payload = null
          try {
            payload = JSON.parse(event.data || '{}')
          } catch (_) {
            return
          }
          this.applyScreenPayload(payload)
        }

        ws.onerror = () => {
          if (this.screenWs === ws) this.screenWsReady = false
          this.disableControl(false)
          if (this.userClosing) return
          this.startFallbackPolling()
        }

        ws.onclose = () => {
          if (this.screenWs === ws) {
            this.screenWs = null
            this.screenWsReady = false
          }
          this.disableControl(false)
          if (!this.userClosing && this.visible && !['closed', 'error'].includes(this.screenStatus)) {
            this.startFallbackPolling()
          }
        }
      } catch (_) {
        this.startFallbackPolling()
      }
    },

    closeScreenSocket() {
      const ws = this.screenWs
      this.screenWs = null
      this.screenWsReady = false
      if (!ws) return
      try {
        ws.close()
      } catch (_) {
        // Ignore socket close failures while tearing down the preview.
      }
    },

    applyScreenPayload(payload = {}) {
      const type = String(payload.type || '').trim().toLowerCase()
      this.applyControlPayload(payload)
      if (type === 'frame') {
        this.screenStatus = payload.status || 'open'
        this.screenError = payload.error || ''
        this.frameSeq = Number(payload.seq || this.frameSeq || 0)
        this.frameWidth = Number(payload.width || 0)
        this.frameHeight = Number(payload.height || 0)
        this.frameBytes = Number(payload.frame_bytes || 0)
        if (payload.frame) {
          this.frameSrc = `data:image/jpeg;base64,${payload.frame}`
        }
        return
      }

      if (type === 'status') {
        this.screenStatus = payload.status || this.screenStatus
        this.screenError = payload.error || ''
      }
    },

    async applySettings() {
      if (!this.screenSessionId) return
      this.settingsSaving = true
      try {
        const result = await screenViewApi.updateScreenView(this.screenSessionId, {
          fps: this.fps,
          quality: this.quality,
        })
        this.fps = Number(result.fps || this.fps)
        this.quality = Number(result.quality || this.quality)
      } catch (e) {
        ElMessage.error(e?.message || 'Failed to update screen view settings')
      } finally {
        this.settingsSaving = false
      }
    },

    startFallbackPolling() {
      if (!this.screenSessionId || this.fallbackPollTimer) return
      const poll = async () => {
        if (!this.visible || !this.screenSessionId || this.userClosing) {
          this.stopFallbackPolling()
          return
        }
        try {
          const payload = await screenViewApi.pollScreenView(this.screenSessionId, this.frameSeq)
          if (payload.frame) {
            this.applyScreenPayload({ type: 'frame', ...payload })
          } else if (payload.status) {
            this.applyScreenPayload({ type: 'status', ...payload })
          }
        } catch (e) {
          this.screenStatus = 'error'
          this.screenError = e?.message || 'Screen view polling failed'
          this.stopFallbackPolling()
        }
      }
      this.fallbackPollTimer = window.setInterval(poll, 250)
      poll()
    },

    stopFallbackPolling() {
      if (!this.fallbackPollTimer) return
      window.clearInterval(this.fallbackPollTimer)
      this.fallbackPollTimer = null
    },

    async closeRemoteSession(showError = false) {
      const screenSessionId = this.screenSessionId
      this.disableControl(true)
      this.screenSessionId = ''
      this.stopFallbackPolling()
      this.closeScreenSocket()
      if (!screenSessionId) return
      try {
        await screenViewApi.closeScreenView(screenSessionId)
      } catch (e) {
        if (showError) ElMessage.error(e?.message || 'Failed to close screen view')
      }
    },

    handleDialogClose() {
      this.userClosing = true
      this.closeRemoteSession(false)
    },

    handleDialogClosed() {
      this.userClosing = false
      this.fullscreen = false
      this.screenSessionId = ''
      this.screenWsPath = ''
      this.screenWsReady = false
      this.screenStatus = 'idle'
      this.screenError = ''
      this.frameSrc = ''
      this.frameSeq = 0
      this.frameWidth = 0
      this.frameHeight = 0
      this.frameBytes = 0
      this.controlEnabled = false
      this.controlError = ''
      this.removeControlSafetyListeners()
      this.clearPointerMoveTimer()
      this.targetClientId = ''
      this.targetLabel = '-'
    },

    formatFrameBytes(value) {
      const bytes = Number(value || 0)
      if (!bytes) return '0 B'
      if (bytes < 1024) return `${bytes} B`
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
      return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
    },
  },
}
</script>

<style scoped>
.screen-view-body {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 620px;
}

.screen-view-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.screen-view-toolbar-left,
.screen-view-toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.screen-view-target {
  max-width: 380px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 650;
  color: #334155;
}

.screen-view-meta,
.screen-view-control-label {
  color: #64748b;
  font-size: 12px;
}

.screen-view-fps-select {
  width: 92px;
}

.screen-view-quality-select {
  width: 140px;
}

.screen-view-canvas {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  flex: 1 1 auto;
  min-height: 560px;
  overflow: hidden;
  border: 1px solid #1e293b;
  border-radius: 10px;
  background: #020617;
}

.screen-view-canvas-control {
  outline: 2px solid #409eff;
  outline-offset: -2px;
  cursor: default;
}

.screen-view-canvas:focus {
  outline-color: #409eff;
}

.screen-view-image {
  display: block;
  width: 100%;
  height: 100%;
  max-height: 72vh;
  object-fit: contain;
  user-select: none;
  pointer-events: none;
}

.screen-view-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 28px;
  text-align: center;
  color: #94a3b8;
}

.screen-view-empty-title {
  color: #e2e8f0;
  font-size: 15px;
  font-weight: 650;
}

.screen-view-empty-text,
.screen-view-empty-hint {
  max-width: 720px;
  font-size: 12px;
  line-height: 1.6;
}

.screen-view-error .screen-view-empty-title {
  color: #fca5a5;
}

@media (max-width: 760px) {
  .screen-view-toolbar,
  .screen-view-toolbar-left,
  .screen-view-toolbar-right {
    align-items: flex-start;
    width: 100%;
  }

  .screen-view-toolbar {
    flex-direction: column;
  }

  .screen-view-toolbar-right {
    flex-wrap: wrap;
  }

  .screen-view-canvas {
    min-height: 420px;
  }
}
</style>


<style>
.screen-view-dialog.screen-view-dialog-fullscreen.el-dialog {
  width: 100vw !important;
  max-width: 100vw !important;
  height: 100dvh !important;
  max-height: 100dvh !important;
  margin: 0 !important;
  top: 0 !important;
  border-radius: 0 !important;
  display: flex !important;
  flex-direction: column !important;
}

.screen-view-dialog.screen-view-dialog-fullscreen .el-dialog__header {
  flex: 0 0 auto !important;
}

.screen-view-dialog.screen-view-dialog-fullscreen .el-dialog__body {
  flex: 1 1 auto !important;
  min-height: 0 !important;
  overflow: hidden !important;
  display: flex !important;
  flex-direction: column !important;
}

.screen-view-dialog.screen-view-dialog-fullscreen .el-dialog__footer {
  flex: 0 0 auto !important;
}

.screen-view-dialog.screen-view-dialog-fullscreen .screen-view-body {
  flex: 1 1 auto !important;
  min-height: 0 !important;
  height: 100% !important;
}

.screen-view-dialog.screen-view-dialog-fullscreen .screen-view-canvas {
  flex: 1 1 auto !important;
  min-height: 0 !important;
}

.screen-view-dialog.screen-view-dialog-fullscreen .screen-view-image {
  max-height: none !important;
}
</style>
