<template>
  <el-dialog
    v-model="visible"
    width="760px"
    class="clipboard-dialog"
    :close-on-click-modal="false"
    destroy-on-close
    @closed="resetState"
  >
    <template #header>
      <div class="clipboard-head">
        <div>
          <div class="clipboard-title">{{ dialogTitle }}</div>
          <div class="clipboard-subtitle">{{ targetLabel }}</div>
        </div>
        <el-tag v-if="capabilityText" size="small" effect="plain">{{ capabilityText }}</el-tag>
      </div>
    </template>

    <div v-if="mode === 'get'" class="clipboard-body">
      <div v-if="loading" class="clipboard-loading">
        <el-icon class="is-loading"><Loading /></el-icon>
        Reading target clipboard...
      </div>

      <template v-else-if="remoteKind === 'text'">
        <div class="clipboard-section-label">Text</div>
        <el-input
          v-model="remoteText"
          type="textarea"
          :rows="12"
          resize="vertical"
          readonly
        />
        <div class="clipboard-actions">
          <el-button size="small" @click="copyRemoteTextLocal">Copy Local</el-button>
        </div>
      </template>

      <template v-else-if="remoteKind === 'image' && remoteImageArtifact">
        <div class="clipboard-section-label">Image</div>
        <div class="clipboard-image-shell">
          <img :src="remoteImageArtifact.raw_url" alt="Clipboard image">
        </div>
        <div class="clipboard-file-meta">
          <span>{{ remoteImageArtifact.original_name || 'clipboard.png' }}</span>
          <span>{{ formatBytes(remoteImageArtifact.size) }}</span>
        </div>
        <div class="clipboard-actions">
          <el-button size="small" @click="copyRemoteImageLocal">Copy Local</el-button>
          <el-button size="small" @click="downloadArtifact(remoteImageArtifact)">Download</el-button>
        </div>
      </template>

      <template v-else-if="remoteKind === 'files'">
        <div class="clipboard-section-label">Files · {{ remoteArtifacts.length }}</div>
        <div v-if="remoteArtifacts.length" class="clipboard-file-list">
          <div v-for="artifact in remoteArtifacts" :key="artifact.artifact_id" class="clipboard-file-row">
            <div class="clipboard-file-main">
              <div class="clipboard-file-name">{{ artifact.original_name || artifact.stored_name || 'file' }}</div>
              <div class="clipboard-file-detail">
                {{ formatBytes(artifact.size) }}
                <span v-if="artifact.extra?.source_is_directory"> · directory archive</span>
              </div>
            </div>
            <el-button size="small" @click="downloadArtifact(artifact)">Download</el-button>
          </div>
        </div>
        <el-empty v-else description="Clipboard file list is empty" :image-size="72" />
      </template>

      <el-empty
        v-else
        :description="remoteError || 'Target clipboard is empty or unsupported'"
        :image-size="82"
      />
    </div>

    <div
      v-else
      class="clipboard-body"
      @dragover.prevent
      @drop.prevent="handleDrop"
      @paste.capture="handlePaste"
    >
      <div class="clipboard-section-label">Text</div>
      <el-input
        v-model="sendText"
        type="textarea"
        :rows="7"
        resize="vertical"
        placeholder="Type or paste text here..."
      />

      <div class="clipboard-composer-separator"><span>or</span></div>

      <div class="clipboard-dropzone" @click="openFilePicker">
        <div class="clipboard-drop-title">Drop files here</div>
        <div class="clipboard-drop-hint">Click to choose files, or paste an image/file into this dialog</div>
      </div>
      <input
        ref="fileInputRef"
        type="file"
        multiple
        class="clipboard-hidden-input"
        @change="handleFileChoose"
      >

      <div v-if="sendFiles.length" class="clipboard-send-files">
        <div class="clipboard-section-label">
          {{ sendPayloadKind === 'image' ? 'Image' : `Files · ${sendFiles.length}` }}
        </div>
        <div v-for="(item, index) in sendFiles" :key="`${item.file.name}-${index}`" class="clipboard-file-row">
          <div class="clipboard-file-main">
            <div class="clipboard-file-name">{{ item.file.name }}</div>
            <div class="clipboard-file-detail">{{ item.file.type || 'file' }} · {{ formatBytes(item.file.size) }}</div>
          </div>
          <el-button size="small" text type="danger" @click="removeSendFile(index)">Remove</el-button>
        </div>
      </div>

      <div class="clipboard-send-tools">
        <el-button size="small" @click="readLocalClipboard">Read Local Clipboard</el-button>
        <el-button size="small" @click="clearComposer">Clear</el-button>
        <span class="clipboard-send-note">
          {{ sendFiles.length ? 'Attached file/image takes priority over text.' : 'Browser clipboard access is optional; manual paste always works.' }}
        </span>
      </div>
    </div>

    <template #footer>
      <div class="clipboard-footer">
        <el-button @click="visible = false">Close</el-button>
        <el-button
          v-if="mode === 'get'"
          type="primary"
          :loading="loading"
          @click="loadRemoteClipboard"
        >
          Refresh
        </el-button>
        <el-button
          v-else
          type="primary"
          :loading="sending"
          :disabled="!canSend"
          @click="sendClipboard"
        >
          Send to Target
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script>
import { ElMessage } from 'element-plus'
import { Loading } from '@element-plus/icons-vue'
import {
  getClipboardCapabilities,
  getRemoteClipboard,
  setRemoteClipboardFiles,
  setRemoteClipboardImage,
  setRemoteClipboardText,
} from '../api/clipboardApi.js'

export default {
  name: 'ClipboardDialog',
  components: { Loading },
  props: {
    selectedId: { type: [String, Number], default: '' },
    currentConnection: { type: Object, default: null },
  },
  emits: ['artifacts-maybe-changed'],
  data() {
    return {
      visible: false,
      mode: 'get',
      loading: false,
      sending: false,
      capabilities: {},
      remoteKind: '',
      remoteText: '',
      remoteImageArtifact: null,
      remoteArtifacts: [],
      remoteError: '',
      sendText: '',
      sendFiles: [],
      sendPayloadKind: 'files',
    }
  },
  computed: {
    dialogTitle() {
      return this.mode === 'get' ? 'Get Clipboard' : 'Send Clipboard'
    },
    targetLabel() {
      const item = this.currentConnection || {}
      return item.hostname || item.machine_alias || item.client_id || String(this.selectedId || '')
    },
    capabilityText() {
      if (!Object.keys(this.capabilities || {}).length) return ''
      const names = ['text', 'image', 'files'].filter((key) => this.capabilities[key])
      return names.length ? names.join(' / ') : 'Unsupported'
    },
    canSend() {
      if (this.sending) return false
      if (this.sendFiles.length) {
        return this.sendPayloadKind === 'image'
          ? this.capabilities.image !== false
          : this.capabilities.files !== false
      }
      return String(this.sendText || '').length > 0 && this.capabilities.text !== false
    },
  },
  methods: {
    async openGet() {
      this.mode = 'get'
      this.visible = true
      this.resetRemotePayload()
      await this.loadCapabilities()
      await this.loadRemoteClipboard()
    },
    async openSend() {
      this.mode = 'send'
      this.visible = true
      this.clearComposer()
      await this.loadCapabilities()
    },
    async loadCapabilities() {
      if (!this.selectedId) return
      try {
        this.capabilities = await getClipboardCapabilities(this.selectedId)
      } catch (e) {
        this.capabilities = {}
        ElMessage.error(e.message || 'Failed to read clipboard capabilities')
      }
    },
    async loadRemoteClipboard() {
      if (!this.selectedId || this.loading) return
      this.loading = true
      this.resetRemotePayload()
      try {
        const payload = await getRemoteClipboard(this.selectedId)
        this.capabilities = payload.capabilities || this.capabilities || {}
        this.remoteKind = String(payload.kind || 'empty')
        if (this.remoteKind === 'text') {
          this.remoteText = String(payload.text || '')
        } else if (this.remoteKind === 'image') {
          this.remoteImageArtifact = payload.artifact || null
          if (this.remoteImageArtifact) this.$emit('artifacts-maybe-changed')
        } else if (this.remoteKind === 'files') {
          this.remoteArtifacts = Array.isArray(payload.artifacts) ? payload.artifacts : []
          if (this.remoteArtifacts.length) this.$emit('artifacts-maybe-changed')
        }
      } catch (e) {
        this.remoteKind = 'error'
        this.remoteError = e.message || 'Failed to read target clipboard'
        ElMessage.error(this.remoteError)
      } finally {
        this.loading = false
      }
    },
    // async sendClipboard() {
    //   if (!this.selectedId || !this.canSend) return
    //   this.sending = true
    //   try {
    //     if (this.sendFiles.length) {
    //       const files = this.sendFiles.map((item) => item.file)
    //       if (this.sendPayloadKind === 'image') {
    //         await setRemoteClipboardImage(this.selectedId, files[0])
    //       } else {
    //         await setRemoteClipboardFiles(this.selectedId, files)
    //       }
    //     } else {
    //       await setRemoteClipboardText(this.selectedId, this.sendText)
    //     }
    //     ElMessage.success('Target clipboard updated')
    //     this.visible = false
    //   } catch (e) {
    //     ElMessage.error(e.message || 'Failed to update target clipboard')
    //   } finally {
    //     this.sending = false
    //   }
    // },
    async sendClipboard() {
  if (!this.selectedId || !this.canSend) return
  this.sending = true
  try {
    if (this.sendFiles.length) {
      const files = this.sendFiles.map((item) => item.file)
      if (this.sendPayloadKind === 'image') {
        await setRemoteClipboardImage(this.selectedId, files[0])
      } else {
        await setRemoteClipboardFiles(this.selectedId, files)
      }
    } else {
      await setRemoteClipboardText(this.selectedId, this.sendText)
    }
    ElMessage.success('Target clipboard updated')
  } catch (e) {
    ElMessage.error(e.message || 'Failed to update target clipboard')
  } finally {
    this.sending = false
  }
},
    async copyRemoteTextLocal() {
      try {
        await navigator.clipboard.writeText(this.remoteText)
        ElMessage.success('Copied to local clipboard')
      } catch (e) {
        ElMessage.warning('Browser clipboard write is unavailable. Select and copy the text manually.')
      }
    },
    async copyRemoteImageLocal() {
      const url = this.remoteImageArtifact?.raw_url
      if (!url || !navigator.clipboard?.write || typeof ClipboardItem === 'undefined') {
        ElMessage.warning('Browser image clipboard write is unavailable')
        return
      }
      try {
        const response = await fetch(url)
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        const blob = await response.blob()
        await navigator.clipboard.write([new ClipboardItem({ [blob.type || 'image/png']: blob })])
        ElMessage.success('Image copied to local clipboard')
      } catch (e) {
        ElMessage.warning('Browser image clipboard write failed. Use Download instead.')
      }
    },
    downloadArtifact(artifact) {
      const url = artifact?.download_url
      if (!url) return
      const link = document.createElement('a')
      link.href = url
      link.download = artifact.original_name || artifact.stored_name || ''
      document.body.appendChild(link)
      link.click()
      link.remove()
    },
    async readLocalClipboard() {
      if (!navigator.clipboard) {
        ElMessage.warning('Browser clipboard access is unavailable. Paste manually instead.')
        return
      }
      try {
        if (navigator.clipboard.read) {
          const items = await navigator.clipboard.read()
          for (const item of items) {
            const imageType = item.types.find((type) => type.startsWith('image/'))
            if (imageType) {
              const blob = await item.getType(imageType)
              const ext = imageType.split('/')[1] || 'png'
              this.sendFiles = [{ file: new File([blob], `clipboard.${ext}`, { type: imageType }) }]
              this.sendPayloadKind = 'image'
              return
            }
          }
        }
        const text = await navigator.clipboard.readText()
        this.sendText = text || ''
        this.sendFiles = []
        this.sendPayloadKind = 'files'
      } catch (e) {
        ElMessage.warning('Browser clipboard read was blocked. Paste manually instead.')
      }
    },
    handlePaste(event) {
      const files = Array.from(event.clipboardData?.files || [])
      if (!files.length) return
      event.preventDefault()
      const singleImage = files.length === 1 && String(files[0].type || '').startsWith('image/')
      this.sendFiles = files.map((file) => ({ file }))
      this.sendPayloadKind = singleImage ? 'image' : 'files'
    },
    handleDrop(event) {
      const files = Array.from(event.dataTransfer?.files || [])
      if (!files.length) return
      this.sendFiles = files.map((file) => ({ file }))
      this.sendPayloadKind = 'files'
    },
    openFilePicker() {
      const input = this.$refs.fileInputRef
      if (!input) return
      input.value = ''
      input.click()
    },
    handleFileChoose(event) {
      const files = Array.from(event.target?.files || [])
      if (!files.length) return
      this.sendFiles = files.map((file) => ({ file }))
      this.sendPayloadKind = 'files'
    },
    removeSendFile(index) {
      this.sendFiles.splice(index, 1)
      if (!this.sendFiles.length) this.sendPayloadKind = 'files'
      if (this.sendPayloadKind === 'image' && this.sendFiles.length !== 1) this.sendPayloadKind = 'files'
    },
    clearComposer() {
      this.sendText = ''
      this.sendFiles = []
      this.sendPayloadKind = 'files'
    },
    resetRemotePayload() {
      this.remoteKind = ''
      this.remoteText = ''
      this.remoteImageArtifact = null
      this.remoteArtifacts = []
      this.remoteError = ''
    },
    resetState() {
      this.loading = false
      this.sending = false
      this.resetRemotePayload()
      this.clearComposer()
    },
    formatBytes(value) {
      let size = Number(value || 0)
      if (!Number.isFinite(size) || size <= 0) return '0 B'
      const units = ['B', 'KB', 'MB', 'GB', 'TB']
      let unit = 0
      while (size >= 1024 && unit < units.length - 1) {
        size /= 1024
        unit += 1
      }
      return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`
    },
  },
}
</script>

<style scoped>
.clipboard-head,
.clipboard-footer,
.clipboard-file-row,
.clipboard-send-tools,
.clipboard-file-meta {
  display: flex;
  align-items: center;
}
.clipboard-head,
.clipboard-footer {
  justify-content: space-between;
  gap: 12px;
}
.clipboard-title { font-size: 16px; font-weight: 600; }
.clipboard-subtitle { margin-top: 3px; font-size: 12px; opacity: .6; }
.clipboard-body { min-height: 260px; }
.clipboard-loading { min-height: 240px; display: flex; gap: 9px; align-items: center; justify-content: center; opacity: .68; }
.clipboard-section-label { margin-bottom: 8px; font-size: 12px; font-weight: 600; opacity: .72; text-transform: uppercase; letter-spacing: .04em; }
.clipboard-actions { margin-top: 12px; display: flex; justify-content: flex-end; gap: 8px; }
.clipboard-image-shell { max-height: 430px; overflow: auto; border: 1px solid var(--el-border-color-light); border-radius: 8px; background: rgba(0,0,0,.025); text-align: center; }
.clipboard-image-shell img { display: block; max-width: 100%; margin: 0 auto; }
.clipboard-file-meta { justify-content: space-between; margin-top: 8px; font-size: 12px; opacity: .65; }
.clipboard-file-list,
.clipboard-send-files { border: 1px solid var(--el-border-color-light); border-radius: 8px; overflow: hidden; }
.clipboard-file-row { justify-content: space-between; gap: 12px; padding: 10px 12px; border-bottom: 1px solid var(--el-border-color-lighter); }
.clipboard-file-row:last-child { border-bottom: 0; }
.clipboard-file-main { min-width: 0; flex: 1; }
.clipboard-file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.clipboard-file-detail { margin-top: 3px; font-size: 11px; opacity: .58; }
.clipboard-composer-separator { position: relative; margin: 18px 0; text-align: center; font-size: 11px; opacity: .55; }
.clipboard-composer-separator::before { content: ''; position: absolute; left: 0; right: 0; top: 50%; border-top: 1px solid var(--el-border-color-lighter); }
.clipboard-composer-separator span { position: relative; padding: 0 10px; background: var(--el-bg-color); }
.clipboard-dropzone { padding: 26px 18px; border: 1px dashed var(--el-border-color); border-radius: 9px; text-align: center; cursor: pointer; transition: border-color .15s, background .15s; }
.clipboard-dropzone:hover { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.clipboard-drop-title { font-weight: 600; }
.clipboard-drop-hint { margin-top: 5px; font-size: 12px; opacity: .58; }
.clipboard-hidden-input { display: none; }
.clipboard-send-files { margin-top: 16px; padding-top: 10px; }
.clipboard-send-files > .clipboard-section-label { padding: 0 12px; }
.clipboard-send-tools { margin-top: 14px; gap: 8px; }
.clipboard-send-note { margin-left: auto; font-size: 11px; opacity: .55; text-align: right; }
@media (max-width: 720px) {
  .clipboard-send-tools { align-items: flex-start; flex-wrap: wrap; }
  .clipboard-send-note { width: 100%; margin-left: 0; text-align: left; }
}
</style>
