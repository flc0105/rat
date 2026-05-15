<template>
  <el-dialog
    :model-value="modelValue"
    :title="title"
    width="520px"
    class="drag-upload-dialog"
    @update:model-value="handleVisibleChange"
  >
    <div
      class="drag-upload-dropzone"
      :class="{ 'is-dragging': dragging, 'is-loading': loading }"
      role="button"
      tabindex="0"
      @click="openFilePicker"
      @keydown.enter.prevent="openFilePicker"
      @keydown.space.prevent="openFilePicker"
      @dragenter.prevent="handleDragEnter"
      @dragover.prevent="handleDragOver"
      @dragleave.prevent="handleDragLeave"
      @drop.prevent="handleDrop"
    >
      <div class="drag-upload-icon">⬆</div>
      <div class="drag-upload-title">Drop files here or click to choose</div>
      <div class="drag-upload-desc">{{ helperText }}</div>
    </div>

    <input
      ref="fileInputRef"
      type="file"
      class="drag-upload-input"
      :accept="accept"
      :multiple="multiple"
      @change="handleInputChange"
    />

    <template #footer>
      <el-button @click="closeDialog">Cancel</el-button>
      <el-button type="primary" :loading="loading" @click="openFilePicker">
        {{ buttonText }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script>
export default {
  name: 'DragUploadDialog',

  props: {
    modelValue: { type: Boolean, default: false },
    title: { type: String, default: 'Upload File' },
    helperText: { type: String, default: 'Only files are supported.' },
    buttonText: { type: String, default: 'Choose File' },
    accept: { type: String, default: '' },
    multiple: { type: Boolean, default: false },
    loading: { type: Boolean, default: false },
  },

  emits: ['update:modelValue', 'selected'],

  data() {
    return {
      dragging: false,
      dragDepth: 0,
    }
  },

  methods: {
    handleVisibleChange(value) {
      this.$emit('update:modelValue', value)
      if (!value) {
        this.resetDragState()
      }
    },

    closeDialog() {
      this.handleVisibleChange(false)
    },

    openFilePicker() {
      if (this.loading) return
      const input = this.$refs.fileInputRef
      if (!input) return
      input.value = ''
      input.click()
    },

    handleDragEnter() {
      if (this.loading) return
      this.dragDepth += 1
      this.dragging = true
    },

    handleDragOver() {
      if (this.loading) return
      this.dragging = true
    },

    handleDragLeave() {
      if (this.loading) return
      this.dragDepth = Math.max(this.dragDepth - 1, 0)
      if (this.dragDepth === 0) {
        this.dragging = false
      }
    },

    handleDrop(event) {
      if (this.loading) return
      const files = Array.from(event?.dataTransfer?.files || [])
      this.resetDragState()
      this.emitFiles(files)
    },

    handleInputChange(event) {
      const files = Array.from(event?.target?.files || [])
      this.emitFiles(files)
      if (event?.target) event.target.value = ''
    },

    emitFiles(files) {
      const validFiles = files.filter(file => file && typeof file.name === 'string')
      if (!validFiles.length) return
      this.$emit('selected', this.multiple ? validFiles : [validFiles[0]])
    },

    resetDragState() {
      this.dragging = false
      this.dragDepth = 0
    },
  },
}
</script>

<style scoped>
.drag-upload-dropzone {
  min-height: 190px;
  border: 1px dashed rgba(148, 163, 184, 0.75);
  border-radius: 18px;
  background: rgba(248, 250, 252, 0.72);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 28px 24px;
  cursor: pointer;
  text-align: center;
  transition: border-color 0.16s ease, background 0.16s ease, box-shadow 0.16s ease;
}

.drag-upload-dropzone:hover,
.drag-upload-dropzone.is-dragging {
  border-color: var(--el-color-primary);
  background: rgba(64, 158, 255, 0.08);
  box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
}

.drag-upload-dropzone.is-loading {
  cursor: wait;
  opacity: 0.72;
}

.drag-upload-icon {
  width: 46px;
  height: 46px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: rgba(64, 158, 255, 0.12);
  color: var(--el-color-primary);
  font-size: 24px;
  line-height: 1;
}

.drag-upload-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--text, #0f172a);
}

.drag-upload-desc {
  font-size: 13px;
  color: var(--muted-2, #64748b);
  line-height: 1.5;
}

.drag-upload-input {
  display: none;
}
</style>
