<template>
  <el-dialog
    :model-value="visible"
    :title="title || 'File Preview'"
    width="1080px"
    top="5vh"
    class="fixed-dialog preview-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div
      v-loading="loading"
      class="preview-wrap"
    >
      <div
        v-if="type === 'image' || type === 'text'"
        class="preview-toolbar"
      >
        <div class="preview-toolbar-left">
          <template v-if="type === 'text'">
            <el-button
              size="small"
              @click="$emit('copy-text')"
            >
              Copy
            </el-button>

            <el-button
              v-if="!editMode && !truncated"
              size="small"
              type="primary"
              @click="$emit('enter-edit')"
            >
              Edit
            </el-button>

            <template v-else-if="editMode">
              <el-button
                size="small"
                type="primary"
                :loading="saving"
                @click="$emit('save')"
              >
                Save
              </el-button>

              <el-button
                size="small"
                @click="$emit('cancel-edit')"
              >
                Cancel
              </el-button>

              <el-button
                size="small"
                type="danger"
                plain
                @click="$emit('clear-content')"
              >
                Clear
              </el-button>
            </template>
          </template>

          <template v-if="type === 'image' && url">
            <el-button
              v-if="imageInfo"
              size="small"
              @click="$emit('open-image-info')"
            >
              Image Info
            </el-button>

            <el-button
              size="small"
              @click="$emit('open-original')"
            >
              Open Original
            </el-button>
          </template>
        </div>

        <div class="preview-toolbar-right">
          <template v-if="type === 'text'">
            <div class="preview-info-tags">
              <el-tag
                size="small"
                type="primary"
              >
                {{ sourceLabel }}
              </el-tag>

              <el-tag
                size="small"
                type="info"
              >
                {{ fileSize }}
              </el-tag>

              <el-tag
                size="small"
                type="info"
              >
                {{ fileEncoding }}
              </el-tag>

              <el-tag
                size="small"
                type="info"
              >
                {{ detectedLanguage }}
              </el-tag>

              <el-tag
                v-if="truncated"
                size="small"
                type="danger"
              >
                Truncated - Edit disabled
              </el-tag>

              <el-tag
                v-else
                size="small"
                type="success"
              >
                Full content
              </el-tag>
            </div>
          </template>
        </div>
      </div>

      <template v-if="type === 'image' && url">
        <div class="image-preview-box">
          <img
            :src="url"
            alt="preview"
            class="preview-image"
          >
        </div>
      </template>

      <template v-else-if="type === 'text'">
        <!-- Monaco Editor 容器：这个 id 必须保留，preview.js 会用 document.getElementById 找它 -->
        <div
          id="monaco-editor-container"
          class="monaco-editor-container"
        />
      </template>

      <template v-else-if="type === 'unsupported'">
        <div class="empty-state">
          This file type is not supported for preview.
        </div>
      </template>

      <template v-else>
        <div class="empty-state">
          No preview available.
        </div>
      </template>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'PreviewDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    loading: {
      type: Boolean,
      default: false,
    },

    type: {
      type: String,
      default: '',
    },

    title: {
      type: String,
      default: '',
    },

    url: {
      type: String,
      default: '',
    },

    editMode: {
      type: Boolean,
      default: false,
    },

    saving: {
      type: Boolean,
      default: false,
    },

    truncated: {
      type: Boolean,
      default: false,
    },

    sourceLabel: {
      type: String,
      default: '',
    },

    fileSize: {
      type: String,
      default: '',
    },

    fileEncoding: {
      type: String,
      default: '',
    },

    detectedLanguage: {
      type: String,
      default: 'Plain Text',
    },

    imageInfo: {
      type: Object,
      default: null,
    },
  },

  emits: [
    'update:visible',
    'copy-text',
    'enter-edit',
    'save',
    'cancel-edit',
    'clear-content',
    'open-image-info',
    'open-original',
  ],
}
</script>