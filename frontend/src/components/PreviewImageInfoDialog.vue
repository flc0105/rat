<template>
  <el-dialog
    :model-value="visible"
    title="Image Info"
    width="760px"
    top="8vh"
    class="fixed-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div class="preview-image-info-body">
      <template v-if="info">
        <div
          v-if="formatted.basic.length"
          class="preview-image-info-section"
        >
          <div class="preview-image-info-title">
            Basic
          </div>

          <div
            v-for="item in formatted.basic"
            :key="'basic-' + item.key"
            class="preview-image-info-row"
          >
            <div class="preview-image-info-label">
              {{ item.label }}
            </div>

            <div class="preview-image-info-value">
              {{ item.value }}
            </div>
          </div>
        </div>

        <div
          v-if="formatted.exif.length"
          class="preview-image-info-section"
        >
          <div class="preview-image-info-title">
            EXIF
          </div>

          <div
            v-for="item in formatted.exif"
            :key="'exif-' + item.key"
            class="preview-image-info-row"
          >
            <div class="preview-image-info-label">
              {{ item.label }}
            </div>

            <div class="preview-image-info-value">
              {{ item.value }}
            </div>
          </div>
        </div>

        <div
          v-if="formatted.other.length"
          class="preview-image-info-section"
        >
          <div class="preview-image-info-title">
            Other
          </div>

          <div
            v-for="item in formatted.other"
            :key="'other-' + item.key"
            class="preview-image-info-row"
          >
            <div class="preview-image-info-label">
              {{ item.label }}
            </div>

            <div class="preview-image-info-value">
              {{ item.value }}
            </div>
          </div>
        </div>
      </template>

      <el-empty
        v-else
        description="No image info available"
      />
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'PreviewImageInfoDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    info: {
      type: Object,
      default: null,
    },
  },

  emits: ['update:visible'],

  computed: {
    formatted() {
      return this.formatPreviewImageInfo(this.info)
    },
  },

  methods: {
    // 图片信息展示格式化逻辑归属在图片信息弹窗内。
    formatPreviewImageInfo(info) {
      if (!info || typeof info !== 'object') {
        return {
          basic: [],
          exif: [],
          other: [],
        }
      }

      const basicFieldOrder = [
        ['name', 'Name'],
        ['width', 'Width'],
        ['height', 'Height'],
        ['size', 'Dimensions'],
        ['format', 'Format'],
        ['mode', 'Color Mode'],
        ['file_size_bytes', 'File Size (Bytes)'],
        ['artifact_id', 'Artifact ID'],
      ]

      const exifFieldOrder = [
        ['make', 'Camera Make'],
        ['model', 'Camera Model'],
        ['lens_model', 'Lens Model'],
        ['datetime_original', 'Date Taken'],
        ['exposure_time', 'Exposure Time'],
        ['f_number', 'F Number'],
        ['iso', 'ISO'],
        ['focal_length', 'Focal Length'],
        ['color_space', 'Color Space'],
        ['software', 'Software'],
        ['user_comment', 'User Comment'],
      ]

      const usedKeys = new Set()
      const basic = []
      const exif = []
      const other = []

      basicFieldOrder.forEach(([key, label]) => {
        if (key in info) {
          basic.push({
            key,
            label,
            value: this.formatPreviewImageInfoValue(info[key]),
          })
          usedKeys.add(key)
        }
      })

      exifFieldOrder.forEach(([key, label]) => {
        if (key in info) {
          exif.push({
            key,
            label,
            value: this.formatPreviewImageInfoValue(info[key]),
          })
          usedKeys.add(key)
        }
      })

      Object.keys(info).forEach((key) => {
        if (usedKeys.has(key)) return

        other.push({
          key,
          label: key,
          value: this.formatPreviewImageInfoValue(info[key]),
        })
      })

      return {
        basic,
        exif,
        other,
      }
    },

    formatPreviewImageInfoValue(value) {
      if (value === null || value === undefined || value === '') return '-'
      if (Array.isArray(value)) return value.join(', ')

      if (typeof value === 'object') {
        try {
          return JSON.stringify(value)
        } catch (e) {
          return String(value)
        }
      }

      return String(value)
    },
  },
}
</script>

<style scoped>
.preview-image-info-body {
  max-height: 65vh;
  overflow: auto;
}

.preview-image-info-section {
  margin-bottom: 20px;
}

.preview-image-info-title {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 10px;
}

.preview-image-info-row {
  display: grid;
  grid-template-columns: 180px 1fr;
  gap: 12px;
  padding: 8px 0;
  border-bottom: 1px solid #ebeef5;
}

.preview-image-info-label {
  color: #606266;
  font-weight: 500;
}

.preview-image-info-value {
  word-break: break-word;
}
</style>