<template>
  <canvas ref="canvas" class="screen-view-image screen-view-delta-canvas" />
</template>

<script>
export default {
  name: 'KeyframeDeltaScreenRenderer',

  data() {
    return {
      baseCanvas: null,
      baseSeq: 0,
      renderQueue: Promise.resolve(),
      renderGeneration: 0,
    }
  },

  mounted() {
    this.baseCanvas = document.createElement('canvas')
  },

  methods: {
    reset() {
      this.renderGeneration += 1
      this.baseSeq = 0
      this.renderQueue = Promise.resolve()

      const canvas = this.$refs.canvas
      if (canvas) {
        canvas.width = 0
        canvas.height = 0
      }
      if (this.baseCanvas) {
        this.baseCanvas.width = 0
        this.baseCanvas.height = 0
      }
    },

    applyFrame(frame = {}) {
      const generation = this.renderGeneration
      this.renderQueue = this.renderQueue
        .then(() => this.renderFrame(frame, generation))
        .catch(() => false)
      return this.renderQueue
    },

    async renderFrame(frame, generation) {
      if (generation !== this.renderGeneration) return false

      const frameType = String(frame.frame_type || '').trim().toLowerCase()
      if (frameType === 'keyframe') {
        return this.renderKeyframe(frame, generation)
      }
      if (frameType === 'delta') {
        return this.renderDelta(frame, generation)
      }
      return false
    },

    async renderKeyframe(frame, generation) {
      const width = Number(frame.width || 0)
      const height = Number(frame.height || 0)
      const seq = Number(frame.seq || 0)
      if (!width || !height || !seq || !frame.frame) return false

      const image = await this.decodeJpeg(frame.frame)
      if (generation !== this.renderGeneration) return false

      const canvas = this.$refs.canvas
      if (!canvas || !this.baseCanvas) return false

      canvas.width = width
      canvas.height = height
      this.baseCanvas.width = width
      this.baseCanvas.height = height

      const baseContext = this.baseCanvas.getContext('2d')
      const context = canvas.getContext('2d')
      if (!baseContext || !context) return false

      baseContext.clearRect(0, 0, width, height)
      baseContext.drawImage(image, 0, 0, width, height)
      context.clearRect(0, 0, width, height)
      context.drawImage(this.baseCanvas, 0, 0)
      this.baseSeq = seq
      return true
    },

    async renderDelta(frame, generation) {
      const canvas = this.$refs.canvas
      if (!canvas || !this.baseCanvas || !this.baseSeq) return false

      const baseSeq = Number(frame.base_seq || 0)
      const width = Number(frame.width || 0)
      const height = Number(frame.height || 0)
      if (baseSeq !== this.baseSeq || width !== canvas.width || height !== canvas.height) return false
      if (!frame.frame) return false

      const image = await this.decodeJpeg(frame.frame)
      if (generation !== this.renderGeneration || baseSeq !== this.baseSeq) return false

      const patchX = Number(frame.patch_x || 0)
      const patchY = Number(frame.patch_y || 0)
      const patchWidth = Number(frame.patch_width || 0)
      const patchHeight = Number(frame.patch_height || 0)
      if (!patchWidth || !patchHeight) return false

      const context = canvas.getContext('2d')
      if (!context) return false

      // 每个 Delta 都从固定 Keyframe 重建，确保中间 Delta 被丢弃也不会污染当前画面。
      context.clearRect(0, 0, width, height)
      context.drawImage(this.baseCanvas, 0, 0)
      context.drawImage(image, patchX, patchY, patchWidth, patchHeight)
      return true
    },

    decodeJpeg(base64Data) {
      return new Promise((resolve, reject) => {
        const image = new Image()
        image.onload = () => resolve(image)
        image.onerror = () => reject(new Error('Failed to decode screen frame'))
        image.src = `data:image/jpeg;base64,${base64Data}`
      })
    },
  },
}
</script>
