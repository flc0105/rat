<template>
  <el-dialog
    :model-value="visible"
    title="Message"
    width="760px"
    top="8vh"
    class="fixed-dialog background-job-message-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div class="fixed-dialog-body">
      <div class="background-job-full-message-time">
        {{ formatDateTimeStandard(safeMessage.time) || '-' }}
      </div>

      <pre
        class="background-job-full-message-text"
        :class="{ 'is-error': safeMessage.status === 0, 'is-success': safeMessage.status === 1 }"
      >{{ formatBackgroundJobMessageText(safeMessage.text || '') }}</pre>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'BackgroundJobMessageDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },
    message: {
      type: Object,
      default: () => ({}),
    },
    formatDateTimeStandard: {
      type: Function,
      required: true,
    },
    formatBackgroundJobMessageText: {
      type: Function,
      required: true,
    },
  },

  emits: ['update:visible'],

  computed: {
    safeMessage() {
      return this.message || {}
    },
  },
}
</script>