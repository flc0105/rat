<template>
  <div class="command-row">
    <div
      class="command-box command-box-full"
      style="display: flex; gap: 8px; align-items: center;"
    >
      <div class="command-autocomplete-shell" style="flex: 1; min-width: 0;">
        <el-autocomplete
          ref="commandInputRef"
          :model-value="modelValue"
          :fetch-suggestions="queryCommandCandidates"
          popper-class="command-autocomplete-popper"
          class="command-autocomplete"
          value-key="value"
          placeholder="Enter a command."
          autocomplete="off"
          @update:model-value="$emit('update:modelValue', $event)"
          @select="$emit('select-candidate', $event)"
          @keyup.enter="$emit('run')"
        >
          <template #default="{ item }">
            <div class="command-autocomplete-item">
              <div class="command-autocomplete-item-main">
                <div
                  class="command-autocomplete-item-name"
                  :title="item.template || item.value || '-'"
                >
                  {{ item.template || item.value || '-' }}
                </div>

                <div
                  v-if="item.help"
                  class="command-autocomplete-item-desc"
                  :title="item.help"
                >
                  {{ item.help }}
                </div>
              </div>

              <div
                v-if="item.groupLabel"
                class="command-autocomplete-item-group"
              >
                {{ item.groupLabel }}
              </div>
            </div>
          </template>
        </el-autocomplete>
      </div>

      <button
        class="run-button"
        :disabled="sending || hasRunningWebTask"
        style="white-space: nowrap;"
        @click="$emit('run')"
      >
        <span v-if="!sending && !hasRunningWebTask">Run</span>
        <span v-else-if="sending">...</span>
        <span v-else>Busy</span>
      </button>

      <el-button
        class="run-button tool-btn-danger"
        :disabled="!hasRunningWebTask"
        :loading="currentTaskIsCancelling"
        style="white-space: nowrap;"
        @click="$emit('cancel')"
      >
        Cancel
      </el-button>
    </div>
  </div>
</template>

<script>
export default {
  name: 'CommandInputBar',

  props: {
    modelValue: {
      type: String,
      default: '',
    },

    sending: {
      type: Boolean,
      default: false,
    },

    hasRunningWebTask: {
      type: Boolean,
      default: false,
    },

    currentTaskIsCancelling: {
      type: Boolean,
      default: false,
    },

    queryCommandCandidates: {
      type: Function,
      required: true,
    },
  },

  emits: [
    'update:modelValue',
    'select-candidate',
    'run',
    'cancel',
  ],

  methods: {
    focusInput() {
      const input = this.$refs.commandInputRef

      if (input && typeof input.focus === 'function') {
        input.focus()
      }
    },

    closeAutocomplete() {
      const input = this.$refs.commandInputRef

      if (input && typeof input.close === 'function') {
        input.close()
      }
    },
  },
}
</script>