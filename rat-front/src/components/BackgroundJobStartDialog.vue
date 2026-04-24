<template>
  <el-dialog
    :model-value="visible"
    :title="item ? `Start ${item.display_name || item.job_name}` : 'Start Background Job'"
    width="640px"
    top="10vh"
    class="fixed-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div
      v-if="item"
      class="fixed-dialog-body"
    >
      <div class="background-jobs-section-title">
        {{ item.description || 'Configure job parameters before starting' }}
      </div>

      <div class="background-job-module-tags background-job-start-tags">
        <el-tag
          size="small"
          :type="isJobSupportedForCurrentConnection(item) ? 'info' : 'danger'"
        >
          {{ formatJobPlatformLabel(item.metadata?.platforms || []) }}
        </el-tag>
      </div>

      <el-form label-position="top">
        <el-form-item
          v-for="param in params"
          :key="`job-param-${param.name}`"
          :label="`${param.name} (${param.type || 'string'})`"
        >
          <el-input
            :model-value="paramForm[param.name]"
            :placeholder="param.description || param.name"
            @update:model-value="$emit('update-param', param.name, $event)"
          />

          <div class="hint-text background-job-param-hint">
            {{ param.description || 'No description' }}

            <template v-if="param.required">
              · required
            </template>

            <template v-if="param.default !== undefined && param.default !== null">
              · default: {{ param.default }}
            </template>

            <template v-if="param.min !== undefined">
              · min: {{ param.min }}
            </template>

            <template v-if="param.max !== undefined">
              · max: {{ param.max }}
            </template>
          </div>
        </el-form-item>
      </el-form>
    </div>

    <template #footer>
      <el-button @click="$emit('cancel')">
        Cancel
      </el-button>

      <el-button
        type="primary"
        :loading="submitting"
        @click="$emit('confirm')"
      >
        Start
      </el-button>
    </template>
  </el-dialog>
</template>

<script>
export default {
  name: 'BackgroundJobStartDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },
    item: {
      type: Object,
      default: null,
    },
    params: {
      type: Array,
      default: () => [],
    },
    paramForm: {
      type: Object,
      default: () => ({}),
    },
    submitting: {
      type: Boolean,
      default: false,
    },
    isJobSupportedForCurrentConnection: {
      type: Function,
      required: true,
    },
    formatJobPlatformLabel: {
      type: Function,
      required: true,
    },
  },

  emits: [
    'update:visible',
    'update-param',
    'cancel',
    'confirm',
  ],
}
</script>

<style scoped>
.background-job-start-tags {
  margin-bottom: 12px;
}

.background-job-param-hint {
  margin-top: 6px;
}
</style>