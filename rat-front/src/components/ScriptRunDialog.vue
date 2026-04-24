<template>
  <el-dialog
    :model-value="visible"
    :title="item ? `Run ${item.display_name || item.script_name}` : 'Run Script'"
    width="680px"
    top="10vh"
    class="fixed-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div
      v-if="item"
      class="fixed-dialog-body"
    >
      <div class="script-run-dialog-top">
        <div class="background-job-module-key mono">
          {{ item.path || item.script_name }}
        </div>

        <div
          v-if="item.description"
          class="script-library-description"
        >
          {{ item.description }}
        </div>

        <div
          class="background-job-module-tags script-run-tags"
        >
          <el-tag
            size="small"
            :type="isScriptSupportedForCurrentConnection(item) ? 'info' : 'danger'"
          >
            {{ formatScriptPlatformLabel(item) }}
          </el-tag>

          <el-tag
            v-if="paramSpecs.length"
            size="small"
            type="warning"
          >
            Params
          </el-tag>
        </div>
      </div>

      <el-form
        v-if="paramSpecs.length"
        label-position="top"
        class="script-library-form"
      >
        <el-form-item
          v-for="param in paramSpecs"
          :key="`script-param-${param.name}`"
          :label="`${param.name} (${param.type || 'string'})`"
        >
          <el-switch
            v-if="param.type === 'boolean'"
            :model-value="paramForm[param.name]"
            @update:model-value="$emit('update-param', param.name, $event)"
          />

          <el-select
            v-else-if="param.type === 'select' && param.options && param.options.length"
            :model-value="paramForm[param.name]"
            class="script-run-select"
            @update:model-value="$emit('update-param', param.name, $event)"
          >
            <el-option
              v-for="option in param.options"
              :key="`${param.name}-${option}`"
              :label="option"
              :value="option"
            />
          </el-select>

          <el-input
            v-else
            :model-value="paramForm[param.name]"
            :placeholder="param.description || param.name"
            @update:model-value="$emit('update-param', param.name, $event)"
          />

          <div class="hint-text script-run-param-hint">
            {{ param.description || 'No description' }}

            <template v-if="param.required">
              · required
            </template>

            <template
              v-if="param.default !== undefined && param.default !== null && param.type !== 'boolean'"
            >
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

      <div
        v-else
        class="empty-state script-run-empty"
      >
        This script has no declared parameters.
      </div>
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
        Run
      </el-button>
    </template>
  </el-dialog>
</template>

<script>
export default {
  name: 'ScriptRunDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    item: {
      type: Object,
      default: null,
    },

    paramSpecs: {
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

    isScriptSupportedForCurrentConnection: {
      type: Function,
      required: true,
    },

    formatScriptPlatformLabel: {
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
.script-run-tags {
  margin-top: 10px;
}

.script-run-select {
  width: 100%;
}

.script-run-param-hint {
  margin-top: 6px;
}

.script-run-empty {
  min-height: 96px;
}
</style>