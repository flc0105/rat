<template>
  <el-dialog
    :model-value="visible"
    :title="item ? `Run ${item.display_name || item.script_name}` : 'Run Script'"
    width="680px"
    top="10vh"
    class="fixed-dialog script-run-dialog"
    modal-class="script-run-overlay"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div
      v-if="item"
      class="fixed-dialog-body script-run-body"
    >
      <div class="script-run-dialog-top">
        <div class="background-job-module-key mono">
          {{ item.path || item.script_name }}
        </div>

        <div
          v-if="item.description"
          class="script-run-description"
        >
          {{ item.description }}
        </div>

        <div class="background-job-module-tags script-run-tags">
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
        class="script-run-form"
      >
        <el-form-item
          v-for="param in paramSpecs"
          :key="`script-param-${param.name}`"
          :label="`${param.name} (${param.type || 'string'})`"
          class="script-run-form-item"
        >
          <el-switch
            v-if="param.type === 'boolean'"
            :model-value="paramForm[param.name]"
            @update:model-value="$emit('update-param', param.name, $event)"
          />

          <el-select
            v-else-if="param.type === 'select' && param.options && param.options.length"
            :model-value="paramForm[param.name]"
            class="script-run-control script-run-select"
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
            class="script-run-control"
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
      <div class="script-run-footer">
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
      </div>
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
.script-run-body {
  gap: 14px;
}

.script-run-dialog-top {
  flex: 0 0 auto;
}

.script-run-description {
  margin-top: 8px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--muted);
  word-break: break-word;
}

.script-run-tags {
  margin-top: 10px;
  margin-bottom: 0;
}

.script-run-form {
  flex: 1 1 auto;
  min-height: 0;
  overflow: auto;
  padding-right: 4px;
}

.script-run-form-item {
  margin-bottom: 16px;
}

.script-run-control,
.script-run-select {
  width: 100%;
}
/*
.script-run-control :deep(.el-input__wrapper),
.script-run-select :deep(.el-select__wrapper) {
  min-height: 34px;
  border-radius: 10px;
}*/

.script-run-param-hint {
  margin-top: 6px;
  line-height: 1.5;
}

.script-run-empty {
  min-height: 96px;
}

.script-run-footer {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

/*
.script-run-footer :deep(.el-button) {
  height: 32px;
  min-height: 32px;
  margin: 0;
  padding-inline: 14px;
  border-radius: 10px;
}
*/

</style>

<style>
/* ScriptRunDialog: 保持运行参数弹窗内部滚动，不挤压页脚按钮。 */
.script-run-overlay .el-dialog {
  display: flex !important;
  flex-direction: column !important;
  max-height: 78vh !important;
  overflow: hidden !important;
}

.script-run-overlay .el-dialog__body {
  flex: 1 1 auto !important;
  min-height: 0 !important;
  overflow: hidden !important;
}

.script-run-overlay .el-dialog__footer {
  flex: 0 0 auto !important;
}

@media (max-width: 768px), (max-height: 720px) {
  .script-run-overlay .el-dialog {
    width: 100vw !important;
    max-width: 100vw !important;
    height: 100dvh !important;
    max-height: 100dvh !important;
    margin: 0 !important;
    border-radius: 0 !important;
  }
}
</style>