<template>
  <el-dialog
    :model-value="visible"
    title="Build Agent"
    width="640px"
    @update:model-value="$emit('update:visible', $event)"
  >
    <el-form :model="form" label-width="100px">
      <el-form-item label="Server IP" required>
        <el-input
          v-model="form.server_host"
          placeholder="e.g., 192.168.1.100"
        />
      </el-form-item>

      <el-form-item label="Server Port" required>
        <el-input
          v-model.number="form.server_port"
          type="number"
          placeholder="8000"
        />
      </el-form-item>

      <el-form-item label="Web Port" required>
        <el-input
          v-model.number="form.web_port"
          type="number"
          placeholder="8000"
        />
      </el-form-item>

      <el-form-item label="Target OS">
        <el-radio-group
          v-model="form.target_os"
          :disabled="targetOsDisabled"
        >
          <el-radio label="mac">macOS</el-radio>
          <el-radio label="win">Windows</el-radio>
          <el-radio label="linux">Linux</el-radio>
        </el-radio-group>
      </el-form-item>

      <el-form-item label="Builder">
        <el-radio-group v-model="form.builder">
          <el-radio label="bundle">Bundle</el-radio>
          <el-radio label="pyinstaller">PyInstaller</el-radio>
          <el-radio label="go">Go (Simple)</el-radio>
          <el-radio label="go_loader">Go (Loader)</el-radio>
        </el-radio-group>
      </el-form-item>

      <el-form-item label="Target Arch">
        <el-radio-group
          v-model="form.target_arch"
          :disabled="targetArchDisabled"
        >
          <el-radio label="amd64">amd64</el-radio>
          <el-radio label="arm64">arm64</el-radio>
        </el-radio-group>
      </el-form-item>

      <el-alert
        type="info"
        :closable="false"
        show-icon
      >
        <template #default>
          <div class="agent-builder-alert-text">
            {{ builderAlertText }}
          </div>
        </template>
      </el-alert>
    </el-form>

    <template #footer>
      <el-button @click="$emit('update:visible', false)">
        Cancel
      </el-button>

      <el-button
        type="primary"
        :loading="building"
        @click="$emit('build')"
      >
        Build & Download
      </el-button>
    </template>
  </el-dialog>
</template>

<script>
export default {
  name: 'AgentBuilderDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    form: {
      type: Object,
      required: true,
    },

    builderAlertText: {
      type: String,
      default: '',
    },

    building: {
      type: Boolean,
      default: false,
    },

    targetOsDisabled: {
      type: Boolean,
      default: false,
    },

    targetArchDisabled: {
      type: Boolean,
      default: false,
    },
  },

  emits: [
    'update:visible',
    'build',
  ],
}
</script>

<style scoped>
.agent-builder-alert-text {
  white-space: pre-line;
  line-height: 1.7;
  font-size: 12px;
}
</style>