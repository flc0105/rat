<template>
  <el-dialog
    :model-value="visible"
    title="Agent Outputs"
    width="1280px"
    top="4vh"
    class="fixed-dialog agent-outputs-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div class="agent-outputs-toolbar-actions" style="margin-bottom: 12px">
      <el-button
        type="primary"
        plain
        class="toolbar-btn"
        size="small"
        @click="$emit('open-builder')"
      >
        Build Agent
      </el-button>

      <el-button
        class="toolbar-btn"
        size="small"
        :loading="loading"
        @click="$emit('refresh')"
      >
        Refresh
      </el-button>
    </div>

    <div class="agent-outputs-table-wrap">
      <el-table
        :data="outputs"
        v-loading="loading"
        stripe
        border
        style="width: 100%;"
        height="66vh"
        class="dialog-table-shell"
      >
        <el-table-column label="File" min-width="320">
          <template #default="{ row }">
            <div class="agent-output-file-cell">
              <div
                class="agent-output-file-name"
                :title="row.file_name"
              >
                {{ row.file_name || '-' }}
              </div>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="Builder" min-width="100">
          <template #default="{ row }">
            {{ row.builder || '-' }}
          </template>
        </el-table-column>

        <el-table-column label="Version" min-width="200">
          <template #default="{ row }">
            <span>{{ row.build_version || '-' }}</span>
          </template>
        </el-table-column>

        <el-table-column label="OS" min-width="100">
          <template #default="{ row }">
            <el-tag size="small" effect="plain">
              {{ describeAgentTargetOs(row.target_os) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="Arch" min-width="100">
          <template #default="{ row }">
            <el-tag size="small" type="info" effect="plain">
              {{ row.target_arch || '-' }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="Source" min-width="100">
          <template #default="{ row }">
            {{ formatAgentSourceText(row.source) }}
          </template>
        </el-table-column>

        <el-table-column
          label="Socket"
          min-width="180"
          show-overflow-tooltip
        >
          <template #default="{ row }">
            <span class="agent-output-mono">
              {{ formatAgentListenerText(row) }}
            </span>
          </template>
        </el-table-column>

        <el-table-column
          label="Web"
          min-width="220"
          show-overflow-tooltip
        >
          <template #default="{ row }">
            <span class="agent-output-mono">
              {{ formatAgentWebListenerText(row) }}
            </span>
          </template>
        </el-table-column>

        <el-table-column label="Build Time" min-width="200">
          <template #default="{ row }">
            {{ formatDateTimeStandard(row.build_time) }}
          </template>
        </el-table-column>

        <el-table-column label="Size" min-width="120">
          <template #default="{ row }">
            <span>{{ formatBytes(row.size) }}</span>
          </template>
        </el-table-column>

        <el-table-column label="Actions" width="170" fixed="right">
          <template #default="{ row }">
            <div class="agent-output-actions">
              <a
                class="table-action-link"
                :href="row.download_url"
                target="_blank"
              >
                Download
              </a>

              <a
                class="table-action-link danger"
                @click.prevent="$emit('delete-output', row)"
              >
                {{ isAgentOutputDeleting(row.file_name) ? 'Deleting...' : 'Delete' }}
              </a>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'AgentOutputsDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    outputs: {
      type: Array,
      default: () => [],
    },

    loading: {
      type: Boolean,
      default: false,
    },

    describeAgentTargetOs: {
      type: Function,
      required: true,
    },

    formatAgentSourceText: {
      type: Function,
      required: true,
    },

    formatAgentListenerText: {
      type: Function,
      required: true,
    },

    formatAgentWebListenerText: {
      type: Function,
      required: true,
    },

    formatDateTimeStandard: {
      type: Function,
      required: true,
    },

    formatBytes: {
      type: Function,
      required: true,
    },

    isAgentOutputDeleting: {
      type: Function,
      required: true,
    },
  },

  emits: [
    'update:visible',
    'open-builder',
    'refresh',
    'delete-output',
  ],
}
</script>