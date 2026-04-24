<template>
  <el-dialog
    :model-value="visible"
    :title="title"
    width="980px"
    top="8vh"
    class="fixed-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <template v-if="displayMode === 'table'">
      <div class="terminal-json-scroll">
        <el-table
          :data="tableRows"
          border
          stripe
          style="width: 100%;"
        >
          <el-table-column
            v-for="column in tableColumns"
            :key="column.prop"
            :prop="column.prop"
            :label="column.label"
            min-width="140"
            show-overflow-tooltip
          />
        </el-table>
      </div>
    </template>

    <template v-else-if="displayMode === 'flat'">
      <div class="terminal-json-scroll">
        <div
          v-for="item in flatRows"
          :key="item.key"
          class="terminal-json-flat-row"
        >
          <div class="terminal-json-flat-label">
            {{ item.label }}
          </div>

          <div class="terminal-json-flat-value">
            {{ item.value }}
          </div>
        </div>
      </div>
    </template>

    <template v-else>
      <div class="terminal-json-scroll">
        <pre class="terminal-json-raw">{{ text }}</pre>
      </div>
    </template>
  </el-dialog>
</template>

<script>
export default {
  name: 'TerminalJsonDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    title: {
      type: String,
      default: '',
    },

    displayMode: {
      type: String,
      default: 'raw',
    },

    tableRows: {
      type: Array,
      default: () => [],
    },

    tableColumns: {
      type: Array,
      default: () => [],
    },

    flatRows: {
      type: Array,
      default: () => [],
    },

    text: {
      type: String,
      default: '',
    },
  },

  emits: ['update:visible'],
}
</script>

<style scoped>
.terminal-json-scroll {
  max-height: 65vh;
  overflow: auto;
}

.terminal-json-flat-row {
  display: grid;
  grid-template-columns: 220px 1fr;
  gap: 12px;
  padding: 8px 0;
  border-bottom: 1px solid #ebeef5;
}

.terminal-json-flat-label {
  color: #606266;
  font-weight: 500;
  word-break: break-word;
}

.terminal-json-flat-value {
  word-break: break-word;
}

.terminal-json-raw {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: monospace;
  font-size: 13px;
  line-height: 1.6;
}
</style>