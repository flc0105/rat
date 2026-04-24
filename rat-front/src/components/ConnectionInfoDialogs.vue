<template>
  <el-dialog
    :model-value="infoVisible"
    title="Connection Info"
    width="980px"
    top="6vh"
    class="fixed-dialog connection-info-dialog"
    @update:model-value="$emit('update:infoVisible', $event)"
  >
    <div class="fixed-dialog-body" v-loading="loading">
      <div class="background-job-stats connection-info-stats-grid">
        <div
          v-for="item in cards"
          :key="item.label"
          class="background-job-stat connection-info-stat connection-info-stat-expandable"
          @click="$emit('open-value', item)"
        >
          <div class="background-job-stat-label connection-info-stat-label">
            {{ item.label }}
          </div>

          <div
            class="background-job-stat-value connection-info-stat-value"
            :class="{ mono: item.mono }"
          >
            {{ item.fullValue }}
          </div>
        </div>
      </div>

      <div class="background-job-panel connection-command-panel">
        <div class="background-job-panel-title">Command List</div>

        <div class="background-job-message-list">
          <div
            v-for="(item, index) in commands"
            :key="`${item.template}-${index}`"
            class="background-job-message-item"
          >
            <div class="background-job-message-time">
              <span v-if="item.group">{{ item.group }}</span>
            </div>

            <div class="background-job-message-text">
              <span class="mono">{{ item.name || item.template }}</span>
              <span v-if="item.help"> — {{ item.help }}</span>
            </div>
          </div>

          <div v-if="!commands.length" class="empty-state compact">
            No commands available
          </div>
        </div>
      </div>
    </div>
  </el-dialog>

  <el-dialog
    :model-value="valueVisible"
    :title="valueTitle || 'Details'"
    width="760px"
    top="12vh"
    class="fixed-dialog"
    @update:model-value="$emit('update:valueVisible', $event)"
  >
    <div class="fixed-dialog-body">
      <pre class="connection-info-full-value">{{ valueValue || '-' }}</pre>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'ConnectionInfoDialogs',

  props: {
    infoVisible: {
      type: Boolean,
      default: false,
    },

    valueVisible: {
      type: Boolean,
      default: false,
    },

    loading: {
      type: Boolean,
      default: false,
    },

    cards: {
      type: Array,
      default: () => [],
    },

    commands: {
      type: Array,
      default: () => [],
    },

    valueTitle: {
      type: String,
      default: '',
    },

    valueValue: {
      type: String,
      default: '',
    },
  },

  emits: [
    'update:infoVisible',
    'update:valueVisible',
    'open-value',
  ],
}
</script>