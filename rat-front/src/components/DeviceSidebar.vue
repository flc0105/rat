<template>
  <aside class="sidebar panel">
    <div class="panel-header">
      <div class="panel-title">Devices</div>
      <el-button size="small" @click="$emit('refresh')">Refresh</el-button>
    </div>

    <div class="sidebar-body">
      <div v-if="connections.length === 0" class="empty-state">
        No active devices
      </div>

      <div
        v-for="item in connections"
        :key="item.client_id"
        class="device-item"
        :class="{ active: selectedId === item.client_id }"
        @click="$emit('select', item.client_id)"
      >
        <div class="device-item-top">
          <div class="device-text">
            <div class="device-name">
              {{ item.hostname || 'Unknown Host' }}
            </div>
            <div class="device-os">
              {{ formatOsLabel(item.os_type, item.os_ver) }}
            </div>
          </div>

          <div
            class="device-dot"
            :class="getConnectionStatusDotClass(item)"
          ></div>
        </div>

        <div class="device-ip">
          {{ formatAddress(item.addr) }}
        </div>

        <div class="device-status-row">
          <span class="device-status-text">
            {{ getConnectionStatusText(item) }}
          </span>
          <span class="device-status-sep">·</span>
          <span class="device-status-text">
            last seen {{ formatConnectionLastSeenRelative(item) }}
          </span>
        </div>
      </div>
    </div>
  </aside>
</template>

<script>
export default {
  name: 'DeviceSidebar',

  props: {
    connections: {
      type: Array,
      default: () => [],
    },

    selectedId: {
      type: String,
      default: '',
    },

    formatOsLabel: {
      type: Function,
      required: true,
    },

    formatAddress: {
      type: Function,
      required: true,
    },

    getConnectionStatusDotClass: {
      type: Function,
      required: true,
    },

    getConnectionStatusText: {
      type: Function,
      required: true,
    },

    formatConnectionLastSeenRelative: {
      type: Function,
      required: true,
    },
  },

  emits: ['refresh', 'select'],
}
</script>