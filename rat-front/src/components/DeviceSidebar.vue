<template>
  <aside class="sidebar">
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

<style scoped>
/* ========== 设备侧边栏 ========== */
.sidebar {
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  background: var(--bg-panel);
  border: 1px solid rgba(255, 255, 255, 0.7);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow);
  backdrop-filter: blur(14px);
}

.panel-header {
  padding: 16px 18px;
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
}

.panel-title {
  font-size: 15px;
  font-weight: 700;
}

.sidebar-body {
  padding: 12px;
  overflow-y: auto;
  min-height: 0;
}

/* ========== 设备列表 ========== */
.device-item {
  padding: 14px;
  margin-bottom: 10px;
  border-radius: var(--radius-md);
  background: rgba(255, 255, 255, 0.96);
  border: 1px solid rgba(15, 23, 42, 0.06);
  cursor: pointer;
  transition: border-color 0.18s ease, background 0.18s ease;
}

.device-item:hover {
  border-color: rgba(37, 99, 235, 0.14);
  background: #fff;
}

.device-item.active {
  border-color: rgba(37, 99, 235, 0.22);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(239, 246, 255, 0.96));
}

.device-item-top {
  display: flex;
  align-items: center;
  gap: 12px;
}

.device-text {
  min-width: 0;
  flex: 1;
}

.device-name {
  font-size: 14px;
  font-weight: 700;
  color: var(--text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.device-os {
  margin-top: 4px;
  font-size: 12px;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.device-ip {
  margin-top: 9px;
  font-size: 12px;
  color: var(--muted-2);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.device-status-row {
  margin-top: 7px;
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--muted);
}

.device-status-text {
  line-height: 1.4;
}

.device-status-sep {
  color: var(--muted-2);
}

.device-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  flex-shrink: 0;
}

.device-dot-online {
  background: #22c55e;
}

.device-dot-stale {
  background: #f59e0b;
}

.device-dot-offline {
  background: #94a3b8;
}
</style>