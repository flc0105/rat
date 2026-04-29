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

    statusNowTick: {
      type: Number,
      default: () => Date.now(),
    },
  },

  emits: ['refresh', 'select'],

  methods: {
    // 根据连接状态统一计算设备展示态
    getConnectionDisplayState(conn) {
      const state = String((conn && conn.connection_state) || '').trim()
      if (state === 'offline') return 'offline'

      if (conn && conn.is_transfer_active) {
        return 'online'
      }

      const disconnectedAt = String((conn && conn.disconnected_at) || '').trim()
      if (disconnectedAt) return 'offline'

      const lastSeenAt = String((conn && conn.last_seen_at) || '').trim()
      if (!lastSeenAt) return state || 'online'

      const staleAfterSeconds = Number((conn && conn.stale_after_seconds) || 45)
      const seenMs = Date.parse(lastSeenAt)
      if (!Number.isFinite(seenMs)) return state || 'online'

      const ageMs = Math.max(this.statusNowTick - seenMs, 0)
      if (ageMs > staleAfterSeconds * 1000) return 'stale'

      return 'online'
    },

    getConnectionStatusDotClass(conn) {
      const state = this.getConnectionDisplayState(conn)
      if (state === 'online') return 'device-dot-online'
      if (state === 'stale') return 'device-dot-stale'
      return 'device-dot-offline'
    },

    getConnectionStatusText(conn) {
      const state = this.getConnectionDisplayState(conn)
      if (state === 'online') return 'online'
      if (state === 'stale') return 'stale'
      return 'offline'
    },

    formatConnectionLastSeenRelative(conn) {
      if (!conn) return '-'

      const state = this.getConnectionDisplayState(conn)
      const baseText = state === 'offline'
        ? String(conn.disconnected_at || '').trim()
        : String(conn.last_seen_at || '').trim()

      if (!baseText) return '-'

      const ts = Date.parse(baseText)
      if (!Number.isFinite(ts)) return '-'

      const diffMs = Math.max(this.statusNowTick - ts, 0)
      const diffSec = Math.floor(diffMs / 1000)

      if (diffSec < 5) return 'just now'
      if (diffSec < 60) return `${diffSec}s ago`

      const diffMin = Math.floor(diffSec / 60)
      if (diffMin < 60) return `${diffMin}m ago`

      const diffHour = Math.floor(diffMin / 60)
      if (diffHour < 24) return `${diffHour}h ago`

      const diffDay = Math.floor(diffHour / 24)
      return `${diffDay}d ago`
    },

    formatOsLabel(osType, osVer) {
      const type = osType || 'Unknown'
      return osVer ? `${type}` : type
    },

    formatAddress(addr) {
      if (!addr) return '-'
      const raw = String(addr)
      const parts = raw.split(':')
      if (parts.length >= 2) return parts.slice(0, -1).join(':') || raw
      return raw
    },
  },
}
</script>

<style scoped>
/* ========== 设备侧边栏 ========== */
.sidebar {
  display: flex;
  flex-direction: column;
  min-height: 0;
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