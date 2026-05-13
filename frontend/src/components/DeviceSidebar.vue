<template>
  <aside class="sidebar panel">
    <div class="panel-header">
      <div class="panel-title">Devices</div>

      <el-dropdown
        trigger="click"
        placement="bottom-end"
        popper-class="device-toolbar-menu-popper"
        @command="handleToolbarCommand"
      >
        <button
          type="button"
          class="device-toolbar-more-btn"
          title="Device actions"
          @click.stop
        >
          ⋮
        </button>

        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="refresh">
              Refresh
            </el-dropdown-item>

            <el-dropdown-item command="toggle-hidden">
              {{ showHiddenDevices ? 'Hide hidden devices' : 'Show hidden devices' }}
            </el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>

    <div class="sidebar-body">
      <div v-if="connections.length === 0" class="empty-state">
        No visible devices
      </div>

      <div
        v-for="item in connections"
        :key="item.client_id"
        class="device-item"
        :class="{
          active: selectedId === item.client_id,
          'device-item-hidden': item.device_hidden,
          'context-active': contextMenuClientId === item.client_id,
        }"
        @click="handleDeviceClick(item, $event)"
        @contextmenu.prevent.stop="openDeviceContextMenu($event, item)"
        @touchstart="handleDeviceTouchStart($event, item)"
        @touchmove="handleDeviceTouchMove"
        @touchend="handleDeviceTouchEnd"
        @touchcancel="handleDeviceTouchEnd"
      >
        <div class="device-item-top">
          <div class="device-text">
            <div class="device-name">
              {{ formatDeviceName(item) }}
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

    <Teleport to="body">
      <div
        v-if="contextMenuVisible"
        ref="deviceContextMenuRef"
        class="device-context-menu"
        :style="contextMenuStyle"
        @click.stop
        @contextmenu.prevent.stop
      >
        <button
          type="button"
          class="device-context-menu-item"
          @click="triggerDeviceContextCommand('rename-machine')"
        >
          Set alias
        </button>

        <div class="device-context-menu-separator"></div>

        <button
          type="button"
          class="device-context-menu-item danger"
          :class="{ positive: contextMenuItem && contextMenuItem.device_hidden_by_client }"
          @click="triggerDeviceContextCommand('toggle-client-hidden')"
        >
          {{ contextMenuItem && contextMenuItem.device_hidden_by_client ? 'Unhide current connection' : 'Hide current connection' }}
        </button>

        <button
          type="button"
          class="device-context-menu-item danger"
          :class="{ positive: contextMenuItem && contextMenuItem.device_hidden_by_machine }"
          :disabled="!contextMenuItem || !contextMenuItem.machine_id"
          @click="triggerDeviceContextCommand('toggle-machine-hidden')"
        >
          {{ contextMenuItem && contextMenuItem.device_hidden_by_machine ? 'Unhide this machine' : 'Hide this machine' }}
        </button>
      </div>
    </Teleport>
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

    showHiddenDevices: {
      type: Boolean,
      default: false,
    },
  },

  emits: [
    'refresh',
    'select',
    'toggle-hidden-devices',
    'toggle-client-hidden',
    'toggle-machine-hidden',
    'rename-machine',
  ],

  data() {
    return {
      contextMenuVisible: false,
      contextMenuClientId: '',
      contextMenuItem: null,
      contextMenuX: 0,
      contextMenuY: 0,

      touchMenuTimer: null,
      touchStartX: 0,
      touchStartY: 0,
      touchMoved: false,
      suppressNextDeviceClick: false,

      // 移动端长按打开菜单后，浏览器可能补发 click / scroll。
      // 这两个时间窗用来避免菜单刚打开又被自动关闭。
      ignoreNextDocumentClickUntil: 0,
      ignoreNextScrollUntil: 0,
    }
  },

  computed: {
    contextMenuStyle() {
      return {
        left: `${this.contextMenuX}px`,
        top: `${this.contextMenuY}px`,
      }
    },
  },

  mounted() {
    document.addEventListener('click', this.handleDocumentClick, true)
    document.addEventListener('keydown', this.handleDocumentKeydown, true)
    window.addEventListener('resize', this.closeDeviceContextMenu)
    window.addEventListener('scroll', this.handleWindowScroll, true)
  },

  beforeUnmount() {
    document.removeEventListener('click', this.handleDocumentClick, true)
    document.removeEventListener('keydown', this.handleDocumentKeydown, true)
    window.removeEventListener('resize', this.closeDeviceContextMenu)
    window.removeEventListener('scroll', this.handleWindowScroll, true)
    this.clearDeviceTouchTimer()
    document.body.classList.remove('device-touch-callout-guard')
  },

  methods: {
    handleToolbarCommand(command) {
      if (command === 'refresh') {
        this.$emit('refresh')
        return
      }

      if (command === 'toggle-hidden') {
        this.$emit('toggle-hidden-devices')
      }
    },

    handleDeviceClick(item, event) {
      if (this.suppressNextDeviceClick) {
        this.suppressNextDeviceClick = false

        if (event && typeof event.preventDefault === 'function') {
          event.preventDefault()
        }

        if (event && typeof event.stopPropagation === 'function') {
          event.stopPropagation()
        }

        return
      }

      this.closeDeviceContextMenu()
      this.$emit('select', item.client_id)
    },

    openDeviceContextMenu(event, item) {
      this.openDeviceContextMenuAt(event.clientX, event.clientY, item, {
        fromTouch: false,
      })
    },

    openDeviceContextMenuAt(x, y, item, options = {}) {
      this.clearDeviceTouchTimer()

      const now = Date.now()

      // 移动端长按打开菜单后，浏览器可能补发一次 click。
      // document 捕获阶段会先收到这个 click，如果不忽略，菜单会刚出现就关闭。
      this.ignoreNextDocumentClickUntil = now + 420

      // 长按附近可能伴随轻微滚动 / 惯性滚动，不要刚打开就被 scroll 关掉。
      if (options.fromTouch) {
        this.ignoreNextScrollUntil = now + 420
      }

      this.contextMenuItem = item
      this.contextMenuClientId = String(item?.client_id || '')
      this.contextMenuX = x
      this.contextMenuY = y
      this.contextMenuVisible = true

      this.$nextTick(() => {
        this.adjustDeviceContextMenuPosition()
      })
    },

    clearDeviceTouchTimer() {
      if (this.touchMenuTimer) {
        window.clearTimeout(this.touchMenuTimer)
        this.touchMenuTimer = null
      }
    },

    handleDeviceTouchStart(event, item) {
      if (!event.touches || event.touches.length !== 1) return

      const touch = event.touches[0]

      this.clearDeviceTouchTimer()

      this.touchStartX = touch.clientX
      this.touchStartY = touch.clientY
      this.touchMoved = false
      this.suppressNextDeviceClick = false

      // 不在 touchstart 立刻 preventDefault，否则会阻止列表上下滚动。
      // 先用 body class 尽量压住 iOS 的 Copy / Look Up。
      document.body.classList.add('device-touch-callout-guard')

      this.touchMenuTimer = window.setTimeout(() => {
        if (this.touchMoved) return

        // 到这里说明是真的长按，不是滑动。
        // 这里再 preventDefault，尽量阻止 iOS 长按系统菜单。
        if (event.cancelable && typeof event.preventDefault === 'function') {
          event.preventDefault()
        }

        this.suppressNextDeviceClick = true
        this.openDeviceContextMenuAt(this.touchStartX, this.touchStartY, item, {
          fromTouch: true,
        })
      }, 520)
    },

    handleDeviceTouchMove(event) {
      if (!this.touchMenuTimer || !event.touches || event.touches.length !== 1) return

      const touch = event.touches[0]
      const dx = Math.abs(touch.clientX - this.touchStartX)
      const dy = Math.abs(touch.clientY - this.touchStartY)

      // 用户开始上下滑动，取消长按菜单，保留浏览器原生滚动。
      if (dx > 8 || dy > 8) {
        this.touchMoved = true
        this.clearDeviceTouchTimer()
        document.body.classList.remove('device-touch-callout-guard')
      }
    },

    handleDeviceTouchEnd() {
      this.clearDeviceTouchTimer()

      if (!this.contextMenuVisible) {
        document.body.classList.remove('device-touch-callout-guard')
      }
    },

    adjustDeviceContextMenuPosition() {
      const menu = this.$refs.deviceContextMenuRef
      if (!menu) return

      const rect = menu.getBoundingClientRect()
      const padding = 8
      const maxX = window.innerWidth - rect.width - padding
      const maxY = window.innerHeight - rect.height - padding

      this.contextMenuX = Math.max(padding, Math.min(this.contextMenuX, maxX))
      this.contextMenuY = Math.max(padding, Math.min(this.contextMenuY, maxY))
    },

    closeDeviceContextMenu() {
      this.contextMenuVisible = false
      this.contextMenuClientId = ''
      this.contextMenuItem = null
      this.ignoreNextDocumentClickUntil = 0
      this.ignoreNextScrollUntil = 0
      document.body.classList.remove('device-touch-callout-guard')
    },

    handleDocumentClick(event) {
      if (!this.contextMenuVisible) return

      if (Date.now() < this.ignoreNextDocumentClickUntil) {
        return
      }

      const menu = this.$refs.deviceContextMenuRef
      if (menu && menu.contains(event.target)) return

      this.closeDeviceContextMenu()
    },

    handleDocumentKeydown(event) {
      if (event.key === 'Escape') {
        this.closeDeviceContextMenu()
      }
    },

    handleWindowScroll() {
      if (!this.contextMenuVisible) return

      if (Date.now() < this.ignoreNextScrollUntil) {
        return
      }

      this.closeDeviceContextMenu()
    },

    triggerDeviceContextCommand(command) {
      const item = this.contextMenuItem
      if (!item) return

      if (command === 'rename-machine') {
        this.$emit('rename-machine', item)
      } else if (command === 'toggle-client-hidden') {
        this.$emit('toggle-client-hidden', item)
      } else if (command === 'toggle-machine-hidden') {
        this.$emit('toggle-machine-hidden', item)
      }

      this.closeDeviceContextMenu()
    },

    formatDeviceName(item) {
      return item?.device_display_name || item?.display_hostname || item?.device_alias || item?.hostname || 'Unknown Host'
    },

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

.device-toolbar-more-btn {
  width: 24px;
  height: 24px;
  padding: 0;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--muted);
  font-size: 17px;
  line-height: 1;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
}

.device-toolbar-more-btn:hover {
  background: rgba(15, 23, 42, 0.06);
  color: var(--text);
}

.sidebar-body {
  padding: 12px;
  overflow-y: auto;
  min-height: 0;
}

/* ========== 设备列表 ========== */
.device-item {
  -webkit-touch-callout: none;
  user-select: none;
  padding: 14px;
  margin-bottom: 10px;
  border-radius: var(--radius-md);
  background: rgba(255, 255, 255, 0.96);
  border: 1px solid rgba(15, 23, 42, 0.06);
  cursor: pointer;
  transition: border-color 0.18s ease, background 0.18s ease, opacity 0.18s ease;
}

.device-item:hover {
  border-color: rgba(37, 99, 235, 0.14);
  background: #fff;
}

.device-item.active {
  border-color: rgba(37, 99, 235, 0.22);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(239, 246, 255, 0.96));
}

.device-item.context-active {
  border-color: rgba(37, 99, 235, 0.34);
}

.device-item-hidden:not(.active) {
  opacity: 0.64;
  border-style: dashed;
}

.device-item-hidden.active {
  border-style: dashed;
}

.device-item-hidden .device-name,
.device-item-hidden .device-os,
.device-item-hidden .device-ip,
.device-item-hidden .device-status-row {
  color: #64748b;
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

<style>
body.device-touch-callout-guard,
body.device-touch-callout-guard * {
  -webkit-touch-callout: none !important;
  -webkit-user-select: none !important;
  user-select: none !important;
}

.device-context-menu {
  position: fixed;
  z-index: 5000;
  min-width: 176px;
  padding: 4px;
  border-radius: 8px;
  border: 1px solid rgba(15, 23, 42, 0.12);
  background: #fff;
  box-shadow: 0 10px 28px rgba(15, 23, 42, 0.18);
  user-select: none;
  -webkit-user-select: none;
  -moz-user-select: none;
  -ms-user-select: none;
  -webkit-touch-callout: none;
}

.device-context-menu-item {
  -webkit-touch-callout: none;
  display: block;
  width: 100%;
  height: 28px;
  padding: 0 10px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: #111827;
  font-size: 12px;
  line-height: 28px;
  text-align: left;
  white-space: nowrap;
  cursor: pointer;
}

.device-context-menu-item:hover {
  background: #f1f5f9;
}

.device-context-menu-item.danger:hover {
  background: #fff1f2;
  color: #be123c;
}

.device-context-menu-item.positive:hover {
  background: #ecfdf5;
  color: #047857;
}

.device-context-menu-item:disabled {
  color: #9ca3af;
  cursor: not-allowed;
}

.device-context-menu-item:disabled:hover {
  background: transparent;
  color: #9ca3af;
}

.device-context-menu-separator {
  height: 1px;
  margin: 4px 2px;
  background: rgba(15, 23, 42, 0.08);
}

.device-toolbar-menu-popper {
  min-width: 156px !important;
  border-radius: 8px !important;
  border: 1px solid rgba(15, 23, 42, 0.12) !important;
  box-shadow: 0 10px 26px rgba(15, 23, 42, 0.16) !important;
  overflow: hidden !important;
}

.device-toolbar-menu-popper .el-dropdown-menu {
  padding: 4px !important;
}

.device-toolbar-menu-popper .el-dropdown-menu__item {
  height: 28px !important;
  min-height: 28px !important;
  line-height: 28px !important;
  padding: 0 10px !important;
  border-radius: 6px !important;
  font-size: 12px !important;
  color: #111827 !important;
}

.device-toolbar-menu-popper .el-dropdown-menu__item:not(.is-disabled):hover,
.device-toolbar-menu-popper .el-dropdown-menu__item:not(.is-disabled):focus {
  background: #f1f5f9 !important;
  color: #111827 !important;
}
</style>
