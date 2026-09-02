<template>
  <el-drawer
    v-model="visible"
    direction="rtl"
    size="430px"
    :with-header="false"
    class="transfer-center-drawer"
  >
    <div class="transfer-center-shell">
      <div class="transfer-center-header">
        <div>
          <div class="transfer-center-title">Transfers</div>
          <div class="transfer-center-subtitle">
            {{ activeTransfers.length }} active
          </div>
        </div>

        <button
          class="transfer-center-close"
          type="button"
          title="Close"
          @click="visible = false"
        >
          <el-icon><Close /></el-icon>
        </button>
      </div>

      <section v-if="activeTransfers.length" class="transfer-center-section">
        <div class="transfer-center-section-title">Active</div>

        <article
          v-for="transfer in activeTransfers"
          :key="transfer.transfer_id"
          class="transfer-card"
        >
          <div class="transfer-card-head">
            <div class="transfer-direction">{{ directionSymbol(transfer) }}</div>
            <div class="transfer-card-main">
              <div class="transfer-card-title">{{ transfer.filename || 'File transfer' }}</div>
              <div class="transfer-card-meta">{{ transferSubtitle(transfer) }}</div>
            </div>
            <div class="transfer-card-percent">
              {{ formatPercent(transfer.percent) }}
            </div>
          </div>

          <el-progress
            v-if="hasProgress(transfer)"
            :percentage="normalizedPercent(transfer.percent)"
            :stroke-width="6"
            :show-text="false"
          />
          <div v-else class="transfer-indeterminate" aria-hidden="true">
            <span></span>
          </div>

          <div class="transfer-card-status-row">
            <span>{{ stageLabel(transfer) }}</span>
            <span v-if="hasProgress(transfer)">
              {{ formatBytes(transfer.transferred_bytes) }} / {{ formatBytes(transfer.total_bytes) }}
            </span>
          </div>

          <div v-if="transfer.speed_bytes_per_sec > 0" class="transfer-card-detail">
            {{ formatRate(transfer.speed_bytes_per_sec) }}
            <template v-if="transfer.eta_seconds != null">
              · {{ formatEta(transfer.eta_seconds) }} left
            </template>
          </div>

          <div
            v-if="transfer.progress_supported === false && transfer.stage === 'staging'"
            class="transfer-card-detail"
          >
            Legacy HTTP mode · byte progress unavailable
          </div>
        </article>
      </section>

      <section v-if="recentTransfers.length" class="transfer-center-section transfer-center-recent">
        <div class="transfer-center-section-title">Recent</div>

        <article
          v-for="transfer in recentTransfers"
          :key="transfer.transfer_id"
          class="transfer-recent-row"
        >
          <div
            class="transfer-recent-icon"
            :class="transfer.state === 'failed' ? 'is-failed' : 'is-completed'"
          >
            <el-icon>
              <CircleCloseFilled v-if="transfer.state === 'failed'" />
              <CircleCheckFilled v-else />
            </el-icon>
          </div>

          <div class="transfer-recent-main">
            <div class="transfer-recent-title">{{ transfer.filename || 'File transfer' }}</div>
            <div class="transfer-recent-meta">
              {{ transfer.state === 'failed' ? (transfer.error || 'Transfer failed') : transferSubtitle(transfer) }}
            </div>
          </div>

          <div class="transfer-recent-state">
            {{ transfer.state === 'failed' ? 'Failed' : 'Completed' }}
          </div>
        </article>
      </section>

      <div v-if="!activeTransfers.length && !recentTransfers.length" class="transfer-center-empty">
        <div class="transfer-center-empty-symbol">⇅</div>
        <div class="transfer-center-empty-title">No transfers</div>
        <div class="transfer-center-empty-text">
          Active file transfers will appear here.
        </div>
      </div>
    </div>
  </el-drawer>
</template>

<script>
import {
  CircleCheckFilled,
  CircleCloseFilled,
  Close,
} from '@element-plus/icons-vue'

export default {
  components: {
    CircleCheckFilled,
    CircleCloseFilled,
    Close,
  },

  props: {
    transfers: {
      type: Array,
      default: () => [],
    },
  },

  data() {
    return {
      visible: false,
    }
  },

  computed: {
    activeTransfers() {
      return (this.transfers || []).filter(item => item?.state === 'running')
    },

    recentTransfers() {
      return (this.transfers || [])
        .filter(item => item?.state && item.state !== 'running')
        .slice(0, 50)
    },
  },

  methods: {
    open() {
      this.visible = true
    },

    hasProgress(transfer) {
      return transfer?.progress_supported !== false
        && Number.isFinite(Number(transfer?.percent))
        && Number(transfer?.total_bytes) > 0
    },

    normalizedPercent(value) {
      const number = Number(value)
      if (!Number.isFinite(number)) return 0
      return Math.max(0, Math.min(100, number))
    },

    formatPercent(value) {
      const number = Number(value)
      if (!Number.isFinite(number)) return ''
      return `${Math.round(number)}%`
    },

    directionSymbol(transfer) {
      return transfer?.direction === 'server_to_client' ? '↑' : '↓'
    },

    transferSubtitle(transfer) {
      const device = String(transfer?.hostname || transfer?.client_id || 'Device').trim() || 'Device'
      if (transfer?.direction === 'server_to_client') {
        return transfer.destination_path
          ? `Server → ${device} · ${transfer.destination_path}`
          : `Server → ${device}`
      }
      return `${device} → Server`
    },

    stageLabel(transfer) {
      const stage = String(transfer?.stage || '').toLowerCase()
      if (stage === 'preparing') {
        return transfer?.metadata?.source === 'remote_file_download_zip'
          ? 'Preparing archive…'
          : 'Preparing…'
      }
      if (stage === 'staging') return 'Staging to Server'
      if (stage === 'transferring') return 'Sending to Device'
      if (stage === 'finalizing') return 'Finalizing…'
      if (stage === 'failed') return 'Failed'
      if (stage === 'completed') return 'Completed'
      return 'Transferring…'
    },

    formatBytes(value) {
      const bytes = Number(value)
      if (!Number.isFinite(bytes) || bytes < 0) return '—'
      if (bytes < 1024) return `${Math.round(bytes)} B`

      const units = ['KB', 'MB', 'GB', 'TB']
      let amount = bytes
      let unitIndex = -1
      do {
        amount /= 1024
        unitIndex += 1
      } while (amount >= 1024 && unitIndex < units.length - 1)

      const digits = amount >= 100 ? 0 : amount >= 10 ? 1 : 2
      return `${amount.toFixed(digits)} ${units[unitIndex]}`
    },

    formatRate(value) {
      return `${this.formatBytes(value)}/s`
    },

    formatEta(value) {
      const seconds = Math.max(0, Math.round(Number(value) || 0))
      if (seconds < 60) return `${seconds}s`
      if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
      const hours = Math.floor(seconds / 3600)
      const minutes = Math.floor((seconds % 3600) / 60)
      return `${hours}h ${minutes}m`
    },
  },
}
</script>

<style scoped>
.transfer-center-shell {
  min-height: 100%;
  display: flex;
  flex-direction: column;
  color: var(--text);
}

.transfer-center-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 18px 18px 14px;
  border-bottom: 1px solid var(--line);
}

.transfer-center-title {
  font-size: 18px;
  font-weight: 700;
}

.transfer-center-subtitle {
  margin-top: 4px;
  color: var(--muted);
  font-size: 12px;
}

.transfer-center-close {
  border: 0;
  background: transparent;
  color: var(--muted);
  cursor: pointer;
  padding: 4px;
  font-size: 17px;
}

.transfer-center-section {
  padding: 16px 16px 0;
}

.transfer-center-section-title {
  margin: 0 2px 9px;
  color: var(--muted);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.transfer-card {
  padding: 13px 14px;
  margin-bottom: 10px;
  border: 1px solid var(--line);
  border-radius: 10px;
  background: var(--bg-card);
}

.transfer-card-head {
  display: grid;
  grid-template-columns: 24px minmax(0, 1fr) auto;
  align-items: center;
  gap: 9px;
  margin-bottom: 10px;
}

.transfer-direction {
  font-size: 18px;
  color: var(--primary);
  font-weight: 700;
}

.transfer-card-main,
.transfer-recent-main {
  min-width: 0;
}

.transfer-card-title,
.transfer-recent-title {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
  font-weight: 650;
}

.transfer-card-meta,
.transfer-recent-meta,
.transfer-card-detail {
  margin-top: 3px;
  color: var(--muted);
  font-size: 11px;
  overflow-wrap: anywhere;
}

.transfer-card-percent {
  min-width: 34px;
  text-align: right;
  font-size: 12px;
  font-weight: 700;
}

.transfer-card-status-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 8px;
  color: var(--muted);
  font-size: 11px;
}

.transfer-indeterminate {
  height: 6px;
  overflow: hidden;
  border-radius: 999px;
  background: rgba(148, 163, 184, 0.18);
}

.transfer-indeterminate span {
  display: block;
  width: 38%;
  height: 100%;
  border-radius: inherit;
  background: var(--primary);
  animation: transfer-slide 1.25s ease-in-out infinite;
}

@keyframes transfer-slide {
  from { transform: translateX(-110%); }
  to { transform: translateX(275%); }
}

.transfer-center-recent {
  padding-bottom: 16px;
}

.transfer-recent-row {
  display: grid;
  grid-template-columns: 22px minmax(0, 1fr) auto;
  gap: 9px;
  align-items: center;
  padding: 10px 4px;
  border-bottom: 1px solid var(--line);
}

.transfer-recent-icon {
  font-size: 15px;
}

.transfer-recent-icon.is-completed {
  color: #16a34a;
}

.transfer-recent-icon.is-failed {
  color: var(--danger);
}

.transfer-recent-state {
  color: var(--muted);
  font-size: 11px;
}

.transfer-center-empty {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 56px 24px;
  text-align: center;
}

.transfer-center-empty-symbol {
  color: var(--muted);
  font-size: 28px;
}

.transfer-center-empty-title {
  margin-top: 10px;
  font-size: 14px;
  font-weight: 700;
}

.transfer-center-empty-text {
  margin-top: 5px;
  color: var(--muted);
  font-size: 12px;
}

:deep(.el-progress-bar__outer) {
  background-color: rgba(148, 163, 184, 0.18);
}

</style>

<style>
.transfer-center-drawer .el-drawer__body {
  padding: 0;
}

@media (max-width: 640px) {
  .transfer-center-drawer.el-drawer {
    width: min(94vw, 430px) !important;
  }
}
</style>
