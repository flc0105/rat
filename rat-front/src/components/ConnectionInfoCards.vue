<template>
  <section class="info-grid">
    <div class="info-card">
      <div class="info-label">Hostname</div>
      <div class="info-value">{{ connection.hostname || '-' }}</div>
    </div>

    <div class="info-card">
      <div class="info-label">IP Address</div>
      <div class="info-value">{{ formatAddress(connection.addr) || '-' }}</div>
    </div>

    <div class="info-card">
      <div class="info-label">Platform</div>
      <div class="info-value">
        {{ formatOsLabel(connection.os_type, connection.os_ver) }}
      </div>
    </div>

    <div class="info-card">
      <div class="info-label">Status</div>
      <div class="info-value">{{ getConnectionStatusText(connection) }}</div>
    </div>

    <div class="info-card">
      <div class="info-label">RTT</div>
      <div class="info-value">{{ formatConnectionRtt(connection) }}</div>
    </div>

    <div class="info-card">
      <div class="info-label">Integrity</div>
      <div class="info-value">{{ connection.integrity || '-' }}</div>
    </div>

    <div class="info-card info-card-wide-2">
      <div class="info-label">Client ID</div>
      <div class="info-value">{{ connection.client_id || '-' }}</div>
    </div>

    <div class="info-card info-card-wide-2">
      <div class="info-label">Working Directory</div>
      <div class="info-value mono">{{ connection.cwd || '-' }}</div>
    </div>
  </section>
</template>

<script>
export default {
  name: 'ConnectionInfoCards',

  props: {
    connection: {
      type: Object,
      required: true,
    },

    formatAddress: {
      type: Function,
      required: true,
    },

    formatOsLabel: {
      type: Function,
      required: true,
    },

    getConnectionStatusText: {
      type: Function,
      required: true,
    },

    formatConnectionRtt: {
      type: Function,
      required: true,
    },
  },
}
</script>