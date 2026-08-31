<template>
  <el-dialog
    v-model="visible"
    title="Notification Settings"
    width="620px"
    :close-on-click-modal="false"
    append-to-body
  >
    <div v-loading="loading" class="notification-preferences-body">
      <div class="notification-master-row">
        <div>
          <div class="notification-master-title">SSE Notifications</div>
          <div class="notification-master-note">
            Events still update application state when notifications are disabled.
          </div>
        </div>
        <el-switch v-model="draft.enabled" />
      </div>

      <div class="notification-groups">
        <section
          v-for="group in groups"
          :key="group.title"
          class="notification-group"
        >
          <div class="notification-group-title">{{ group.title }}</div>

          <div class="notification-group-list">
            <div
              v-for="item in group.items"
              :key="item.key"
              class="notification-option-row"
            >
              <span>{{ item.label }}</span>
              <el-switch
                v-model="draft.events[item.key]"
                :disabled="!draft.enabled"
              />
            </div>
          </div>
        </section>
      </div>
    </div>

    <template #footer>
      <div class="notification-preferences-footer">
        <el-button :disabled="loading || saving" @click="resetDefaults">
          Reset Default
        </el-button>
        <span class="notification-preferences-spacer"></span>
        <el-button :disabled="saving" @click="visible = false">Cancel</el-button>
        <el-button
          type="primary"
          :loading="saving"
          :disabled="loading"
          @click="savePreferences"
        >
          Save
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script>
import { ElMessage } from 'element-plus'
import {
  loadNotificationPreferences,
  saveNotificationPreferences,
} from '../api/notificationPreferencesApi.js'
import {
  DEFAULT_SSE_NOTIFICATION_PREFERENCES,
  SSE_NOTIFICATION_GROUPS,
  cloneSseNotificationPreferences,
  normalizeSseNotificationPreferences,
} from '../data/sseNotificationPreferences.js'

export default {
  name: 'NotificationPreferencesDialog',

  emits: ['saved'],

  data() {
    return {
      visible: false,
      loading: false,
      saving: false,
      groups: SSE_NOTIFICATION_GROUPS,
      draft: cloneSseNotificationPreferences(DEFAULT_SSE_NOTIFICATION_PREFERENCES),
    }
  },

  methods: {
    async open() {
      this.visible = true
      this.loading = true

      try {
        const preferences = await loadNotificationPreferences()
        this.draft = normalizeSseNotificationPreferences(preferences)
      } catch (e) {
        ElMessage.error(e.message || 'Failed to load notification preferences')
      } finally {
        this.loading = false
      }
    },

    resetDefaults() {
      this.draft = cloneSseNotificationPreferences(DEFAULT_SSE_NOTIFICATION_PREFERENCES)
    },

    async savePreferences() {
      if (this.saving) return
      this.saving = true

      try {
        const saved = normalizeSseNotificationPreferences(
          await saveNotificationPreferences(this.draft),
        )
        this.draft = cloneSseNotificationPreferences(saved)
        this.$emit('saved', saved)
        this.visible = false
        ElMessage.success('Notification settings updated')
      } catch (e) {
        ElMessage.error(e.message || 'Failed to save notification preferences')
      } finally {
        this.saving = false
      }
    },
  },
}
</script>

<style scoped>
.notification-preferences-body {
  min-height: 180px;
}

.notification-master-row,
.notification-option-row,
.notification-preferences-footer {
  display: flex;
  align-items: center;
}

.notification-master-row {
  justify-content: space-between;
  gap: 20px;
  padding: 14px 16px;
  border: 1px solid var(--el-border-color-light);
  border-radius: 10px;
  background: var(--el-fill-color-light);
}

.notification-master-title,
.notification-group-title {
  font-weight: 650;
}

.notification-master-note {
  margin-top: 4px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
  line-height: 1.45;
}

.notification-groups {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
  margin-top: 14px;
}

.notification-group {
  border: 1px solid var(--el-border-color-light);
  border-radius: 10px;
  overflow: hidden;
}

.notification-group-title {
  padding: 9px 12px;
  border-bottom: 1px solid var(--el-border-color-lighter);
  background: var(--el-fill-color-light);
  font-size: 12px;
}

.notification-group-list {
  padding: 2px 12px;
}

.notification-option-row {
  justify-content: space-between;
  gap: 16px;
  min-height: 42px;
  border-bottom: 1px solid var(--el-border-color-extra-light);
  font-size: 13px;
}

.notification-option-row:last-child {
  border-bottom: none;
}

.notification-preferences-footer {
  width: 100%;
}

.notification-preferences-spacer {
  flex: 1;
}

@media (max-width: 640px) {
  .notification-groups {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
