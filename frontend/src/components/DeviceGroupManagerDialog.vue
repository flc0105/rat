<template>
  <el-dialog
    v-model="visible"
    title="Manage Device Groups"
    width="520px"
    :close-on-click-modal="true"
  >
    <div class="device-group-manager">
      <div class="device-group-add-row">
        <el-input
          v-model="newGroupName"
          size="small"
          maxlength="80"
          placeholder="New group name"
          @keyup.enter="createGroup"
        />
        <el-button
          class="device-group-add-button"
          size="small"
          type="primary"
          :loading="creating"
          :disabled="!normalizedNewGroupName"
          @click="createGroup"
        >
          Add Group
        </el-button>
      </div>

      <div v-if="!groups.length" class="device-group-empty">
        No device groups yet.
      </div>

      <div v-else class="device-group-list">
        <div
          v-for="group in groups"
          :key="group.group_id"
          class="device-group-row"
        >
          <div class="device-group-row-main">
            <div class="device-group-name">{{ group.name }}</div>
            <div class="device-group-meta">
              {{ getMachineCount(group.group_id) }} machine{{ getMachineCount(group.group_id) === 1 ? '' : 's' }}
            </div>
          </div>

          <div class="device-group-actions">
            <el-dropdown
              trigger="click"
              placement="bottom-end"
              @command="command => handleGroupCommand(command, group)"
            >
              <el-button
                class="device-group-more-button"
                size="small"
                text
                title="Group actions"
                aria-label="Group actions"
              >
                <span class="device-group-more-icon">⋮</span>
              </el-button>

              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="rename">
                    Rename
                  </el-dropdown-item>
                  <el-dropdown-item divided command="delete">
                    <span class="device-group-delete-command">Delete</span>
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </div>
      </div>
    </div>
  </el-dialog>
</template>

<script>
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  createDeviceGroup,
  deleteDeviceGroup,
  renameDeviceGroup,
} from '../api/deviceGroupsApi.js'

export default {
  name: 'DeviceGroupManagerDialog',

  props: {
    groups: {
      type: Array,
      default: () => [],
    },

    machineGroupAssignments: {
      type: Object,
      default: () => ({}),
    },
  },

  emits: ['groups-changed'],

  data() {
    return {
      visible: false,
      newGroupName: '',
      creating: false,
    }
  },

  computed: {
    normalizedNewGroupName() {
      return String(this.newGroupName || '').trim()
    },
  },

  methods: {
    open() {
      this.newGroupName = ''
      this.visible = true
    },

    getMachineCount(groupId) {
      const target = String(groupId || '').trim()
      return Object.values(this.machineGroupAssignments || {}).filter(value => value === target).length
    },

    handleGroupCommand(command, group) {
      if (command === 'rename') {
        this.renameGroup(group)
        return
      }

      if (command === 'delete') {
        this.removeGroup(group)
      }
    },

    async createGroup() {
      const name = this.normalizedNewGroupName
      if (!name || this.creating) return

      this.creating = true
      try {
        const payload = await createDeviceGroup(name)
        this.newGroupName = ''
        this.$emit('groups-changed', payload)
        ElMessage.success('Device group added')
      } catch (e) {
        ElMessage.error(e.message || 'Failed to add device group')
      } finally {
        this.creating = false
      }
    },

    async renameGroup(group) {
      const groupId = String(group?.group_id || '').trim()
      const currentName = String(group?.name || '').trim()
      if (!groupId) return

      try {
        const { value } = await ElMessageBox.prompt(
          'Enter a new name for this device group.',
          'Rename Device Group',
          {
            confirmButtonText: 'Save',
            cancelButtonText: 'Cancel',
            inputValue: currentName,
            inputPlaceholder: 'Group name',
            inputValidator: value => {
              const name = String(value || '').trim()
              if (!name) return 'Group name is required'
              if (name.length > 80) return 'Group name must be 80 characters or fewer'
              return true
            },
          },
        )

        const payload = await renameDeviceGroup(groupId, value)
        this.$emit('groups-changed', payload)
        ElMessage.success('Device group renamed')
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return
        ElMessage.error(e.message || 'Failed to rename device group')
      }
    },

    async removeGroup(group) {
      const groupId = String(group?.group_id || '').trim()
      const name = String(group?.name || '').trim()
      if (!groupId) return

      try {
        await ElMessageBox.confirm(
          `Delete "${name}"? Machines in this group will become ungrouped.`,
          'Delete Device Group',
          {
            type: 'warning',
            confirmButtonText: 'Delete',
            cancelButtonText: 'Cancel',
            confirmButtonClass: 'el-button--danger',
          },
        )

        const payload = await deleteDeviceGroup(groupId)
        this.$emit('groups-changed', payload)
        ElMessage.success('Device group deleted')
      } catch (e) {
        if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return
        ElMessage.error(e.message || 'Failed to delete device group')
      }
    },
  },
}
</script>

<style scoped>
.device-group-manager {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.device-group-add-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
}

.device-group-add-row :deep(.el-input__wrapper) {
  min-height: 34px;
  border-radius: 10px;
}

.device-group-add-button.el-button {
  min-width: 92px;
  height: 34px;
  min-height: 34px;
  padding: 0 14px;
  margin: 0;
  border-radius: 10px;
  font-weight: 600;
}

.device-group-empty {
  padding: 28px 12px;
  border: 1px dashed var(--el-border-color-light);
  border-radius: 8px;
  color: var(--el-text-color-secondary);
  text-align: center;
  font-size: 13px;
}

.device-group-list {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 12px;
  overflow: hidden;
}

.device-group-row {
  display: flex;
  align-items: center;
  gap: 12px;
  min-height: 62px;
  padding: 10px 14px;
  background: var(--el-bg-color);
  border-bottom: 1px solid var(--el-border-color-lighter);
}

.device-group-row:hover {
  background: var(--el-fill-color-extra-light);
}

.device-group-row:last-child {
  border-bottom: 0;
}

.device-group-row-main {
  min-width: 0;
  flex: 1;
}

.device-group-name {
  color: var(--el-text-color-primary);
  font-size: 14px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.device-group-meta {
  margin-top: 3px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
}

.device-group-actions {
  display: inline-flex;
  align-items: center;
  flex-shrink: 0;
}

.device-group-more-button.el-button {
  width: 30px;
  min-width: 30px;
  height: 30px;
  min-height: 30px;
  padding: 0;
  margin: 0;
  border-radius: 8px;
  color: var(--el-text-color-secondary);
}

.device-group-more-button.el-button:hover,
.device-group-more-button.el-button:focus {
  background: var(--el-fill-color-light);
  color: var(--el-text-color-primary);
}

.device-group-more-icon {
  font-size: 17px;
  line-height: 1;
}

.device-group-delete-command {
  color: var(--el-color-danger);
}

@media (max-width: 640px) {
  .device-group-add-row {
    grid-template-columns: 1fr;
  }

  .device-group-row {
    align-items: center;
  }
}
</style>
