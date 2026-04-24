<template>
  <el-dialog
    :model-value="visible"
    title="Script Library"
    width="1180px"
    top="6vh"
    class="fixed-dialog script-library-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div
      class="fixed-dialog-body script-library-body"
      v-loading="loading"
    >
      <div class="background-jobs-toolbar script-library-toolbar">
        <div class="script-library-toolbar-left">
          <el-button
            size="small"
            class="toolbar-btn"
            type="primary"
            plain
            @click="$emit('create-script')"
          >
            New
          </el-button>

          <el-button
            size="small"
            class="toolbar-btn"
            :loading="uploadLoading"
            @click="$emit('trigger-upload')"
          >
            Upload
          </el-button>

          <el-button
            size="small"
            class="toolbar-btn"
            @click="$emit('create-folder')"
          >
            New Folder
          </el-button>

          <el-button
            size="small"
            class="toolbar-btn"
            :disabled="!selectedDirectory"
            @click="$emit('rename-folder')"
          >
            Rename Folder
          </el-button>

          <el-button
            size="small"
            class="toolbar-btn"
            type="danger"
            plain
            :disabled="!selectedDirectory"
            @click="$emit('delete-folder')"
          >
            Delete Folder
          </el-button>

          <el-button
            size="small"
            class="toolbar-btn"
            :loading="loading"
            @click="$emit('refresh')"
          >
            Refresh
          </el-button>

          <input
            id="server-script-upload-input"
            type="file"
            accept=".py,text/x-python"
            style="display: none"
            @change="$emit('upload-change', $event)"
          />
        </div>

        <div class="script-library-toolbar-right">
          <span class="background-job-module-key mono">
            Upload Target: {{ selectedDirectory || 'root' }}
          </span>
        </div>
      </div>

      <div class="script-library-shell">
        <div class="script-library-tree panel-lite">
          <div class="background-jobs-section-title">Folders</div>

          <div class="script-library-pane-scroll">
            <el-tree
              :data="directoryTreeData"
              node-key="key"
              default-expand-all
              highlight-current
              :expand-on-click-node="true"
              class="script-library-tree-view"
              @node-click="$emit('tree-node-click', $event)"
            >
              <template #default="{ data }">
                <span class="script-tree-node">
                  <span class="script-tree-node-label">
                    {{ data.label }}
                  </span>
                </span>
              </template>
            </el-tree>
          </div>
        </div>

        <div class="script-library-directory panel-lite">
          <div class="script-library-directory-top">
            <div>
              <div class="background-jobs-section-title">
                {{ selectedDirectory || 'Scripts' }}
              </div>

              <div class="background-job-module-key mono">
                {{ directoryItems.length }}
                script<span v-if="directoryItems.length !== 1">s</span>
              </div>
            </div>
          </div>

          <div class="script-library-pane-scroll">
            <div
              v-if="directoryItems.length"
              class="script-library-card-list script-library-card-list-single"
            >
              <div
                v-for="item in directoryItems"
                :key="item.script_name"
                class="script-library-card"
              >
                <div class="script-library-card-main">
                  <div
                    class="script-library-card-title"
                    :title="item.display_name || item.script_name"
                  >
                    {{ item.display_name || item.script_name }}
                  </div>

                  <div
                    class="script-library-card-path mono"
                    :title="item.path || item.script_name"
                  >
                    {{ item.path || item.script_name }}
                  </div>

                  <div
                    class="script-library-card-description"
                    :title="item.description || ''"
                  >
                    {{ item.description || 'No description' }}
                  </div>

                  <div class="script-tags script-library-card-tags">
                    <el-tag
                      size="small"
                      :type="isScriptSupportedForCurrentConnection(item) ? 'info' : 'danger'"
                    >
                      {{ formatScriptPlatformLabel(item) }}
                    </el-tag>

                    <el-tag
                      v-if="scriptHasParams(item)"
                      size="small"
                      type="warning"
                    >
                      Params
                    </el-tag>
                  </div>
                </div>

                <div class="script-library-card-actions">
                  <el-button
                    size="small"
                    type="primary"
                    plain
                    :disabled="!isScriptSupportedForCurrentConnection(item)"
                    @click="$emit('run-script', item)"
                  >
                    Run
                  </el-button>

                  <el-button
                    size="small"
                    plain
                    @click="$emit('edit-script', item.script_name)"
                  >
                    Edit
                  </el-button>

                  <el-button
                    size="small"
                    plain
                    @click="$emit('rename-script', item.script_name)"
                  >
                    Rename
                  </el-button>

                  <el-button
                    size="small"
                    type="danger"
                    plain
                    @click="$emit('delete-script', item.script_name)"
                  >
                    Delete
                  </el-button>
                </div>
              </div>
            </div>

            <div
              v-else
              class="empty-state"
            >
              No scripts in this folder
            </div>
          </div>
        </div>
      </div>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'ScriptLibraryDialog',

  props: {
    visible: {
      type: Boolean,
      default: false,
    },

    loading: {
      type: Boolean,
      default: false,
    },

    uploadLoading: {
      type: Boolean,
      default: false,
    },

    selectedDirectory: {
      type: String,
      default: '',
    },

    directoryTreeData: {
      type: Array,
      default: () => [],
    },

    directoryItems: {
      type: Array,
      default: () => [],
    },

    isScriptSupportedForCurrentConnection: {
      type: Function,
      required: true,
    },

    formatScriptPlatformLabel: {
      type: Function,
      required: true,
    },

    scriptHasParams: {
      type: Function,
      required: true,
    },
  },

  emits: [
    'update:visible',
    'create-script',
    'trigger-upload',
    'upload-change',
    'create-folder',
    'rename-folder',
    'delete-folder',
    'refresh',
    'tree-node-click',
    'run-script',
    'edit-script',
    'rename-script',
    'delete-script',
  ],
}
</script>