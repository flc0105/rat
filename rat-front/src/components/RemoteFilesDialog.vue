<template>
  <el-dialog
    :model-value="visible"
    title="Remote File Browser"
    width="1180px"
    top="4vh"
    class="fixed-dialog remote-files-dialog"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div class="fixed-dialog-body">
      <div class="dialog-head remote-files-head">
        <div class="dialog-head-left remote-files-head-main">
          <div class="remote-breadcrumb-bar">
            <template v-if="remoteBreadcrumbItems.length">
              <button
                v-for="(item, index) in remoteBreadcrumbItems"
                :key="`breadcrumb-${index}-${item.path}`"
                type="button"
                class="remote-breadcrumb-item"
                :class="{ active: item.isCurrent }"
                :disabled="item.isCurrent"
                @click="$emit('breadcrumb', item)"
              >
                <span v-if="index > 0" class="remote-breadcrumb-sep">/</span>
                <span>{{ item.label }}</span>
              </button>
            </template>

            <span v-else class="remote-breadcrumb-empty">No path</span>
          </div>

          <div class="remote-files-toolbar">
            <div class="remote-toolbar-group">
              <el-button size="small" @click="$emit('refresh')">
                Refresh
              </el-button>

              <el-button
                size="small"
                :disabled="!remoteFilesParentPath"
                @click="$emit('parent')"
              >
                Up
              </el-button>

              <el-dropdown
                :loading="quickJumpLoading || remotePinnedJumpLoading"
                @command="$emit('jump', $event)"
              >
                <el-button size="small">
                  Quick Jump
                </el-button>

                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="root">Root</el-dropdown-item>
                    <el-dropdown-item command="home">Home</el-dropdown-item>
                    <el-dropdown-item command="desktop">Desktop</el-dropdown-item>
                    <el-dropdown-item command="documents">Documents</el-dropdown-item>
                    <el-dropdown-item command="downloads">Downloads</el-dropdown-item>
                    <el-dropdown-item command="executable">Program Directory</el-dropdown-item>

                    <el-dropdown-item
                      v-for="(item, index) in remotePinnedJumpItems"
                      :key="`pinned-jump-${item.display_name}-${item.path}`"
                      :divided="index === 0"
                      :command="{
                        type: 'pinned_jump',
                        display_name: item.display_name,
                        path: item.path,
                      }"
                    >
                      {{ item.display_name }}
                    </el-dropdown-item>

                    <el-dropdown-item divided command="input_navigate">
                      Go to Folder
                    </el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </div>

            <span class="remote-toolbar-divider"></span>

            <div class="remote-toolbar-group">
              <el-button size="small" @click="$emit('create-folder')">
                New Folder
              </el-button>

              <el-button
                size="small"
                :loading="remoteUploadLoading"
                @click="$emit('trigger-upload')"
              >
                Upload
              </el-button>

              <el-button
                size="small"
                type="primary"
                :disabled="!hasRemoteSelection"
                :loading="remoteZipDownloading"
                @click="$emit('download-selected')"
              >
                Download
                <span v-if="remoteSelectedPaths.length">
                  ({{ remoteSelectedPaths.length }})
                </span>
              </el-button>

              <el-button
                size="small"
                type="danger"
                :disabled="!hasRemoteSelection"
                @click="$emit('delete-selected')"
              >
                Delete
                <span v-if="remoteSelectedPaths.length">
                  ({{ remoteSelectedPaths.length }})
                </span>
              </el-button>
            </div>

            <span class="remote-toolbar-divider"></span>

            <div class="remote-toolbar-group">
              <el-dropdown
                trigger="click"
                @command="$emit('more-command', $event)"
              >
                <el-button size="small">More</el-button>

                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="toggle_pin">
                      {{ remotePinButtonText }}
                    </el-dropdown-item>

                    <el-dropdown-item
                      v-if="hasPinnedQuickJumps"
                      command="manage_pins"
                    >
                      Manage Pins
                    </el-dropdown-item>

                    <el-dropdown-item
                      command="copy"
                      :disabled="!hasRemoteSelection"
                      divided
                    >
                      Copy
                      <span v-if="remoteSelectedPaths.length">
                        ({{ remoteSelectedPaths.length }})
                      </span>
                    </el-dropdown-item>

                    <el-dropdown-item
                      command="cut"
                      :disabled="!hasRemoteSelection"
                    >
                      Cut
                      <span v-if="remoteSelectedPaths.length">
                        ({{ remoteSelectedPaths.length }})
                      </span>
                    </el-dropdown-item>

                    <el-dropdown-item
                      command="paste"
                      :disabled="!hasRemoteClipboard"
                    >
                      Paste
                      <span v-if="hasRemoteClipboard">
                        ({{ remoteClipboardPaths.length }})
                      </span>
                    </el-dropdown-item>

                    <el-dropdown-item
                      command="clear_clipboard"
                      :disabled="!hasRemoteClipboard"
                    >
                      Clear Clipboard
                    </el-dropdown-item>

                    <el-dropdown-item
                      command="clear_selection"
                      :disabled="!hasRemoteSelection"
                      divided
                    >
                      Clear Selection
                    </el-dropdown-item>

                    <el-dropdown-item command="toggle_hidden">
                      {{ showHiddenFiles ? 'Hide Hidden' : 'Show Hidden' }}
                    </el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </div>
          </div>
        </div>
      </div>

      <div class="dialog-path-row remote-files-meta-row">
        <div v-if="hasRemoteClipboard" class="dialog-pagination-meta">
          Clipboard: {{ remoteClipboardActionText }} {{ remoteClipboardPaths.length }} item(s)
          <span v-if="remoteClipboardSourcePath">
            · From {{ remoteClipboardSourcePath }}
          </span>
        </div>
      </div>

      <div class="dialog-table-shell">
        <el-table
          ref="remoteFilesTableRef"
          :data="displayRemoteFilesEntries"
          v-loading="remoteFilesLoading"
          stripe
          width="100%"
          height="100%"
          empty-text="This folder is empty"
          table-layout="fixed"
          @row-dblclick="$emit('row-dblclick', $event)"
          @selection-change="$emit('selection-change', $event)"
        >
          <el-table-column
            type="selection"
            width="52"
            align="center"
            :selectable="row => !row.is_parent_entry"
          />

          <el-table-column label="Name" min-width="320" show-overflow-tooltip>
            <template #default="{ row }">
              <div class="file-cell">
                <span>{{ row.is_dir ? '📁' : '📄' }}</span>
                <span class="file-cell-text">
                  {{ row.is_parent_entry ? '..' : row.name }}
                </span>

                <el-tag v-if="row.is_parent_entry" size="small" type="info">
                  Parent
                </el-tag>

                <el-tag v-else-if="row.is_symlink" size="small" type="info">
                  Link
                </el-tag>

                <el-tag
                  v-if="!row.is_parent_entry && row.is_hidden"
                  size="small"
                  type="warning"
                >
                  Hidden
                </el-tag>
              </div>
            </template>
          </el-table-column>

          <el-table-column label="Type" width="110" align="center">
            <template #default="{ row }">
              {{ row.is_parent_entry ? 'Parent' : (row.is_dir ? 'Folder' : 'File') }}
            </template>
          </el-table-column>

          <el-table-column label="Size" width="120" align="center">
            <template #default="{ row }">
              {{ row.is_dir ? '-' : formatBytes(row.size) }}
            </template>
          </el-table-column>

          <el-table-column
            prop="modified_at"
            label="Modified"
            width="180"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <div class="ellipsis">
                {{ row.is_parent_entry ? '-' : (row.modified_at || '-') }}
              </div>
            </template>
          </el-table-column>

          <el-table-column label="Actions" width="220" align="center" fixed="right">
            <template #default="{ row }">
              <div class="table-actions table-actions-links">
                <template v-if="row.is_parent_entry">
                  <el-button
                    size="small"
                    link
                    type="primary"
                    @click="$emit('parent')"
                  >
                    Open
                  </el-button>
                </template>

                <template v-else>
                  <el-button
                    v-if="row.is_dir"
                    size="small"
                    link
                    type="primary"
                    @click="$emit('enter-dir', row)"
                  >
                    Open
                  </el-button>

                  <template v-if="!row.is_dir">
                    <el-button
                      size="small"
                      link
                      type="primary"
                      @click="$emit('preview', row)"
                    >
                      Preview
                    </el-button>

                    <el-button
                      size="small"
                      link
                      type="primary"
                      @click="$emit('download', row)"
                    >
                      Download
                    </el-button>
                  </template>

                  <el-dropdown
                    trigger="click"
                    @command="$emit('row-more-action', $event, row)"
                  >
                    <el-button size="small" link type="primary">
                      More
                    </el-button>

                    <template #dropdown>
                      <el-dropdown-menu>
                        <el-dropdown-item command="rename">Rename</el-dropdown-item>
                        <el-dropdown-item command="copy">Copy</el-dropdown-item>
                        <el-dropdown-item command="cut">Cut</el-dropdown-item>
                        <el-dropdown-item command="copy_path">Copy Path</el-dropdown-item>
                        <el-dropdown-item command="delete">Delete</el-dropdown-item>
                      </el-dropdown-menu>
                    </template>
                  </el-dropdown>
                </template>
              </div>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div class="dialog-pagination-wrap">
        <div class="dialog-pagination-bar">
          <div class="dialog-pagination-meta">
            <span>Visible {{ remoteFilesTotal }} items</span>

            <span v-if="!showHiddenFiles && remoteFilesHiddenTotal > 0">
              · Hidden {{ remoteFilesHiddenTotal }}
            </span>

            <span v-if="remoteFilesAllTotal > remoteFilesTotal">
              · All {{ remoteFilesAllTotal }}
            </span>

            <span v-if="remoteFilesTotalPages > 1">
              · Page {{ remoteFilesPage }} / {{ remoteFilesTotalPages }}
            </span>
          </div>

          <el-pagination
            background
            layout="total, sizes, prev, pager, next"
            :current-page="remoteFilesPage"
            :page-size="remoteFilesPageSize"
            :page-sizes="remoteFilesPageSizeOptions"
            :total="remoteFilesTotal"
            :pager-count="5"
            @current-change="$emit('page-change', $event)"
            @size-change="$emit('size-change', $event)"
          />
        </div>
      </div>

      <div class="mobile-file-list-shell">
        <div class="mobile-file-list" v-loading="remoteFilesLoading">
          <div
            v-if="!displayRemoteFilesEntries.length && !remoteFilesLoading"
            class="empty-state"
          >
            This folder is empty
          </div>

          <div v-else class="mobile-file-grid">
            <div
              v-for="row in displayRemoteFilesEntries"
              :key="`${row.is_parent_entry ? 'parent-' : ''}${row.path}`"
              class="mobile-file-card"
              style="position: relative;"
            >
              <div
                v-if="!row.is_parent_entry"
                style="position:absolute; top:6px; right:12px; z-index:1;"
              >
                <el-checkbox
                  :model-value="isRemoteEntrySelected(row)"
                  @change="$emit('toggle-select', row)"
                />
              </div>

              <div class="mobile-file-card-top">
                <div class="mobile-file-icon">
                  {{ row.is_dir ? '📁' : '📄' }}
                </div>

                <div class="mobile-file-main">
                  <div
                    class="mobile-file-name"
                    :style="row.is_parent_entry ? '' : 'padding-right: 42px;'"
                  >
                    {{ row.is_parent_entry ? '..' : row.name }}
                  </div>

                  <div class="mobile-file-tags">
                    <el-tag size="small" type="info">
                      {{ row.is_parent_entry ? 'Parent' : (row.is_dir ? 'Folder' : 'File') }}
                    </el-tag>

                    <el-tag
                      v-if="!row.is_parent_entry && row.is_symlink"
                      size="small"
                      type="info"
                    >
                      Link
                    </el-tag>

                    <el-tag
                      v-if="!row.is_parent_entry && row.is_hidden"
                      size="small"
                      type="warning"
                    >
                      Hidden
                    </el-tag>
                  </div>

                  <div class="mobile-file-meta">
                    <div class="mobile-file-meta-item">
                      <div class="mobile-file-meta-label">Size</div>
                      <div class="mobile-file-meta-value">
                        {{ row.is_dir ? '-' : formatBytes(row.size) }}
                      </div>
                    </div>

                    <div class="mobile-file-meta-item">
                      <div class="mobile-file-meta-label">Modified</div>
                      <div class="mobile-file-meta-value">
                        {{ row.is_parent_entry ? '-' : (row.modified_at || '-') }}
                      </div>
                    </div>
                  </div>

                  <div class="mobile-file-actions">
                    <template v-if="row.is_parent_entry">
                      <el-button
                        size="small"
                        type="primary"
                        plain
                        @click="$emit('parent')"
                      >
                        Open
                      </el-button>
                    </template>

                    <template v-else>
                      <el-button
                        v-if="row.is_dir"
                        size="small"
                        type="primary"
                        plain
                        @click="$emit('enter-dir', row)"
                      >
                        Open
                      </el-button>

                      <template v-if="!row.is_dir">
                        <el-button
                          size="small"
                          type="primary"
                          plain
                          @click="$emit('preview', row)"
                        >
                          Preview
                        </el-button>

                        <el-button
                          size="small"
                          type="primary"
                          plain
                          @click="$emit('download', row)"
                        >
                          Download
                        </el-button>
                      </template>

                      <el-button
                        size="small"
                        plain
                        @click="$emit('copy-one', row)"
                      >
                        Copy
                      </el-button>

                      <el-button
                        size="small"
                        plain
                        @click="$emit('cut-one', row)"
                      >
                        Cut
                      </el-button>

                      <el-button
                        size="small"
                        plain
                        @click="$emit('rename', row)"
                      >
                        Rename
                      </el-button>

                      <el-button
                        size="small"
                        plain
                        @click="$emit('copy-path', row)"
                      >
                        Copy Path
                      </el-button>

                      <el-button
                        size="small"
                        type="danger"
                        plain
                        @click="$emit('delete', row)"
                      >
                        Delete
                      </el-button>
                    </template>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </el-dialog>

  <el-dialog
    :model-value="pinManagerVisible"
    title="Manage Pinned Paths"
    width="760px"
    top="6vh"
    class="fixed-dialog"
    @update:model-value="$emit('update:pinManagerVisible', $event)"
  >
    <div class="fixed-dialog-body">
      <div class="dialog-table-shell" style="height: 420px; min-height: 220px;">
        <el-table
          :data="remotePinnedJumpItems"
          stripe
          width="100%"
          height="100%"
          empty-text="No pinned paths"
          table-layout="fixed"
        >
          <el-table-column
            prop="display_name"
            label="Display Name"
            min-width="180"
            show-overflow-tooltip
          />

          <el-table-column
            prop="path"
            label="Path"
            min-width="360"
            show-overflow-tooltip
          />

          <el-table-column
            label="Actions"
            width="160"
            align="center"
            fixed="right"
          >
            <template #default="{ row }">
              <div class="table-actions table-actions-links">
                <el-button
                  size="small"
                  link
                  type="primary"
                  @click="$emit('edit-pin', row)"
                >
                  Edit
                </el-button>

                <el-button
                  size="small"
                  link
                  type="danger"
                  @click="$emit('delete-pin', row)"
                >
                  Delete
                </el-button>
              </div>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </div>
  </el-dialog>
</template>

<script>
export default {
  name: 'RemoteFilesDialog',

  props: {
    visible: { type: Boolean, default: false },
    pinManagerVisible: { type: Boolean, default: false },

    remoteBreadcrumbItems: { type: Array, default: () => [] },
    remoteFilesParentPath: { type: String, default: '' },

    quickJumpLoading: { type: Boolean, default: false },
    remotePinnedJumpLoading: { type: Boolean, default: false },
    remotePinnedJumpItems: { type: Array, default: () => [] },

    remoteUploadLoading: { type: Boolean, default: false },
    hasRemoteSelection: { type: Boolean, default: false },
    remoteZipDownloading: { type: Boolean, default: false },
    remoteSelectedPaths: { type: Array, default: () => [] },

    remotePinButtonText: { type: String, default: '' },
    hasPinnedQuickJumps: { type: Boolean, default: false },

    hasRemoteClipboard: { type: Boolean, default: false },
    remoteClipboardPaths: { type: Array, default: () => [] },
    remoteClipboardActionText: { type: String, default: '' },
    remoteClipboardSourcePath: { type: String, default: '' },

    showHiddenFiles: { type: Boolean, default: false },

    displayRemoteFilesEntries: { type: Array, default: () => [] },
    remoteFilesLoading: { type: Boolean, default: false },

    remoteFilesTotal: { type: Number, default: 0 },
    remoteFilesHiddenTotal: { type: Number, default: 0 },
    remoteFilesAllTotal: { type: Number, default: 0 },
    remoteFilesTotalPages: { type: Number, default: 1 },
    remoteFilesPage: { type: Number, default: 1 },
    remoteFilesPageSize: { type: Number, default: 50 },
    remoteFilesPageSizeOptions: { type: Array, default: () => [50, 100, 200] },

    formatBytes: { type: Function, required: true },
    isRemoteEntrySelected: { type: Function, required: true },
  },

  emits: [
    'update:visible',
    'update:pinManagerVisible',

    'breadcrumb',
    'refresh',
    'parent',
    'jump',

    'create-folder',
    'trigger-upload',
    'download-selected',
    'delete-selected',
    'more-command',

    'row-dblclick',
    'selection-change',
    'enter-dir',
    'preview',
    'download',
    'row-more-action',

    'page-change',
    'size-change',

    'toggle-select',
    'copy-one',
    'cut-one',
    'rename',
    'copy-path',
    'delete',

    'edit-pin',
    'delete-pin',
  ],

  methods: {
    clearTableSelection() {
      const table = this.$refs.remoteFilesTableRef

      if (table && typeof table.clearSelection === 'function') {
        table.clearSelection()
      }
    },
  },
}
</script>