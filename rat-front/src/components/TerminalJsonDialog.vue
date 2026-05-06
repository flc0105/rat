<template>
  <el-dialog
    v-model="visible"
    :title="title"
    width="980px"
    top="8vh"
    class="fixed-dialog"
  >
    <div class="terminal-json-wrap">
      <div class="terminal-json-toolbar">
        <div class="terminal-json-toolbar-left">
          <el-button
            size="small"
            @click="copyTerminalJsonRaw"
          >
            Copy Raw
          </el-button>
        </div>

        <div class="terminal-json-toolbar-right">
          <template v-if="displayMode === 'table'">
            <el-input
              v-model="tableSearchText"
              class="terminal-json-search"
              size="small"
              clearable
              placeholder="Search text"
            />

            <el-tag
              size="small"
              type="info"
            >
              {{ filteredTableRows.length }} / {{ tableRows.length }} rows
            </el-tag>
          </template>
        </div>
      </div>

      <template v-if="displayMode === 'table'">
        <div class="terminal-json-scroll">
          <el-table
            :data="visibleTableRows"
            border
            stripe
            style="width: 100%;"
            @sort-change="handleTableSortChange"
          >
            <el-table-column
              v-for="column in tableColumns"
              :key="column.prop"
              :prop="column.prop"
              :label="column.label"
              min-width="140"
              show-overflow-tooltip
              sortable="custom"
              :sort-orders="['descending', 'ascending', null]"
            />
          </el-table>
        </div>
      </template>

      <template v-else-if="displayMode === 'flat'">
        <div class="terminal-json-scroll">
          <div
            v-for="item in flatRows"
            :key="item.key"
            class="terminal-json-flat-row"
          >
            <div class="terminal-json-flat-label">
              {{ item.label }}
            </div>

            <div class="terminal-json-flat-value">
              {{ item.value }}
            </div>
          </div>
        </div>
      </template>

      <template v-else>
        <div class="terminal-json-scroll">
          <pre class="terminal-json-raw"><code>{{ formattedRawText }}</code></pre>
        </div>
      </template>
    </div>
  </el-dialog>
</template>

<script>
import { ElMessage } from 'element-plus'

export default {
  name: 'TerminalJsonDialog',

  data() {
    return {
      visible: false,
      title: 'JSON Viewer',
      text: '',
      displayMode: 'raw',
      tableColumns: [],
      tableRows: [],
      flatRows: [],
      tableSearchText: '',
      tableSort: {
        prop: '',
        order: '',
      },
    }
  },

  computed: {
    formattedRawText() {
      return this.formatTerminalJsonRawForDisplay(this.text)
    },

    filteredTableRows() {
      const rows = Array.isArray(this.tableRows) ? this.tableRows : []
      const keyword = String(this.tableSearchText || '').trim().toLowerCase()

      if (!keyword) {
        return rows
      }

      // table 搜索只做前端行筛选，不改原始 JSON。
      return rows.filter((row) => {
        return Object.values(row || {}).some((value) => {
          return String(value ?? '').toLowerCase().includes(keyword)
        })
      })
    },

    visibleTableRows() {
      return this.sortTerminalJsonTableRows(this.filteredTableRows)
    },
  },

  watch: {
    visible(value) {
      if (!value) {
        this.reset()
      }
    },
  },

  methods: {
    open(line) {
      if (!line || !line.isJsonMessage) return

      const jsonText = String(line.jsonText || '').trim()
      const tableModel = this.tryBuildTerminalJsonTableModel(jsonText)
      const flatModel = tableModel ? null : this.tryBuildTerminalJsonFlatModel(jsonText)

      this.title = 'JSON Viewer'
      this.text = jsonText
      this.tableSearchText = ''
      this.tableSort = {
        prop: '',
        order: '',
      }

      if (tableModel) {
        this.displayMode = 'table'
        this.tableColumns = tableModel.columns
        this.tableRows = tableModel.rows
        this.flatRows = []
      } else if (flatModel) {
        this.displayMode = 'flat'
        this.tableColumns = []
        this.tableRows = []
        this.flatRows = flatModel
      } else {
        this.displayMode = 'raw'
        this.tableColumns = []
        this.tableRows = []
        this.flatRows = []
      }

      this.visible = true
    },

    reset() {
      this.title = 'JSON Viewer'
      this.text = ''
      this.displayMode = 'raw'
      this.tableColumns = []
      this.tableRows = []
      this.flatRows = []
      this.tableSearchText = ''
      this.tableSort = {
        prop: '',
        order: '',
      }
    },

    isTerminalJsonPlainObject(value) {
      return !!value && typeof value === 'object' && !Array.isArray(value)
    },

    tryBuildTerminalJsonTableModel(jsonText) {
      const raw = String(jsonText || '').trim()
      if (!raw) return null

      let parsed
      try {
        parsed = JSON.parse(raw)
      } catch (e) {
        return null
      }

      if (!Array.isArray(parsed) || !parsed.length) {
        return null
      }

      if (!parsed.every(item => this.isTerminalJsonPlainObject(item))) {
        return null
      }

      const firstKeys = Object.keys(parsed[0])
      if (!firstKeys.length) {
        return null
      }

      const sortedFirstKeys = [...firstKeys].sort()

      const hasSameStructure = parsed.every((item) => {
        const keys = Object.keys(item)
        if (keys.length !== firstKeys.length) return false

        const sortedKeys = [...keys].sort()
        for (let i = 0; i < sortedFirstKeys.length; i += 1) {
          if (sortedKeys[i] !== sortedFirstKeys[i]) return false
        }

        return true
      })

      if (!hasSameStructure) {
        return null
      }

      return {
        columns: firstKeys.map((key) => ({
          prop: key,
          label: key,
        })),

        rows: parsed.map((item) => {
          const row = {}

          firstKeys.forEach((key) => {
            const value = item[key]

            if (value === null || value === undefined) {
              row[key] = ''
            } else if (typeof value === 'object') {
              row[key] = JSON.stringify(value)
            } else {
              row[key] = String(value)
            }
          })

          return row
        }),
      }
    },

    tryBuildTerminalJsonFlatModel(jsonText) {
      const raw = String(jsonText || '').trim()
      if (!raw) return null

      let parsed
      try {
        parsed = JSON.parse(raw)
      } catch (e) {
        return null
      }

      if (!this.isTerminalJsonPlainObject(parsed)) {
        return null
      }

      return Object.keys(parsed).map((key) => ({
        key,
        label: key,
        value: this.formatTerminalJsonFlatValue(parsed[key]),
      }))
    },

    formatTerminalJsonFlatValue(value) {
      if (value === null || value === undefined) {
        return ''
      }

      if (typeof value === 'object') {
        try {
          return JSON.stringify(value)
        } catch (e) {
          return String(value)
        }
      }

      return String(value)
    },

    formatTerminalJsonRawForDisplay(jsonText) {
      const raw = String(jsonText || '').trim()
      if (!raw) return ''

      try {
        return JSON.stringify(JSON.parse(raw), null, 2)
      } catch (e) {
        return raw
      }
    },

    async copyTerminalJsonRaw() {
      const raw = String(this.text || '')
      if (!raw) return

      try {
        if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(raw)
        } else {
          this.copyTextWithLegacyTextarea(raw)
        }

        ElMessage.success('Raw JSON copied')
      } catch (e) {
        try {
          this.copyTextWithLegacyTextarea(raw)
          ElMessage.success('Raw JSON copied')
        } catch (_error) {
          ElMessage.error('Copy failed')
        }
      }
    },

    copyTextWithLegacyTextarea(text) {
      const textarea = document.createElement('textarea')
      textarea.value = text
      textarea.setAttribute('readonly', 'readonly')
      textarea.style.position = 'fixed'
      textarea.style.left = '-9999px'
      textarea.style.top = '-9999px'
      document.body.appendChild(textarea)
      textarea.select()

      try {
        const copied = document.execCommand('copy')
        if (!copied) {
          throw new Error('copy command failed')
        }
      } finally {
        document.body.removeChild(textarea)
      }
    },

    handleTableSortChange({ prop, order }) {
      this.tableSort = {
        prop: prop || '',
        order: order || '',
      }
    },

    sortTerminalJsonTableRows(rows) {
      const safeRows = Array.isArray(rows) ? rows : []
      const prop = this.tableSort.prop
      const order = this.tableSort.order

      if (!prop || !order) {
        return safeRows
      }

      const direction = order === 'descending' ? -1 : 1

      return safeRows
        .map((row, index) => ({ row, index }))
        .sort((left, right) => {
          const result = this.compareTerminalJsonSortValues(left.row?.[prop], right.row?.[prop])

          if (result === 0) {
            return left.index - right.index
          }

          return result * direction
        })
        .map(item => item.row)
    },

    compareTerminalJsonSortValues(left, right) {
      const leftMeta = this.getTerminalJsonSortMeta(left)
      const rightMeta = this.getTerminalJsonSortMeta(right)

      if (leftMeta.type === 'empty' && rightMeta.type !== 'empty') return 1
      if (leftMeta.type !== 'empty' && rightMeta.type === 'empty') return -1
      if (leftMeta.type === 'empty' && rightMeta.type === 'empty') return 0

      if (leftMeta.type === rightMeta.type) {
        if (leftMeta.type === 'string') {
          return leftMeta.value.localeCompare(rightMeta.value, undefined, {
            sensitivity: 'base',
          })
        }

        if (leftMeta.value < rightMeta.value) return -1
        if (leftMeta.value > rightMeta.value) return 1
        return 0
      }

      return leftMeta.text.localeCompare(rightMeta.text, undefined, {
        sensitivity: 'base',
      })
    },

    getTerminalJsonSortMeta(value) {
      const text = String(value ?? '').trim()

      if (!text) {
        return {
          type: 'empty',
          value: '',
          text,
        }
      }

      if (/^[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?$/i.test(text)) {
        return {
          type: 'number',
          value: Number(text),
          text,
        }
      }

      const parsedDate = Date.parse(text)
      if (!Number.isNaN(parsedDate) && this.isTerminalJsonDateLikeString(text)) {
        return {
          type: 'date',
          value: parsedDate,
          text,
        }
      }

      return {
        type: 'string',
        value: text,
        text,
      }
    },

    isTerminalJsonDateLikeString(text) {
      return /^\d{4}[-/]\d{1,2}[-/]\d{1,2}/.test(text)
        || /^\d{1,2}[-/]\d{1,2}[-/]\d{2,4}/.test(text)
        || /^\d{4}-\d{2}-\d{2}T/.test(text)
        || /(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}/i.test(text)
    },
  },
}
</script>

<style scoped>
.terminal-json-wrap {
  min-height: 220px;
}

.terminal-json-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--line, #ebeef5);
  flex-wrap: wrap;
  gap: 12px;
}

.terminal-json-toolbar-left,
.terminal-json-toolbar-right {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.terminal-json-toolbar-left :deep(.el-button) {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 6px 16px;
  height: 26px;
}

.terminal-json-search {
  width: 240px;
}

.terminal-json-scroll {
  max-height: 65vh;
  overflow: auto;
}

.terminal-json-flat-row {
  display: grid;
  grid-template-columns: 220px 1fr;
  gap: 12px;
  padding: 8px 0;
  border-bottom: 1px solid #ebeef5;
}

.terminal-json-flat-label {
  color: #606266;
  font-weight: 500;
  word-break: break-word;
}

.terminal-json-flat-value {
  word-break: break-word;
}

.terminal-json-raw {
  margin: 0;
  padding: 16px;
  white-space: pre-wrap;
  word-break: break-word;
  overflow: auto;
  border: 1px solid var(--line, #dcdfe6);
  border-radius: 12px;
  background: #f8fafc;
  color: #1f2937;
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.55);
  font-family: Monaco, Menlo, "Ubuntu Mono", Consolas, monospace;
  font-size: 13px;
  line-height: 1.65;
  tab-size: 2;
}

.terminal-json-raw code {
  font-family: inherit;
}

@media (max-width: 768px), (max-height: 720px) {
  .terminal-json-toolbar {
    flex-direction: column;
    align-items: flex-start;
    margin-bottom: 10px;
    padding-bottom: 10px;
  }

  .terminal-json-toolbar-left,
  .terminal-json-toolbar-right,
  .terminal-json-search {
    width: 100%;
  }
}
</style>