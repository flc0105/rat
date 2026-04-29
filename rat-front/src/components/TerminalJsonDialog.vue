<template>
  <el-dialog
    v-model="visible"
    :title="title"
    width="980px"
    top="8vh"
    class="fixed-dialog"
  >
    <template v-if="displayMode === 'table'">
      <div class="terminal-json-scroll">
        <el-table
          :data="tableRows"
          border
          stripe
          style="width: 100%;"
        >
          <el-table-column
            v-for="column in tableColumns"
            :key="column.prop"
            :prop="column.prop"
            :label="column.label"
            min-width="140"
            show-overflow-tooltip
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
        <pre class="terminal-json-raw">{{ text }}</pre>
      </div>
    </template>
  </el-dialog>
</template>

<script>
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
    }
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
  },
}
</script>

<style scoped>
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
  white-space: pre-wrap;
  word-break: break-word;
  font-family: monospace;
  font-size: 13px;
  line-height: 1.6;
}
</style>