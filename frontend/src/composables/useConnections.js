import { ElMessage, ElMessageBox } from 'element-plus'
import { listConnections } from '../api/connectionsApi.js'

const DEVICE_VIEW_PREFS_STORAGE_KEY = 'rch.deviceViewPrefs.v1'

function emptyDeviceViewPrefs() {
    return {
        machineAliases: {},
        hiddenClientIds: {},
        hiddenMachineIds: {},
    }
}

function readDeviceViewPrefsFromStorage() {
    if (typeof window === 'undefined' || !window.localStorage) {
        return emptyDeviceViewPrefs()
    }

    try {
        const raw = window.localStorage.getItem(DEVICE_VIEW_PREFS_STORAGE_KEY)
        if (!raw) return emptyDeviceViewPrefs()

        const parsed = JSON.parse(raw)
        return {
            machineAliases: parsed && typeof parsed.machineAliases === 'object' && parsed.machineAliases ? parsed.machineAliases : {},
            hiddenClientIds: parsed && typeof parsed.hiddenClientIds === 'object' && parsed.hiddenClientIds ? parsed.hiddenClientIds : {},
            hiddenMachineIds: parsed && typeof parsed.hiddenMachineIds === 'object' && parsed.hiddenMachineIds ? parsed.hiddenMachineIds : {},
        }
    } catch (_e) {
        return emptyDeviceViewPrefs()
    }
}

function writeDeviceViewPrefsToStorage(prefs) {
    if (typeof window === 'undefined' || !window.localStorage) return

    try {
        window.localStorage.setItem(DEVICE_VIEW_PREFS_STORAGE_KEY, JSON.stringify(prefs || emptyDeviceViewPrefs()))
    } catch (_e) {
        // localStorage may be disabled in some environments; device view prefs are non-critical.
    }
}

export default {
    data() {
        return {
            connections: [],
            selectedId: '',
            showHiddenDevices: false,
            deviceViewPrefs: readDeviceViewPrefsFromStorage(),
        }
    },

    methods: {
        buildConnectionIdentityKey(item) {
            if (!item) return ''
            return item.client_id
        },

        normalizeClientId(value) {
            return String(value || '').trim()
        },

        normalizeMachineId(value) {
            return String(value || '').trim()
        },

        getConnectionClientId(item) {
            return this.normalizeClientId(item?.client_id)
        },

        getConnectionMachineId(item) {
            return this.normalizeMachineId(item?.machine_id)
        },

        getMachineAlias(machineId) {
            const id = this.normalizeMachineId(machineId)
            if (!id) return ''
            return String(this.deviceViewPrefs?.machineAliases?.[id] || '').trim()
        },

        isClientIdHidden(clientId) {
            const id = this.normalizeClientId(clientId)
            return Boolean(id && this.deviceViewPrefs?.hiddenClientIds?.[id])
        },

        isMachineIdHidden(machineId) {
            const id = this.normalizeMachineId(machineId)
            return Boolean(id && this.deviceViewPrefs?.hiddenMachineIds?.[id])
        },

        isConnectionHiddenByPrefs(item) {
            if (!item) return false
            return this.isClientIdHidden(item.client_id) || this.isMachineIdHidden(item.machine_id)
        },

        getDeviceDisplayName(item) {
            const alias = this.getMachineAlias(item?.machine_id)
            if (alias) return alias
            return String(item?.hostname || '').trim() || 'Unknown Host'
        },

        decorateConnectionForDeviceView(item) {
            const alias = this.getMachineAlias(item?.machine_id)
            const hiddenByClient = this.isClientIdHidden(item?.client_id)
            const hiddenByMachine = this.isMachineIdHidden(item?.machine_id)

            return {
                ...item,
                device_alias: alias,
                device_display_name: alias || String(item?.hostname || '').trim() || 'Unknown Host',
                device_hidden: hiddenByClient || hiddenByMachine,
                device_hidden_by_client: hiddenByClient,
                device_hidden_by_machine: hiddenByMachine,
            }
        },

        persistDeviceViewPrefs() {
            writeDeviceViewPrefsToStorage(this.deviceViewPrefs)
        },

        patchDeviceViewPrefs(patch = {}) {
            this.deviceViewPrefs = {
                ...emptyDeviceViewPrefs(),
                ...this.deviceViewPrefs,
                ...patch,
            }
            this.persistDeviceViewPrefs()
        },

        setClientHidden(clientId, hidden) {
            const id = this.normalizeClientId(clientId)
            if (!id) return

            const hiddenClientIds = { ...(this.deviceViewPrefs.hiddenClientIds || {}) }
            if (hidden) {
                hiddenClientIds[id] = true
            } else {
                delete hiddenClientIds[id]
            }

            this.patchDeviceViewPrefs({ hiddenClientIds })
        },

        setMachineHidden(machineId, hidden) {
            const id = this.normalizeMachineId(machineId)
            if (!id) return

            const hiddenMachineIds = { ...(this.deviceViewPrefs.hiddenMachineIds || {}) }
            if (hidden) {
                hiddenMachineIds[id] = true
            } else {
                delete hiddenMachineIds[id]
            }

            this.patchDeviceViewPrefs({ hiddenMachineIds })
        },

        setMachineAlias(machineId, alias) {
            const id = this.normalizeMachineId(machineId)
            if (!id) return

            const machineAliases = { ...(this.deviceViewPrefs.machineAliases || {}) }
            const value = String(alias || '').trim()

            if (value) {
                machineAliases[id] = value
            } else {
                delete machineAliases[id]
            }

            this.patchDeviceViewPrefs({ machineAliases })
        },

        toggleShowHiddenDevices() {
            this.showHiddenDevices = !this.showHiddenDevices
            this.ensureSelectedConnectionVisible()
        },

        ensureSelectedConnectionVisible() {
            if (this.showHiddenDevices) return

            const selected = this.connections.find(item => item.client_id === this.selectedId)
            if (selected && !this.isConnectionHiddenByPrefs(selected)) return

            const next = this.deviceSidebarConnections[0]
            this.selectedId = next?.client_id || ''
        },

        async renameMachineFromSidebar(item) {
            const machineId = this.getConnectionMachineId(item)
            if (!machineId) {
                ElMessage.warning('Invalid machine id')
                return
            }

            const currentAlias = this.getMachineAlias(machineId)
            const hostname = String(item?.hostname || '').trim()
            const title = currentAlias ? 'Edit Machine Alias' : 'Set Machine Alias'

            try {
                const { value } = await ElMessageBox.prompt(
                    `Alias for ${hostname || machineId}. Leave empty to clear alias.`,
                    title,
                    {
                        confirmButtonText: 'Save',
                        cancelButtonText: 'Cancel',
                        inputValue: currentAlias,
                        inputPlaceholder: hostname || 'Machine alias',
                    },
                )

                this.setMachineAlias(machineId, value)
                ElMessage.success(String(value || '').trim() ? 'Alias saved' : 'Alias cleared')
            } catch (e) {
                if (e === 'cancel' || e === 'close' || e?.toString?.().includes('cancel')) return
            }
        },

        toggleClientHiddenFromSidebar(item) {
            const clientId = this.getConnectionClientId(item)
            if (!clientId) {
                ElMessage.warning('Invalid client id')
                return
            }

            const nextHidden = !this.isClientIdHidden(clientId)
            this.setClientHidden(clientId, nextHidden)
            this.ensureSelectedConnectionVisible()
            ElMessage.success(nextHidden ? 'Connection hidden' : 'Connection unhidden')
        },

        toggleMachineHiddenFromSidebar(item) {
            const machineId = this.getConnectionMachineId(item)
            if (!machineId) {
                ElMessage.warning('Invalid machine id')
                return
            }

            const nextHidden = !this.isMachineIdHidden(machineId)
            this.setMachineHidden(machineId, nextHidden)
            this.ensureSelectedConnectionVisible()
            ElMessage.success(nextHidden ? 'Machine hidden' : 'Machine unhidden')
        },

        dedupeConnections(items) {
            const grouped = new Map()
            const ordered = []

            ;(Array.isArray(items) ? items : []).forEach((item) => {
                if (!item || !item.client_id) return

                const key = item.client_id
                const existing = grouped.get(key)

                if (!existing) {
                    const copy = { ...item }
                    grouped.set(key, copy)
                    ordered.push(copy)
                    return
                }

                const existingState = this.getConnectionDisplayState(existing)
                const currentState = this.getConnectionDisplayState(item)

                if (existingState === 'offline' && currentState !== 'offline') {
                    Object.assign(existing, item, { disconnected_at: '' })
                    return
                }

                if (existingState !== 'offline' && currentState === 'offline') {
                    return
                }

                const existingTime = this.getConnectionActivityTimeMs(existing)
                const currentTime = this.getConnectionActivityTimeMs(item)

                if (currentTime >= existingTime) {
                    Object.assign(existing, item)
                }
            })

            const activeItems = []
            const offlineItems = []

            ordered.forEach((item) => {
                if (this.getConnectionDisplayState(item) === 'offline') {
                    offlineItems.push(item)
                } else {
                    activeItems.push(item)
                }
            })

            offlineItems.sort(this.compareConnectionActivityDesc)

            return activeItems.concat(offlineItems)
        },

        async loadConnections() {
            try {
                const fetchedConnections = await listConnections()

                const existingMap = new Map()
                ;(this.connections || []).forEach(item => {
                    if (item && item.client_id) {
                        existingMap.set(item.client_id, { ...item })
                    }
                })

                const fetchedMap = new Map()
                const frontItems = []

                fetchedConnections.forEach(item => {
                    if (!item || !item.client_id) return

                    const existing = existingMap.get(item.client_id)
                    const existingState = this.getConnectionDisplayState(existing)
                    const incomingState = this.getConnectionDisplayState(item)
                    const merged = {
                        ...existing,
                        ...item,
                    }

                    if (incomingState !== 'offline') {
                        merged.disconnected_at = ''
                    }

                    fetchedMap.set(item.client_id, merged)

                    if (!existing || (existingState === 'offline' && incomingState !== 'offline')) {
                        frontItems.push(merged)
                    }
                })

                frontItems.sort(this.compareConnectionActivityDesc)

                const nextItems = []
                const usedIds = new Set()

                frontItems.forEach(item => {
                    if (!item || !item.client_id || usedIds.has(item.client_id)) return
                    nextItems.push(item)
                    usedIds.add(item.client_id)
                })

                ;(this.connections || []).forEach(oldItem => {
                    if (!oldItem || !oldItem.client_id || usedIds.has(oldItem.client_id)) return

                    const merged = fetchedMap.get(oldItem.client_id) || oldItem
                    nextItems.push(merged)
                    usedIds.add(oldItem.client_id)
                })

                fetchedConnections.forEach(item => {
                    if (!item || !item.client_id || usedIds.has(item.client_id)) return

                    const merged = fetchedMap.get(item.client_id) || item
                    nextItems.push(merged)
                    usedIds.add(item.client_id)
                })

                this.connections = this.dedupeConnections(nextItems)

                if (!this.selectedId && this.deviceSidebarConnections.length > 0) {
                    this.selectedId = this.deviceSidebarConnections[0].client_id
                }

                if (this.selectedId && !this.connections.find(item => item.client_id === this.selectedId)) {
                    this.selectedId = this.deviceSidebarConnections.length > 0 ? this.deviceSidebarConnections[0].client_id : ''
                }

                this.ensureSelectedConnectionVisible()

                if (this.selectedId) {
                    await this.reloadCommandCandidatesFromRuntime?.({
                        reset: true,
                        silent: true,
                    })
                }
            } catch (e) {
                ElMessage.error('Failed to load devices')
            }
        },

        upsertConnection(conn) {
            if (!conn || !conn.client_id) return

            const identityKey = this.buildConnectionIdentityKey(conn)
            const incomingState = this.getConnectionDisplayState(conn)

            const duplicateIndexes = []
            this.connections.forEach((item, index) => {
                if (!item) return

                const sameClientId = item.client_id === conn.client_id
                const sameIdentity = identityKey && this.buildConnectionIdentityKey(item) === identityKey

                if (sameClientId || sameIdentity) {
                    duplicateIndexes.push(index)
                }
            })

            if (!duplicateIndexes.length) {
                const nextItem = { ...conn }

                if (incomingState === 'offline') {
                    this.connections.push(nextItem)
                } else {
                    this.connections.unshift(nextItem)
                }

                this.connections = this.dedupeConnections(this.connections)
                this.ensureSelectedConnectionVisible()
                return
            }

            const primaryIndex = duplicateIndexes[0]
            const oldItem = this.connections[primaryIndex]
            const oldState = this.getConnectionDisplayState(oldItem)

            const merged = {
                ...oldItem,
                ...conn,
            }

            if (incomingState !== 'offline') {
                merged.disconnected_at = ''
            }

            if (incomingState === 'offline' && !merged.disconnected_at) {
                merged.disconnected_at = new Date().toISOString()
            }

            duplicateIndexes
                .slice()
                .sort((a, b) => b - a)
                .forEach(index => {
                    this.connections.splice(index, 1)
                })

            if (incomingState === 'offline') {
                this.connections.push(merged)
            } else if (oldState === 'offline') {
                this.connections.unshift(merged)
            } else {
                const removedBefore = duplicateIndexes.filter(index => index < primaryIndex).length
                const stableIndex = Math.max(primaryIndex - removedBefore, 0)
                this.connections.splice(stableIndex, 0, merged)
            }

            this.connections = this.dedupeConnections(this.connections)
            this.ensureSelectedConnectionVisible()
        },

        removeConnection(clientId) {
            const idx = this.connections.findIndex(item => item.client_id === clientId)
            if (idx === -1) return

            const oldItem = this.connections[idx]
            const offlineItem = {
                ...oldItem,
                connection_state: 'offline',
                disconnected_at: oldItem.disconnected_at || new Date().toISOString(),
                is_transfer_active: false,
            }

            this.connections.splice(idx, 1)
            this.connections.push(offlineItem)
            this.connections = this.dedupeConnections(this.connections)
            this.ensureSelectedConnectionVisible()
        },

        getConnectionActivityTimeMs(item) {
            if (!item) return Number.NEGATIVE_INFINITY

            const candidates = [
                item.disconnected_at,
                item.last_seen_at,
                item.connected_at,
            ]

            const validTimes = candidates
                .map(value => Date.parse(String(value || '').trim()))
                .filter(value => Number.isFinite(value))

            if (!validTimes.length) {
                return Number.NEGATIVE_INFINITY
            }

            return Math.max(...validTimes)
        },

        compareConnectionActivityDesc(a, b) {
            const ta = this.getConnectionActivityTimeMs(a)
            const tb = this.getConnectionActivityTimeMs(b)

            if (ta !== tb) {
                return tb > ta ? 1 : -1
            }

            const fa = String(a?.hostname || a?.machine_id || a?.client_id || '')
            const fb = String(b?.hostname || b?.machine_id || b?.client_id || '')
            return fa.localeCompare(fb)
        },

        selectConnection(clientId) {
            this.selectedId = clientId
            this.ensureOutputBucket(clientId)
            this.commandHistoryItems = []
            this.commandExecutionItems = []
            this.reloadCommandCandidatesFromRuntime?.({
                reset: true,
                silent: true,
            })
            this.scrollToBottom()
            this.refreshBackgroundJobsIfOpen?.()
        },

        getConnectionDisplayState(conn) {
            const state = String(conn && conn.connection_state || '').trim()
            if (state === 'offline') return 'offline'

            if (conn && conn.is_transfer_active) {
                return 'online'
            }

            const disconnectedAt = String(conn && conn.disconnected_at || '').trim()
            if (disconnectedAt) return 'offline'

            const lastSeenAt = String(conn && conn.last_seen_at || '').trim()
            if (!lastSeenAt) return state || 'online'

            const staleAfterSeconds = Number(conn && conn.stale_after_seconds || 45)
            const seenMs = Date.parse(lastSeenAt)
            if (!Number.isFinite(seenMs)) return state || 'online'

            const ageMs = Math.max(this.statusNowTick - seenMs, 0)
            if (ageMs > staleAfterSeconds * 1000) return 'stale'

            return 'online'
        },
    },

    computed: {
        machineAliasMap() {
            return { ...(this.deviceViewPrefs?.machineAliases || {}) }
        },

        deviceSidebarConnections() {
            const decorated = (this.connections || []).map(item => this.decorateConnectionForDeviceView(item))
            if (this.showHiddenDevices) return decorated
            return decorated.filter(item => !item.device_hidden)
        },

        currentConnection() {
            return this.connections.find(item => item.client_id === this.selectedId) || null
        },

        onlineConnectionsCount() {
            return (this.deviceSidebarConnections || []).filter(item => this.getConnectionDisplayState(item) === 'online').length
        },
    },
}
