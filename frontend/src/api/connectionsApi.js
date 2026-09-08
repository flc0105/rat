import { apiData, apiFetch, jsonRequestOptions } from './http.js'

export function listConnections() {
  return apiData('/api/connections', {}, [])
}

export function verifyHiddenDevicesPassword(password = '') {
  return apiData(
    '/api/connections/hidden-devices/verify',
    jsonRequestOptions('POST', { password }),
    { required: false, verified: false },
  )
}

export function getConnectionRevisionStatus(clientId) {
  return apiData(`/api/connections/${encodeURIComponent(clientId)}/revision-status`, {}, {})
}

export function killConnection(clientId) {
  return apiFetch(`/api/connections/${encodeURIComponent(clientId)}/kill`, {
    method: 'POST',
  })
}

export function removeConnection(clientId, payload = {}) {
  return apiFetch(`/api/connections/${encodeURIComponent(clientId)}`, {
    ...jsonRequestOptions('DELETE', payload),
    method: 'DELETE',
  })
}


export function updateConnectionDeviceViewPrefs(payload = {}) {
  return apiData(
    '/api/connections/device-view-prefs',
    jsonRequestOptions('PATCH', payload),
    {},
  )
}

export function sendCommand(clientId, command, headers = {}) {
  return apiData(
    `/api/connections/${encodeURIComponent(clientId)}/command`,
    jsonRequestOptions('POST', { command }, headers),
    {},
  )
}

export function getCommandCandidates(clientId) {
  return apiData(`/api/connections/${encodeURIComponent(clientId)}/command-candidates`, {}, [])
}

export function getCommandCompletions(clientId, payload = {}) {
  return apiData(
    `/api/connections/${encodeURIComponent(clientId)}/command-completions`,
    jsonRequestOptions('POST', payload),
    { items: [] },
  )
}

export function getCommandHistory(machineId) {
  if (!machineId) return Promise.resolve([])
  return apiData(`/api/machines/${encodeURIComponent(machineId)}/command-history`, {}, [])
}

export function getMachineConnectionHistory(machineId) {
  if (!machineId) return Promise.resolve({ sessions: [] })
  return apiData(`/api/machines/${encodeURIComponent(machineId)}/connection-history`, {}, { sessions: [] })
}
