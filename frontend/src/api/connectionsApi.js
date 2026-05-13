import { apiData, apiFetch, jsonRequestOptions } from './http.js'

export function listConnections() {
  return apiData('/api/connections', {}, [])
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

export function getCommandHistory(machineId) {
  if (!machineId) return Promise.resolve([])
  return apiData(`/api/machines/${encodeURIComponent(machineId)}/command-history`, {}, [])
}
