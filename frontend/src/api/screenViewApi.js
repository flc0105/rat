import { apiData, jsonRequestOptions } from './http.js'

export function openScreenView(clientId, payload = {}) {
  return apiData(
    `/api/connections/${encodeURIComponent(clientId)}/screen-view/open`,
    jsonRequestOptions('POST', payload),
    {},
  )
}

export function updateScreenView(screenSessionId, payload = {}) {
  return apiData(
    `/api/screen-view/${encodeURIComponent(screenSessionId)}/config`,
    jsonRequestOptions('POST', payload),
    {},
  )
}

export function closeScreenView(screenSessionId) {
  return apiData(
    `/api/screen-view/${encodeURIComponent(screenSessionId)}/close`,
    { method: 'POST' },
    {},
  )
}

export function pollScreenView(screenSessionId, afterSeq = 0) {
  return apiData(
    `/api/screen-view/${encodeURIComponent(screenSessionId)}/poll?after_seq=${encodeURIComponent(afterSeq)}`,
    {},
    {},
  )
}
