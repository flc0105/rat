import { apiData, jsonRequestOptions } from './http.js'

export function loadToolbarPreferences() {
  return apiData('/api/toolbar/preferences', {}, {})
}

export function saveToolbarPreferences(payload = {}) {
  return apiData(
    '/api/toolbar/preferences',
    jsonRequestOptions('PUT', payload),
    {},
  )
}
