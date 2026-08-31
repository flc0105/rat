import { apiData, jsonRequestOptions } from './http.js'

export function loadNotificationPreferences() {
  return apiData('/api/notifications/preferences', {}, {})
}

export function saveNotificationPreferences(payload = {}) {
  return apiData(
    '/api/notifications/preferences',
    jsonRequestOptions('PUT', payload),
    {},
  )
}
