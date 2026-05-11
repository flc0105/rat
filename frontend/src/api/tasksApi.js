import { apiFetch } from './http.js'

export function cancelTask(taskId) {
  return apiFetch(`/api/tasks/${encodeURIComponent(taskId)}/cancel`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })
}
