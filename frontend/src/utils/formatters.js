export function formatDateTimeStandard(value) {
  const text = String(value || '').trim()
  if (!text) return '-'

  const normalized = text.replace('T', ' ').split('.')[0]
  return normalized || '-'
}

export function formatBytes(size) {
  const value = Number(size || 0)

  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(2)} KB`
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(2)} MB`

  return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`
}