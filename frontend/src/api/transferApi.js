export async function loadTransfers(tabId = '') {
  const headers = {}
  const normalizedTabId = String(tabId || '').trim()
  if (normalizedTabId) headers['X-Tab-Id'] = normalizedTabId

  const res = await fetch('/api/transfers', { headers })
  const json = await res.json()

  if (!res.ok || json.code !== 0) {
    throw new Error(json.message || 'Failed to load transfers')
  }

  return json.data || { active: [], recent: [], items: [] }
}
