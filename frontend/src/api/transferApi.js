function normalizeHeaders(headers = {}) {
  return {...(headers || {})}
}

async function parseApiResponse(res, fallbackMessage) {
  const json = await res.json()
  if (!res.ok || json.code !== 0) {
    throw new Error(json.message || fallbackMessage)
  }
  return json.data || {}
}

export async function loadTransfers(tabId = '') {
  const headers = {}
  const normalizedTabId = String(tabId || '').trim()
  if (normalizedTabId) headers['X-Tab-Id'] = normalizedTabId

  const res = await fetch('/api/transfers', { headers })
  return parseApiResponse(res, 'Failed to load transfers')
}

export async function createBrowserUploadTransfer(payload = {}, headers = {}) {
  const res = await fetch('/api/transfers/browser-upload', {
    method: 'POST',
    headers: normalizeHeaders({
      'Content-Type': 'application/json',
      ...headers,
    }),
    body: JSON.stringify(payload || {}),
  })

  return parseApiResponse(res, 'Failed to initialize upload transfer')
}

export function buildBrowserUploadContentUrl(transfer = {}) {
  const port = String(transfer?.browser_upload_port || '').trim()
  const path = String(transfer?.browser_upload_path || '').trim()
  if (!port || !path) {
    throw new Error('Browser file transfer endpoint is unavailable')
  }

  const url = new URL(window.location.href)
  url.port = port
  url.pathname = path.startsWith('/') ? path : `/${path}`
  url.search = ''
  url.hash = ''
  return url.toString()
}

export async function updateBrowserUploadTransfer(transferId, payload = {}, headers = {}) {
  const normalizedTransferId = String(transferId || '').trim()
  if (!normalizedTransferId) return null

  const res = await fetch(`/api/transfers/${encodeURIComponent(normalizedTransferId)}/browser-upload`, {
    method: 'PATCH',
    headers: normalizeHeaders({
      'Content-Type': 'application/json',
      ...headers,
    }),
    body: JSON.stringify(payload || {}),
  })

  return parseApiResponse(res, 'Failed to update upload transfer')
}
