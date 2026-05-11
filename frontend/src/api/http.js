export async function apiFetch(url, options = {}) {
  const response = await fetch(url, options)
  let payload = null

  try {
    payload = await response.json()
  } catch (e) {
    payload = null
  }

  if (!response.ok || (payload && payload.code !== undefined && payload.code !== 0)) {
    const message = payload && payload.message ? payload.message : `Request failed: ${response.status}`
    throw new Error(message)
  }

  return payload
}

export async function apiData(url, options = {}, fallback = null) {
  const payload = await apiFetch(url, options)
  return payload && Object.prototype.hasOwnProperty.call(payload, 'data') ? payload.data : fallback
}

export function jsonRequestOptions(method, body, headers = {}) {
  return {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(body || {}),
  }
}
