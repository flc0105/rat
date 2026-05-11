export function openSseStream(tabId) {
  const streamUrl = `/api/stream?tab_id=${encodeURIComponent(tabId)}`
  return new EventSource(streamUrl)
}
