export const DEFAULT_SSE_NOTIFICATION_PREFERENCES = {
  version: 1,
  enabled: true,
  events: {
    connection_online: true,
    connection_offline: true,
    artifact_created: true,
    pty_opened: true,
    pty_closed: true,
    pty_error: true,
    screen_view_starting: true,
    screen_view_closed: true,
    screen_view_error: true,
    background_job_running: true,
    background_job_stopped: true,
    background_job_error: true,
  },
}

export const SSE_NOTIFICATION_GROUPS = [
  {
    title: 'Devices',
    items: [
      { key: 'connection_online', label: 'Device online' },
      { key: 'connection_offline', label: 'Device offline' },
    ],
  },
  {
    title: 'Files',
    items: [
      { key: 'artifact_created', label: 'File ready' },
    ],
  },
  {
    title: 'PTY',
    items: [
      { key: 'pty_opened', label: 'PTY started' },
      { key: 'pty_closed', label: 'PTY stopped' },
      { key: 'pty_error', label: 'PTY error' },
    ],
  },
  {
    title: 'Screen View',
    items: [
      { key: 'screen_view_starting', label: 'Screen View starting' },
      { key: 'screen_view_closed', label: 'Screen View stopped' },
      { key: 'screen_view_error', label: 'Screen View error' },
    ],
  },
  {
    title: 'Background Jobs',
    items: [
      { key: 'background_job_running', label: 'Job started' },
      { key: 'background_job_stopped', label: 'Job finished' },
      { key: 'background_job_error', label: 'Job error' },
    ],
  },
]

export function cloneSseNotificationPreferences(preferences = DEFAULT_SSE_NOTIFICATION_PREFERENCES) {
  return {
    version: DEFAULT_SSE_NOTIFICATION_PREFERENCES.version,
    enabled: preferences?.enabled !== false,
    events: {
      ...DEFAULT_SSE_NOTIFICATION_PREFERENCES.events,
      ...(preferences?.events || {}),
    },
  }
}

export function normalizeSseNotificationPreferences(preferences = {}) {
  const source = preferences && typeof preferences === 'object' ? preferences : {}
  const sourceEvents = source.events && typeof source.events === 'object' ? source.events : {}
  const normalized = cloneSseNotificationPreferences(DEFAULT_SSE_NOTIFICATION_PREFERENCES)

  if (typeof source.enabled === 'boolean') {
    normalized.enabled = source.enabled
  }

  Object.keys(normalized.events).forEach((eventKey) => {
    if (typeof sourceEvents[eventKey] === 'boolean') {
      normalized.events[eventKey] = sourceEvents[eventKey]
    }
  })

  return normalized
}
