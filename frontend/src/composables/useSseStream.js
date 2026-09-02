import {
    formatTerminalCommandFinishedLine,
    TERMINAL_BACKGROUND_PREFIX,
    TERMINAL_FILE_READY_PREFIX,
} from './terminalMarkers.js';
import { openSseStream } from '../api/streamApi.js';
import { loadNotificationPreferences } from '../api/notificationPreferencesApi.js';
import {
    addNotificationHistory,
    loadNotificationHistory,
} from '../api/notificationHistoryApi.js';
import {
    DEFAULT_SSE_NOTIFICATION_PREFERENCES,
    cloneSseNotificationPreferences,
    normalizeSseNotificationPreferences,
} from '../data/sseNotificationPreferences.js';

export default {
    data() {
        return {
            tabId: '',
            eventSource: null,
            sseReady: false,
            sseNotificationPreferences: cloneSseNotificationPreferences(DEFAULT_SSE_NOTIFICATION_PREFERENCES),
            sseNotificationHistory: [],
        }
    },


    methods: {
        async loadSseNotificationPreferences() {
            try {
                const preferences = await loadNotificationPreferences();
                this.applySseNotificationPreferences(preferences);
            } catch (e) {
                this.sseNotificationPreferences = cloneSseNotificationPreferences(DEFAULT_SSE_NOTIFICATION_PREFERENCES);
                console.warn('Failed to load SSE notification preferences; using defaults', e);
            }
        },

        applySseNotificationPreferences(preferences) {
            this.sseNotificationPreferences = normalizeSseNotificationPreferences(preferences);
        },

        async loadSseNotificationHistory() {
            try {
                const history = await loadNotificationHistory();
                const notifications = Array.isArray(history?.notifications) ? history.notifications : [];
                this.sseNotificationHistory = notifications;
            } catch (e) {
                console.warn('Failed to load notification history', e);
            }
        },

        upsertSseNotificationHistory(notification) {
            if (!notification || typeof notification !== 'object' || !notification.id) return;

            const existing = Array.isArray(this.sseNotificationHistory)
                ? this.sseNotificationHistory.filter(item => item?.id !== notification.id)
                : [];

            this.sseNotificationHistory = [notification, ...existing];
        },

        removeSseNotificationHistory(notificationId) {
            const normalizedId = String(notificationId || '').trim();
            if (!normalizedId) return;

            this.sseNotificationHistory = (this.sseNotificationHistory || []).filter(
                item => String(item?.id || '') !== normalizedId,
            );
        },

        clearSseNotificationHistory() {
            this.sseNotificationHistory = [];
        },

        applySseNotificationCenterUpdate(payload = {}) {
            const action = String(payload.action || '').trim().toLowerCase();

            if (action === 'added') {
                this.upsertSseNotificationHistory(payload.notification);
                return;
            }

            if (action === 'deleted') {
                this.removeSseNotificationHistory(payload.id);
                return;
            }

            if (action === 'cleared') {
                this.clearSseNotificationHistory();
            }
        },

        async recordSseNotification(notificationKey, options = {}, recordContext = {}) {
            const fallbackMessage = options.dangerouslyUseHTMLString
                ? ''
                : String(options.message || '').trim();

            const payload = {
                event_id: String(recordContext.eventId || '').trim(),
                notification_key: String(notificationKey || '').trim(),
                type: String(options.type || 'info').trim().toLowerCase() || 'info',
                title: String(options.title || 'Notification').trim() || 'Notification',
                message: String(recordContext.message ?? fallbackMessage).trim(),
                shown_at: new Date().toISOString(),
                context: recordContext.context && typeof recordContext.context === 'object'
                    ? recordContext.context
                    : {},
                actions: Array.isArray(recordContext.actions) ? recordContext.actions : [],
            };

            try {
                const notification = await addNotificationHistory(payload);
                this.upsertSseNotificationHistory(notification);
            } catch (e) {
                console.warn('Failed to persist SSE notification history', e);
            }
        },

        showSseNotification(notificationKey, options = {}, recordContext = {}) {
            const preferences = this.sseNotificationPreferences || DEFAULT_SSE_NOTIFICATION_PREFERENCES;
            if (preferences.enabled === false) return;
            if (preferences.events?.[notificationKey] === false) return;

            ElementPlus.ElNotification(options);
            void this.recordSseNotification(notificationKey, options, recordContext);
        },

        initSSE() {
            if (this.eventSource) this.eventSource.close();

            const tabId = this.ensureTabId();
            const es = openSseStream(tabId);
            this.eventSource = es;

            const getConnectionLabel = (clientId) => {
                const normalizedClientId = String(clientId || '').trim();
                const conn = this.connections.find(item => item.client_id === normalizedClientId) || {};
                return conn.hostname || conn.client_id || normalizedClientId || 'Unknown device';
            };

            es.addEventListener('open', () => {
                if (!this.sseReady) this.sseReady = true;
            });

            es.addEventListener('notification_preferences_updated', (event) => {
                const payload = JSON.parse(event.data || '{}');
                this.applySseNotificationPreferences(payload);
            });

            es.addEventListener('notification_center_updated', (event) => {
                const payload = JSON.parse(event.data || '{}');
                this.applySseNotificationCenterUpdate(payload);
            });

            es.addEventListener('connection_online', (event) => {
                const payload = JSON.parse(event.data);
                const conn = payload.connection;
                this.upsertConnection(conn);

                this.showSseNotification('connection_online', {
                    title: 'Device Online',
                    message: `${conn.hostname || conn.client_id} is now available`,
                    type: 'success'
                }, {
                    eventId: event.lastEventId,
                    context: {
                        client_id: conn.client_id || '',
                        hostname: conn.hostname || '',
                    },
                });
            });

            es.addEventListener('connection_offline', (event) => {
                const payload = JSON.parse(event.data);
                const clientId = payload.client_id;
                const conn = payload.connection || this.connections.find(item => item.client_id === clientId) || {client_id: clientId};

                this.upsertConnection({
                    ...conn,
                    connection_state: 'offline',
                    disconnected_at: conn.disconnected_at || payload.time,
                    is_transfer_active: false,
                });

                this.clearActiveTask(clientId);

                this.showSseNotification('connection_offline', {
                    title: 'Device Offline',
                    message: `${(conn && conn.hostname) || clientId} went offline`,
                    type: 'warning'
                }, {
                    eventId: event.lastEventId,
                    context: {
                        client_id: clientId || '',
                        hostname: conn?.hostname || '',
                    },
                });
            });

            es.addEventListener('connection_heartbeat', (event) => {
                const payload = JSON.parse(event.data);
                const conn = payload.connection;
                //
                // //add
                // this.statusNowTick = Date.now();

                this.upsertConnection(conn);
            });

            es.addEventListener('command_result', (event) => {
                const payload = JSON.parse(event.data);
                this.appendOutput(payload.client_id, payload.text || '', '', {
                    task_id: payload.task_id || '',
                    command: payload.command || '',
                    command_id: payload.command_id ?? null,
                    metadata: payload.metadata && typeof payload.metadata === 'object' ? payload.metadata : {},
                });
            });

            es.addEventListener('command_complete', async (event) => {
                const payload = JSON.parse(event.data);
                const statusText = String(payload.status || '').trim();

                let finishText = 'Failed';
                let finishKind = 'error';

                if (statusText === 'cancelled' || payload.cancelled) {
                    finishText = 'Cancelled';
                    finishKind = 'info';
                } else if (payload.success) {
                    finishText = 'Success';
                    finishKind = 'success';
                }

                this.appendOutput(
    payload.client_id,
    formatTerminalCommandFinishedLine(payload.command, finishText),
    finishKind,
    {
        task_id: payload.task_id || '',
        command: payload.command || '',
        command_id: payload.command_id ?? payload.source_command_id ?? null,
        metadata: payload.metadata && typeof payload.metadata === 'object' ? { ...payload.metadata } : {},
    }
);

                // this.clearActiveTask(payload.client_id, payload.task_id);
                this.markTaskCompleted(payload.client_id, payload.task_id);

                const pendingRefresh = this.pendingRemoteUploadRefresh;
                if (
                    pendingRefresh &&
                    pendingRefresh.taskId &&
                    payload.task_id === pendingRefresh.taskId
                ) {
                    const refreshClientId = pendingRefresh.clientId;
                    const refreshPath = pendingRefresh.path || '';

                    this.pendingRemoteUploadRefresh = null;

                    if (payload.success && this.selectedId === refreshClientId) {
                        try {
                            if (pendingRefresh.source === 'script_remote_file_picker') {
                                await this.$refs.scriptLibraryDialogRef?.refreshRemoteFilePickerDirectory(refreshPath);
                            } else if (pendingRefresh.source === 'job_remote_file_picker') {
                                await this.$refs.backgroundJobsDialogRef?.refreshRemoteFilePickerDirectory(refreshPath);
                            } else if (pendingRefresh.source === 'external_tool_remote_file_picker') {
                                await this.$refs.externalToolManagerDialogRef?.loadRemoteFilePickerDirectory(refreshPath);
                            } else if (pendingRefresh.source === 'remote_file_picker') {
                                await this.$refs.scriptLibraryDialogRef?.refreshRemoteFilePickerDirectory(refreshPath);
                            } else if (this.remoteFilesDialogVisible) {
                                await this.loadRemoteDirectory(refreshPath);
                            }
                        } catch (e) {
                        }
                    }
                }

                this.reloadCommandCandidatesFromRuntime?.({
                    reset: true,
                    silent: true,
                });
                await this.loadConnections();
            });

            es.addEventListener('background_message', async (event) => {
                const payload = JSON.parse(event.data);
this.appendOutput(payload.client_id, `${TERMINAL_BACKGROUND_PREFIX} ${payload.text || ''}`, 'info');                await this.loadConnections();
            });

            es.addEventListener('background_job_status', async (event) => {
                const payload = JSON.parse(event.data);
                // this.scheduleBackgroundJobsRefresh(payload.client_id);
                this.scheduleBackgroundJobsRefresh?.(payload.client_id);
            });

            es.addEventListener('background_job_lifecycle', async (event) => {
                const payload = JSON.parse(event.data || '{}');
                const state = String(payload.state || payload.status || '').trim().toLowerCase();
                const jobName = payload.display_name || payload.job_key || payload.job_name || 'background job';
                const deviceName = getConnectionLabel(payload.client_id);

                let title = 'Background Job';
                let type = 'info';
                let stateText = state || 'updated';

                if (state === 'running') {
                    title = 'Background Job Started';
                    type = 'success';
                    stateText = 'started';
                } else if (state === 'stopped') {
                    title = 'Background Job Finished';
                    type = 'success';
                    stateText = 'finished';
                } else if (state === 'error') {
                    title = 'Background Job Error';
                    type = 'error';
                    stateText = 'ended with error';
                }

                const notificationKey = {
                    running: 'background_job_running',
                    stopped: 'background_job_stopped',
                    error: 'background_job_error',
                }[state] || `background_job_${state || 'updated'}`;

                this.showSseNotification(notificationKey, {
                    title,
                    message: `${jobName} ${stateText} on ${deviceName}`,
                    type,
                    duration: 5000,
                }, {
                    eventId: event.lastEventId,
                    context: {
                        client_id: payload.client_id || '',
                        job_id: payload.job_id || '',
                        job_key: payload.job_key || payload.job_name || '',
                        display_name: payload.display_name || '',
                        state,
                    },
                });

                this.scheduleBackgroundJobsRefresh?.(payload.client_id);
            });

            es.addEventListener('background_job_message', async (event) => {
                const payload = JSON.parse(event.data);
                this.scheduleBackgroundJobsRefresh?.(payload.client_id);
                // this.scheduleBackgroundJobsRefresh(payload.client_id);
            });

            es.addEventListener('background_job_file', async (event) => {
                const payload = JSON.parse(event.data);
                // this.scheduleBackgroundJobsRefresh(payload.client_id);
                this.scheduleBackgroundJobsRefresh?.(payload.client_id);

                await this.refreshArtifactsIfOpen?.();
            });

            es.addEventListener('pty_lifecycle', (event) => {
                const payload = JSON.parse(event.data || '{}');
                const state = String(payload.state || '').trim().toLowerCase();
                const deviceName = getConnectionLabel(payload.client_id);

                if (state === 'opened') {
                    this.showSseNotification('pty_opened', {
                        title: 'PTY Started',
                        message: `PTY session started on ${deviceName}`,
                        type: 'success',
                        duration: 4000,
                    }, {
                        eventId: event.lastEventId,
                        context: {
                            client_id: payload.client_id || '',
                            pty_session_id: payload.pty_session_id || '',
                            state,
                        },
                    });
                    return;
                }

                if (state === 'closed') {
                    const exitCode = payload.exit_code === null || payload.exit_code === undefined
                        ? ''
                        : `, exit=${payload.exit_code}`;
                    this.showSseNotification('pty_closed', {
                        title: 'PTY Stopped',
                        message: `PTY session stopped on ${deviceName}${exitCode}`,
                        type: 'warning',
                        duration: 4000,
                    }, {
                        eventId: event.lastEventId,
                        context: {
                            client_id: payload.client_id || '',
                            pty_session_id: payload.pty_session_id || '',
                            state,
                            exit_code: payload.exit_code ?? null,
                        },
                    });
                    return;
                }

                if (state === 'error') {
                    this.showSseNotification('pty_error', {
                        title: 'PTY Error',
                        message: payload.error
                            ? `PTY session ended on ${deviceName}: ${payload.error}`
                            : `PTY session ended with an error on ${deviceName}`,
                        type: 'error',
                        duration: 5000,
                    }, {
                        eventId: event.lastEventId,
                        context: {
                            client_id: payload.client_id || '',
                            pty_session_id: payload.pty_session_id || '',
                            state,
                            error: payload.error || '',
                        },
                    });
                }
            });

            es.addEventListener('screen_view_lifecycle', (event) => {
                const payload = JSON.parse(event.data || '{}');
                const state = String(payload.state || '').trim().toLowerCase();
                const deviceName = getConnectionLabel(payload.client_id);

                if (state === 'starting') {
                    this.showSseNotification('screen_view_starting', {
                        title: 'Screen View Starting',
                        message: `Screen view is starting on ${deviceName}`,
                        type: 'info',
                        duration: 4000,
                    }, {
                        eventId: event.lastEventId,
                        context: {
                            client_id: payload.client_id || '',
                            screen_session_id: payload.screen_session_id || '',
                            state,
                        },
                    });
                    return;
                }

                if (state === 'closed') {
                    this.showSseNotification('screen_view_closed', {
                        title: 'Screen View Stopped',
                        message: `Screen view stopped on ${deviceName}`,
                        type: 'warning',
                        duration: 4000,
                    }, {
                        eventId: event.lastEventId,
                        context: {
                            client_id: payload.client_id || '',
                            screen_session_id: payload.screen_session_id || '',
                            state,
                        },
                    });
                    return;
                }

                if (state === 'error') {
                    this.showSseNotification('screen_view_error', {
                        title: 'Screen View Error',
                        message: payload.error
                            ? `Screen view ended on ${deviceName}: ${payload.error}`
                            : `Screen view ended with an error on ${deviceName}`,
                        type: 'error',
                        duration: 5000,
                    }, {
                        eventId: event.lastEventId,
                        context: {
                            client_id: payload.client_id || '',
                            screen_session_id: payload.screen_session_id || '',
                            state,
                            error: payload.error || '',
                        },
                    });
                }
            });

            es.addEventListener('artifact_created', async (event) => {
                const payload = JSON.parse(event.data || '{}');
                const fileName = payload.original_name || payload.stored_name || 'file';

                if (!payload.artifact_id) return;

    //                 // Command Output 是用户主动保存的命令输出，不按“远程文件已准备好”处理。
    // if (payload.artifact_type === 'command_output') {
    //     await this.refreshArtifactsIfOpen?.();
    //     return;
    // }

                if (payload.client_id) {
                    this.appendOutput(
    payload.client_id,
    `${TERMINAL_FILE_READY_PREFIX} ${fileName}`,
    'success',
    {
        artifactInfo: {
            artifact_id: payload.artifact_id || '',
            artifact_type: payload.artifact_type || '',
            category: payload.category || '',
            original_name: payload.original_name || fileName,
        },
    }
);
                }

                if (!this.selectedId || payload.client_id === this.selectedId || !payload.client_id) {
                    const downloadUrl = payload.download_url || `/api/artifacts/${encodeURIComponent(payload.artifact_id)}/download`;
                    this.showSseNotification('artifact_created', {
                        title: 'File Ready',
                        dangerouslyUseHTMLString: true,
                        message: `
        <div>
          <div>${fileName} has been saved</div>
          <div style="margin-top:6px;">
            <a href="${downloadUrl}" target="_blank" style="color:#409eff;text-decoration:none;">
              Download now
            </a>
          </div>
        </div>
    `,
                        type: 'success',
                        duration: 6000
                    }, {
                        eventId: event.lastEventId,
                        message: `${fileName} has been saved`,
                        context: {
                            client_id: payload.client_id || '',
                            artifact_id: payload.artifact_id || '',
                            artifact_type: payload.artifact_type || '',
                            category: payload.category || '',
                            original_name: payload.original_name || fileName,
                        },
                        actions: [
                            {
                                id: 'download',
                                type: 'artifact_download',
                                label: 'Download now',
                                url: downloadUrl,
                            },
                        ],
                    });
                }

                await this.refreshArtifactsIfOpen?.();
            });


            es.onerror = () => {
                // EventSource reconnects automatically
            };
        },

        ensureTabId() {
            const key = 'rat_web_tab_id';
            let tabId = '';

            try {
                tabId = String(sessionStorage.getItem(key) || '').trim();
            } catch (e) {
                tabId = '';
            }

            if (!tabId) {
                if (window.crypto && typeof window.crypto.randomUUID === 'function') {
                    tabId = window.crypto.randomUUID();
                } else {
                    tabId = `tab_${Date.now()}_${Math.random().toString(16).slice(2)}`;
                }

                try {
                    sessionStorage.setItem(key, tabId);
                } catch (e) {
                }
            }

            this.tabId = tabId;
            return tabId;
        },

        getTabScopedHeaders(extra = {}) {
            const headers = {...extra};
            if (this.tabId) {
                headers['X-Tab-Id'] = this.tabId;
            }
            return headers;
        },
    }
};