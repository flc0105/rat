// export default {
//     data() {
//         return {
//             commandCandidates: [],
//             commandCandidatesLoadedFor: '',
//         }
//     },
//
//     methods: {
//         resolveCommandHistoryMachineId(clientId) {
//             const target = (this.connections || []).find(item => item && item.client_id === clientId);
//             return String(target?.machine_id || '').trim();
//         },
//
//         buildCommonOpsCandidates() {
//             return [
//                 {
//                     name: 'whoami',
//                     template: 'whoami',
//                     help: 'Show current user',
//                     source: 'common_ops',
//                     group: 'common_ops'
//                 },
//                 {
//                     name: 'hostname',
//                     template: 'hostname',
//                     help: 'Show host name',
//                     source: 'common_ops',
//                     group: 'common_ops'
//                 },
//                 {
//                     name: 'mkdir',
//                     template: 'mkdir ',
//                     help: 'Create a directory',
//                     source: 'common_ops',
//                     group: 'common_ops'
//                 },
//                 {
//                     name: 'rmdir',
//                     template: 'rmdir ',
//                     help: 'Remove an empty directory',
//                     source: 'common_ops',
//                     group: 'common_ops'
//                 },
//             ];
//         },
//
//         queryCommandCandidates(queryString, callback) {
//             const keyword = String(queryString || '').trim().toLowerCase();
//             const sourceList = Array.isArray(this.commandCandidates) ? this.commandCandidates : [];
//
//             const quickHistoryShortcutCandidates = this.sortQuickHistoryShortcutCandidates(
//                 sourceList.filter(item => item && item.source === 'quick_history_shortcut')
//             );
//             const normalCandidates = sourceList.filter(item => !(item && item.source === 'quick_history_shortcut'));
//
//             if (!keyword) {
//                 callback(normalCandidates);
//                 return;
//             }
//
//             if (keyword.startsWith('!')) {
//                 if (keyword === '!') {
//                     callback(quickHistoryShortcutCandidates);
//                     return;
//                 }
//
//                 const exactMatches = [];
//                 const prefixMatches = [];
//                 const textMatches = [];
//
//                 quickHistoryShortcutCandidates.forEach(item => {
//                     const shortcutText = String(item.template || item.value || '').trim().toLowerCase();
//                     const commandText = String(item.quickHistoryCommand || item.help || '').trim().toLowerCase();
//                     const searchText = String(item.searchText || '').toLowerCase();
//
//                     if (shortcutText === keyword) {
//                         exactMatches.push(item);
//                         return;
//                     }
//
//                     if (shortcutText.startsWith(keyword)) {
//                         prefixMatches.push(item);
//                         return;
//                     }
//
//                     if (commandText.includes(keyword) || searchText.includes(keyword)) {
//                         textMatches.push(item);
//                     }
//                 });
//
//                 callback([
//                     ...this.sortQuickHistoryShortcutCandidates(exactMatches),
//                     ...this.sortQuickHistoryShortcutCandidates(prefixMatches),
//                     ...this.sortQuickHistoryShortcutCandidates(textMatches)
//                 ]);
//                 return;
//             }
//
//             const result = normalCandidates.filter(item => {
//                 const searchText = String(item.searchText || '').toLowerCase();
//                 return searchText.includes(keyword);
//             });
//
//             callback(result);
//         },
//
//         handleCommandCandidateSelect(item) {
//             if (!item) return;
//             this.commandText = String(item.template || item.value || '');
//         },
//
//         async loadCommandCandidates(clientId) {
//             if (!clientId) return;
//
//             const historyMachineId = this.resolveCommandHistoryMachineId(clientId);
//
//             try {
//                 const requests = [
//                     fetch(`/api/connections/${encodeURIComponent(clientId)}/command-candidates`),
//                     historyMachineId
//                         ? fetch(`/api/machines/${encodeURIComponent(historyMachineId)}/command-history`)
//                         : Promise.resolve({ok: true, json: async () => ({code: 0, data: []})})
//                 ];
//
//                 const [candidateRes, historyRes] = await Promise.all(requests);
//
//                 const candidateJson = await candidateRes.json();
//                 const historyJson = await historyRes.json();
//
//                 if (!candidateRes.ok || candidateJson.code !== 0) {
//                     throw new Error(candidateJson.message || 'Failed to load command candidates');
//                 }
//
//                 if (!historyRes.ok || historyJson.code !== 0) {
//                     throw new Error(historyJson.message || 'Failed to load command history');
//                 }
//
//                 const systemCandidates = Array.isArray(candidateJson.data) ? candidateJson.data : [];
//                 const historyItems = Array.isArray(historyJson.data) ? historyJson.data : [];
//
//                 const merged = [];
//                 const seen = new Set();
//
//                 const buildCandidateGroupLabel = (item) => {
//                     const groupText = String(item.group || item.source || '').trim();
//                     if (!groupText) return '';
//                     return groupText;
//                 };
//
//                 const normalizeCandidateItem = (item) => {
//                     const template = String(item.template || '').trim();
//                     const name = String(item.name || template || '').trim();
//                     const help = String(item.help || '').trim();
//                     const group = String(item.group || '').trim();
//                     const source = String(item.source || '').trim();
//
//                     return {
//                         ...item,
//                         value: template,
//                         name,
//                         template,
//                         help,
//                         group,
//                         source,
//                         groupLabel: buildCandidateGroupLabel(item),
//                         searchText: [
//                             template,
//                             name,
//                             help,
//                             group,
//                             source,
//                             buildCandidateGroupLabel(item)
//                         ]
//                             .filter(Boolean)
//                             .join(' ')
//                             .toLowerCase()
//                     };
//                 };
//
//                 const pushUniqueCandidate = (item) => {
//                     const normalized = normalizeCandidateItem(item);
//                     const template = normalized.template;
//
//                     if (!template || seen.has(template)) return;
//                     seen.add(template);
//                     merged.push(normalized);
//                 };
//
//                 const visibleSystemCandidates = systemCandidates.filter(item => item.suggest !== false);
//
//                 const clientCandidates = visibleSystemCandidates.filter(
//                     item => item.source === 'client' && item.group !== 'acmd'
//                 );
//                 const acmdCandidates = visibleSystemCandidates.filter(
//                     item => item.source === 'client' && item.group === 'acmd'
//                 );
//                 const serverCandidates = visibleSystemCandidates.filter(item => item.source === 'server');
//                 const aliasCandidates = visibleSystemCandidates.filter(item => item.source === 'alias');
//                 const scriptCandidates = visibleSystemCandidates.filter(item => item.source === 'script');
//                 const commonOpsCandidates = this.buildCommonOpsCandidates();
//
//                 clientCandidates.forEach(pushUniqueCandidate);
//                 acmdCandidates.forEach(pushUniqueCandidate);
//                 serverCandidates.forEach(pushUniqueCandidate);
//                 commonOpsCandidates.forEach(pushUniqueCandidate);
//                 aliasCandidates.forEach(pushUniqueCandidate);
//                 scriptCandidates.forEach(pushUniqueCandidate);
//
//                 historyItems.forEach((item) => {
//                     const command = String(item.command || '').trim();
//                     if (!command || seen.has(command)) return;
//                     seen.add(command);
//                     merged.push(normalizeCandidateItem({
//                         name: command,
//                         template: command,
//                         help: 'Recent command',
//                         source: 'history',
//                         group: 'history'
//                     }));
//                 });
//
//                 this.buildQuickHistoryShortcutCandidates(historyItems).forEach((item) => {
//                     merged.push(item);
//                 });
//
//                 this.commandCandidates = merged;
//                 this.commandCandidatesLoadedFor = clientId;
//             } catch (e) {
//                 this.commandCandidates = [];
//                 this.commandCandidatesLoadedFor = '';
//             }
//         },
//
//         sortQuickHistoryShortcutCandidates(items) {
//             const list = Array.isArray(items) ? [...items] : [];
//
//             return list.sort((a, b) => {
//                 const ai = Number.parseInt(a && a.quickHistoryIndex, 10);
//                 const bi = Number.parseInt(b && b.quickHistoryIndex, 10);
//
//                 const av = Number.isInteger(ai) ? ai : Number.MAX_SAFE_INTEGER;
//                 const bv = Number.isInteger(bi) ? bi : Number.MAX_SAFE_INTEGER;
//
//                 return av - bv;
//             });
//         },
//
//         buildQuickHistoryShortcutCandidates(historyItems) {
//             const items = Array.isArray(historyItems) ? historyItems : [];
//
//             return items
//                 .map((item) => {
//                     const indexValue = Number.parseInt(item && item.index, 10);
//                     const commandText = String((item && item.command) || '').trim();
//
//                     if (!Number.isInteger(indexValue) || indexValue <= 0 || !commandText) {
//                         return null;
//                     }
//
//                     const shortcutText = `!${indexValue}`;
//                     return {
//                         name: shortcutText,
//                         value: shortcutText,
//                         template: shortcutText,
//                         help: commandText,
//                         source: 'quick_history_shortcut',
//                         group: 'quick_history',
//                         groupLabel: 'quick_history',
//                         quickHistoryIndex: indexValue,
//                         quickHistoryCommand: commandText,
//                         searchText: [
//                             shortcutText,
//                             `! ${indexValue}`,
//                             String(indexValue),
//                             commandText,
//                             'quick history',
//                             'history shortcut'
//                         ]
//                             .filter(Boolean)
//                             .join(' ')
//                             .toLowerCase()
//                     };
//                 })
//                 .filter(Boolean);
//         },
//     }
// }