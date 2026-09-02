import { apiData, jsonRequestOptions } from './http.js'

export function listDeviceGroups() {
  return apiData('/api/device-groups', {}, { groups: [], machine_groups: {} })
}

export function createDeviceGroup(name) {
  return apiData(
    '/api/device-groups',
    jsonRequestOptions('POST', { name }),
    { groups: [], machine_groups: {} },
  )
}

export function renameDeviceGroup(groupId, name) {
  return apiData(
    `/api/device-groups/${encodeURIComponent(groupId)}`,
    jsonRequestOptions('PATCH', { name }),
    { groups: [], machine_groups: {} },
  )
}

export function deleteDeviceGroup(groupId) {
  return apiData(
    `/api/device-groups/${encodeURIComponent(groupId)}`,
    { method: 'DELETE' },
    { groups: [], machine_groups: {} },
  )
}

export function assignMachineDeviceGroup(machineId, groupId = '') {
  return apiData(
    `/api/machines/${encodeURIComponent(machineId)}/device-group`,
    jsonRequestOptions('PATCH', { group_id: groupId }),
    { groups: [], machine_groups: {} },
  )
}
