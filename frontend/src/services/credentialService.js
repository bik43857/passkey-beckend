import { api } from './api';

export const credentialService = {
  list: () => api.get('/api/settings/credentials'),
  rename: (id, deviceName) => api.patch(`/api/settings/credentials/${id}`, { deviceName }),
  remove: (id) => api.delete(`/api/settings/credentials/${id}`),
};
