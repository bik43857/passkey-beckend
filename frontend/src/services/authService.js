import { api } from './api';

export const authService = {
  register: ({ name, email, password }) =>
    api.post('/api/auth/register', { name, email, password: password || undefined }),

  loginWithPassword: ({ email, password }) =>
    api.post('/api/auth/login/password', { email, password }),

  logout: () => api.post('/api/auth/logout'),

  logoutAll: () => api.post('/api/auth/logout-all'),

  // Resolves the current session's user, or throws (401) if not signed in.
  getCurrentUser: () => api.get('/api/auth/me'),
};
