(function () {
  'use strict';

  const API_PREFIX = '/v1';
  const DEV_MODE = true;

  async function api(method, route, body) {
    const opts = { method, credentials: 'include', headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(API_PREFIX + route, opts);
    const ct = res.headers.get('content-type') || '';
    const data = ct.includes('application/json') ? await res.json().catch(() => ({})) : {};
    return { ok: res.ok, status: res.status, data };
  }

  async function me() {
    const r = await api('GET', '/me');
    return r.ok ? r.data.user : null;
  }

  function login(username, password) {
    return api('POST', '/login', { username, password });
  }

  function logout() {
    return api('POST', '/logout');
  }

  function register(payload) {
    return api('POST', '/register', payload);
  }

  function forgotPassword(payload) {
    return api('POST', '/forgot-password', payload);
  }

  function resetPassword(username, token, newPassword) {
    return api('POST', '/reset-password', { username, token, newPassword });
  }

  function changePassword(currentPassword, newPassword) {
    return api('POST', '/change-password', { currentPassword, newPassword });
  }

  function initials(name) {
    const parts = String(name || '?').trim().split(/\s+/).filter(Boolean);
    return ((parts[0] || '?').charAt(0) + (parts.length > 1 ? parts[parts.length - 1].charAt(0) : '')).toUpperCase() || '?';
  }

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  window.IAM = {
    api,
    me,
    login,
    logout,
    register,
    forgotPassword,
    resetPassword,
    changePassword,
    initials,
    esc,
    DEV_MODE,
  };
})();
