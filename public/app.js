(function () {
  'use strict';

  const UI_BASE_PATH = window.IAM_UI_BASE_PATH ?? (
    location.pathname === '/iam' || location.pathname.startsWith('/iam/') ? '/iam' : ''
  );
  const API_PREFIX = `${UI_BASE_PATH}/v1`;
  const UI_LOGIN_PATH = UI_BASE_PATH ? `${UI_BASE_PATH}/login` : '/login';
  const DEV_MODE = true;
  const UI_CLIENT_STORAGE_KEY = 'iam.ui.client_id';

  const DEFAULT_UI_SETTINGS = Object.freeze({
    pageTitle: 'IAM',
    brandName: 'IAM',
    logoText: 'I',
    subtitle: 'Access your IAM account',
    accentColor: '#6366f1',
    accentStrongColor: '#4f46e5',
    backgroundColor: '#0b1020',
    surfaceColor: '#151b30',
    textColor: '#eef2ff',
    mutedTextColor: '#9aa7c7',
    inputBackgroundColor: '#10162a',
    inputBorderColor: '#3f4b78',
    inputTextColor: '#eef2ff',
    buttonTextColor: '#ffffff',
    linkColor: '#4f46e5',
    linkHoverColor: '#6366f1',
  });

  window.IAM_UI_BASE_PATH = UI_BASE_PATH;

  function isLoginRoute() {
    return location.pathname === UI_LOGIN_PATH;
  }

  function rememberClientId(clientId) {
    if (!clientId) return;
    try { window.sessionStorage.setItem(UI_CLIENT_STORAGE_KEY, clientId); } catch { /* storage may be unavailable */ }
  }

  function rememberedClientId() {
    if (!isLoginRoute()) return '';
    try { return window.sessionStorage.getItem(UI_CLIENT_STORAGE_KEY) || ''; } catch { return ''; }
  }

  function requestedClientId() {
    const params = new URLSearchParams(location.search);
    const direct = params.get('client_id');
    if (direct) { rememberClientId(direct); return direct; }
    const next = params.get('next');
    if (next) {
      try {
        const clientId = new URL(next, location.origin).searchParams.get('client_id');
        if (clientId) { rememberClientId(clientId); return clientId; }
      } catch {
        // Fall back to the IAM theme for malformed or expired return targets.
      }
    }
    return rememberedClientId() || 'sys_iam';
  }

  function validHexColor(value) {
    return typeof value === 'string' && /^#[0-9a-fA-F]{6}$/.test(value);
  }

  function applyUiSettings(input) {
    const settings = { ...DEFAULT_UI_SETTINGS, ...(input || {}) };
    for (const [key, cssVariable] of [
      ['accentColor', '--accent'],
      ['accentStrongColor', '--accent-hover'],
      ['backgroundColor', '--bg'],
      ['surfaceColor', '--card'],
      ['textColor', '--text'],
      ['mutedTextColor', '--muted'],
      ['inputBackgroundColor', '--input'],
      ['inputBorderColor', '--input-border'],
      ['inputTextColor', '--input-text'],
      ['buttonTextColor', '--button-text'],
      ['linkColor', '--link'],
      ['linkHoverColor', '--link-hover'],
    ]) {
      if (validHexColor(settings[key])) document.documentElement.style.setProperty(cssVariable, settings[key]);
    }
    document.title = settings.pageTitle;
    document.querySelectorAll('[data-ui-brand-name]').forEach((node) => { node.textContent = settings.brandName; });
    document.querySelectorAll('[data-ui-logo]').forEach((node) => { node.textContent = settings.logoText; });
    document.querySelectorAll('[data-ui-auth-subtitle]').forEach((node) => { node.textContent = settings.subtitle; });
    window.IAM_UI_SETTINGS = settings;
    return settings;
  }

  async function loadUiSettings() {
    try {
      const response = await fetch(`${API_PREFIX}/ui-config?client_id=${encodeURIComponent(requestedClientId())}`, { credentials: 'include' });
      if (!response.ok) return applyUiSettings(DEFAULT_UI_SETTINGS);
      const payload = await response.json();
      return applyUiSettings(payload.settings);
    } catch {
      return applyUiSettings(DEFAULT_UI_SETTINGS);
    }
  }

  const uiReady = loadUiSettings();

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
    applyUiSettings,
    uiReady,
    initials,
    esc,
    DEV_MODE,
  };
})();
