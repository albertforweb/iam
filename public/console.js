(function () {
  'use strict';

  const state = {
    me: null,
    users: [],
    clients: [],
    systemRoles: [],
    audit: [],
    selectedClientId: '',
    permissions: [],
    appRoles: [],
    roleDetail: null,
    delegations: {},
    query: '',
  };

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const esc = (value) => IAM.esc(value ?? '');
  const routeId = (value) => encodeURIComponent(String(value));
  const userDisplayName = (user) => user?.displayName || user?.display_name || user?.username || 'User';

  function syncSidebarIdentity() {
    const name = userDisplayName(state.me);
    $('#sidebarName').textContent = name;
    $('#sidebarRole').textContent = (state.me?.roles || []).includes('admin') ? 'System administrator' : 'Member';
    $('#sidebarAvatar').textContent = IAM.initials(name);
  }

  function normalizeUrl() {
    if (location.pathname !== '/index.html' || location.search || location.hash) {
      window.history.replaceState(null, '', '/index.html');
    }
  }

  function showMessage(id, message, kind = 'err') {
    const node = document.getElementById(id);
    node.textContent = message || '';
    node.className = message ? `msg show ${kind}` : 'msg';
  }

  function showAuthScreen(screen = 'login', message = '') {
    normalizeUrl();
    $('#authView').hidden = false;
    $('#consoleShell').hidden = true;
    $$('.auth-panel').forEach((panel) => { panel.hidden = panel.dataset.authScreenPanel !== screen; });
    ['login', 'signup', 'forgot', 'reset'].forEach((name) => showMessage(`${name}Message`, ''));
    if (message) showMessage(`${screen}Message`, message, 'ok');
    document.title = screen === 'login' ? 'IAM - Sign in' : `IAM - ${screen[0].toUpperCase()}${screen.slice(1)}`;
    document.body.classList.remove('is-loading');
  }

  function fillProfile(user) {
    $('#profileSubtitle').textContent = `Signed in as @${user.username}`;
    $('#profileDisplayName').textContent = userDisplayName(user);
    $('#profileUsername').textContent = `@${user.username}`;
    $('#profileAvatar').textContent = IAM.initials(userDisplayName(user));
    $('#profileEmail').textContent = user.email || '-';
    $('#profileStatus').textContent = user.status || '-';
    const createdAt = user.created_at ? new Date(user.created_at) : null;
    const normalizedCreatedAt = createdAt && !Number.isNaN(createdAt.getTime())
      ? createdAt
      : user.created_at ? new Date(`${user.created_at}Z`) : null;
    $('#profileCreatedAt').textContent = normalizedCreatedAt && !Number.isNaN(normalizedCreatedAt.getTime())
      ? normalizedCreatedAt.toLocaleString() : '-';
    $('#profileRoles').textContent = '';
    (user.roles || []).forEach((role) => {
      const tag = document.createElement('span');
      tag.className = 'role-tag';
      tag.textContent = role;
      $('#profileRoles').appendChild(tag);
    });
  }

  function showProfile(user) {
    normalizeUrl();
    state.me = user;
    syncSidebarIdentity();
    fillProfile(user);
    $('#authView').hidden = true;
    $('#consoleShell').hidden = false;
    const isAdmin = (user.roles || []).includes('admin');
    $('#adminNavLabel').hidden = !isAdmin;
    $('#adminNavigation').hidden = !isAdmin;
    $('#adminTopbarActions').hidden = !isAdmin;
    $('#accountNavLabel').hidden = false;
    $('#accountNavigation').hidden = false;
    document.title = 'IAM - Profile';
    document.body.classList.remove('is-loading');
    setView('profile');
  }

  async function showAdmin() {
    normalizeUrl();
    syncSidebarIdentity();
    $('#authView').hidden = true;
    $('#consoleShell').hidden = false;
    $('#adminNavLabel').hidden = false;
    $('#adminNavigation').hidden = false;
    $('#adminTopbarActions').hidden = false;
    $('#accountNavLabel').hidden = false;
    $('#accountNavigation').hidden = false;
    document.title = 'IAM Console';
    document.body.classList.remove('is-loading');
    fillProfile(state.me);
    setView(state.view && !['profile', 'password'].includes(state.view) ? state.view : 'overview');
    if (!state.users.length) await loadData();
    syncSidebarIdentity();
  }

  async function routeUser(user) {
    state.me = user;
    if ((user.roles || []).includes('admin')) return showAdmin();
    showProfile(user);
  }

  async function signOut() {
    await IAM.logout();
    state.me = null;
    state.users = [];
    state.clients = [];
    showAuthScreen('login', 'You have signed out.');
  }

  async function submitLogin(event) {
    event.preventDefault();
    showMessage('loginMessage', '');
    const button = $('#loginSubmitBtn');
    button.disabled = true;
    button.textContent = 'Signing in...';
    const result = await IAM.login($('#loginUsername').value.trim(), $('#loginPassword').value);
    button.disabled = false;
    button.textContent = 'Sign in';
    if (!result.ok) return showMessage('loginMessage', result.data.error || `Login failed (HTTP ${result.status})`);
    $('#loginForm').reset();
    await routeUser(result.data.user);
  }

  async function submitSignup(event) {
    event.preventDefault();
    showMessage('signupMessage', '');
    const password = $('#signupPassword').value;
    if (password.length < 8) return showMessage('signupMessage', 'Password must be at least 8 characters.');
    if (password !== $('#signupConfirm').value) return showMessage('signupMessage', 'Passwords do not match.');
    const button = $('#signupSubmitBtn');
    button.disabled = true;
    button.textContent = 'Creating...';
    const payload = {
      username: $('#signupUsername').value.trim(),
      displayName: $('#signupDisplayName').value.trim(),
      password,
    };
    const email = $('#signupEmail').value.trim();
    if (email) payload.email = email;
    const result = await IAM.register(payload);
    button.disabled = false;
    button.textContent = 'Create account';
    if (!result.ok) return showMessage('signupMessage', result.data.error || `Registration failed (HTTP ${result.status})`);
    $('#signupForm').reset();
    await routeUser(result.data.user);
  }

  function updateRecoveryMode() {
    const resetting = $('#recoveryMode').value === 'reset';
    $('#recoveryFieldLabel').textContent = resetting ? 'Username' : 'Email';
    $('#recoveryField').type = resetting ? 'text' : 'email';
    $('#recoveryField').value = '';
    showMessage('forgotMessage', '');
  }

  async function submitForgot(event) {
    event.preventDefault();
    const resetting = $('#recoveryMode').value === 'reset';
    const value = $('#recoveryField').value.trim();
    if (!value) return showMessage('forgotMessage', resetting ? 'Enter your username.' : 'Enter your email.');
    const button = $('#forgotSubmitBtn');
    button.disabled = true;
    button.textContent = 'Submitting...';
    const result = await IAM.forgotPassword(resetting ? { username: value } : { email: value });
    button.disabled = false;
    button.textContent = 'Continue';
    if (!result.ok) return showMessage('forgotMessage', result.data.error || `Request failed (HTTP ${result.status})`);
    if (resetting && result.data.resetToken) {
      $('#resetUsername').value = result.data.username || value;
      $('#resetToken').value = result.data.resetToken;
      showAuthScreen('reset', `${result.data.message} Reset your password below.`);
    } else if (result.data.username) {
      showMessage('forgotMessage', `Your username is: ${result.data.username}`, 'ok');
    } else {
      showMessage('forgotMessage', result.data.message || 'If the account exists, the next steps have been sent.', 'ok');
    }
  }

  async function submitReset(event) {
    event.preventDefault();
    const password = $('#resetPassword').value;
    if (password.length < 8) return showMessage('resetMessage', 'Password must be at least 8 characters.');
    if (password !== $('#resetConfirm').value) return showMessage('resetMessage', 'Passwords do not match.');
    const button = $('#resetSubmitBtn');
    button.disabled = true;
    button.textContent = 'Resetting...';
    const result = await IAM.resetPassword($('#resetUsername').value.trim(), $('#resetToken').value.trim(), password);
    button.disabled = false;
    button.textContent = 'Reset password';
    if (!result.ok) return showMessage('resetMessage', result.data.error || `Reset failed (HTTP ${result.status})`);
    $('#resetForm').reset();
    showAuthScreen('login', 'Password updated. Sign in with your new password.');
  }

  async function submitChangePassword(event) {
    event.preventDefault();
    const password = $('#newPassword').value;
    if (password.length < 8) return showMessage('passwordMessage', 'Password must be at least 8 characters.');
    if (password !== $('#confirmPassword').value) return showMessage('passwordMessage', 'Passwords do not match.');
    const button = $('#changePasswordBtn');
    button.disabled = true;
    button.textContent = 'Updating...';
    const result = await IAM.changePassword($('#currentPassword').value, password);
    button.disabled = false;
    button.textContent = 'Update password';
    if (!result.ok) return showMessage('passwordMessage', result.data.error || `Update failed (HTTP ${result.status})`);
    $('#changePasswordForm').reset();
    showMessage('passwordMessage', 'Password updated.', 'ok');
  }

  async function api(method, route, body) {
    const result = await IAM.api(method, route, body);
    if (result.status === 401 || result.status === 403) {
      throw new Error(result.data?.error || 'Administrator access required');
    }
    if (!result.ok) throw new Error(result.data?.error || `Request failed (HTTP ${result.status})`);
    return result.data;
  }

  function showToast(message, kind = 'ok') {
    const toast = $('#toast');
    toast.textContent = message;
    toast.className = `console-toast show ${kind}`;
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => { toast.className = 'console-toast'; }, 3600);
  }

  function showFormMessage(id, message, kind = 'err') {
    const node = document.getElementById(id);
    node.textContent = message || '';
    node.className = message ? `form-message show ${kind}` : 'form-message';
  }

  function formatDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? esc(value) : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  }

  function initials(user) {
    return IAM.initials(user?.display_name || user?.displayName || user?.username || '?');
  }

  function setView(view) {
    const titles = {
      overview: 'Overview', users: 'Users', applications: 'Applications', authorization: 'Scopes & roles',
      oauth: 'OAuth clients', delegations: 'Delegations', audit: 'Audit log', profile: 'Profile', password: 'Password',
    };
    state.view = view;
    $('#pageTitle').textContent = titles[view] || 'Overview';
    document.title = ['profile', 'password'].includes(view) ? `IAM - ${titles[view]}` : 'IAM Console';
    $$('.console-nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === view));
    $$('.console-view').forEach((panel) => panel.classList.toggle('active', panel.dataset.viewPanel === view));
    if (view === 'authorization') loadAuthorization().catch((error) => showToast(error.message, 'err'));
    if (view === 'delegations') loadDelegations().catch((error) => showToast(error.message, 'err'));
  }

  function renderOverview() {
    const activeUsers = state.users.filter((user) => user.status === 'active').length;
    const scopes = state.clients.reduce((total, client) => total + (client.allowed_scopes || []).length, 0);
    const admins = state.users.filter((user) => user.status === 'active' && (user.roles || []).includes('admin')).length;
    $('#metricUsers').textContent = state.users.length;
    $('#metricUsersMeta').textContent = `${activeUsers} active identities`;
    $('#metricApps').textContent = state.clients.length;
    $('#metricAppsMeta').textContent = `${state.clients.filter((client) => client.enabled).length} enabled clients`;
    $('#metricScopes').textContent = scopes;
    $('#metricScopesMeta').textContent = 'Registered client scopes';
    $('#metricAdmins').textContent = admins;

    $('#overviewUsers').innerHTML = state.users.slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, 5).map((user) => `
      <button class="compact-row" data-action="edit-user" data-id="${esc(user.id)}">
        <span class="console-avatar small">${esc(initials(user))}</span><span class="compact-main"><strong>${esc(user.display_name)}</strong><small>@${esc(user.username)}</small></span><span class="status-dot ${esc(user.status)}"></span>
      </button>`).join('') || '<div class="empty-state">No users yet.</div>';
    $('#overviewAudit').innerHTML = state.audit.slice(0, 5).map((event) => `
      <div class="compact-row static"><span class="event-mark ${event.success ? 'success' : 'failure'}">${event.success ? '✓' : '!'}</span><span class="compact-main"><strong>${esc(event.event_type.replaceAll('_', ' '))}</strong><small>${esc(formatDate(event.created_at))}</small></span></div>`).join('') || '<div class="empty-state">No events yet.</div>';
  }

  function renderUsers() {
    const status = $('#userStatusFilter').value;
    const query = `${state.query} ${$('#userSearch').value}`.trim().toLowerCase();
    const users = state.users.filter((user) => {
      const matchesStatus = !status || user.status === status;
      const haystack = `${user.username} ${user.display_name} ${user.email || ''}`.toLowerCase();
      return matchesStatus && (!query || haystack.includes(query));
    });
    $('#usersTable').innerHTML = users.map((user) => `
      <tr><td><div class="table-person"><span class="console-avatar small">${esc(initials(user))}</span><span><strong>${esc(user.display_name)}</strong><small>@${esc(user.username)}${user.email ? ` · ${esc(user.email)}` : ''}</small></span></div></td>
      <td><span class="status-pill ${esc(user.status)}">${esc(user.status)}</span></td>
      <td><div class="tag-row">${(user.roles || []).map((role) => `<span class="mini-tag">${esc(role)}</span>`).join('') || '<span class="muted">No roles</span>'}</div></td>
      <td class="muted">${esc(formatDate(user.created_at))}</td>
      <td class="align-right"><button class="row-action" data-action="edit-user" data-id="${esc(user.id)}">Edit</button><button class="row-action danger" data-action="delete-user" data-id="${esc(user.id)}">Delete</button></td></tr>`).join('') || '<tr><td colspan="5"><div class="empty-state">No users match your filters.</div></td></tr>';
  }

  function appTypeLabel(client) {
    return client.client_type === 'service' ? 'Service / API' : client.client_type === 'public' ? 'Public client' : 'Confidential';
  }

  function renderApplications() {
    const clients = state.clients.filter((client) => {
      const query = state.query.toLowerCase();
      return !query || `${client.client_id} ${client.name} ${client.description || ''}`.toLowerCase().includes(query);
    });
    $('#applicationsTable').innerHTML = clients.map((client) => `
      <tr><td><div class="app-person"><span class="app-logo">${esc((client.name || client.client_id).slice(0, 1).toUpperCase())}</span><span><strong>${esc(client.name)}</strong><small>${esc(client.client_id)}</small></span></div></td>
      <td><span class="type-pill">${esc(appTypeLabel(client))}</span></td><td><div class="tag-row">${(client.grant_types || []).map((grant) => `<span class="mini-tag">${esc(grant.replace('urn:ietf:params:oauth:grant-type:', ''))}</span>`).join('')}</div></td>
      <td><strong>${(client.allowed_scopes || []).length}</strong> <span class="muted">scopes</span></td><td><span class="status-pill ${client.enabled ? 'active' : 'inactive'}">${client.enabled ? 'Enabled' : 'Disabled'}</span></td>
      <td class="align-right"><button class="row-action" data-action="manage-app" data-id="${esc(client.client_id)}">Manage</button><button class="row-action" data-action="edit-app" data-id="${esc(client.client_id)}">Edit</button>${client.is_system ? '' : `<button class="row-action danger" data-action="delete-app" data-id="${esc(client.client_id)}">Delete</button>`}</td></tr>`).join('') || '<tr><td colspan="6"><div class="empty-state">No applications registered.</div></td></tr>';

    $('#oauthTable').innerHTML = clients.map((client) => `
      <tr><td><div class="app-person"><span class="app-logo">${esc((client.name || client.client_id).slice(0, 1).toUpperCase())}</span><span><strong>${esc(client.client_id)}</strong><small>${esc(client.name)}</small></span></div></td>
      <td><span class="type-pill">${esc(client.client_type === 'public' ? 'Public / PKCE' : 'Client secret')}</span></td><td><span class="muted">${(client.redirect_uris || []).length} configured</span></td><td>${(client.allowed_scopes || []).length} scopes</td><td>${(client.grant_types || []).some((grant) => grant.includes('token-exchange')) ? '<span class="status-pill active">Allowed</span>' : '<span class="muted">Not enabled</span>'}</td>
      <td class="align-right"><button class="row-action" data-action="edit-app" data-id="${esc(client.client_id)}">Configure</button><button class="row-action" data-action="rotate-secret" data-id="${esc(client.client_id)}">Rotate</button>${client.is_system ? '' : `<button class="row-action danger" data-action="delete-app" data-id="${esc(client.client_id)}">Delete</button>`}</td></tr>`).join('') || '<tr><td colspan="6"><div class="empty-state">No OAuth clients registered.</div></td></tr>';
  }

  function renderAuthorization() {
    const app = state.clients.find((client) => client.client_id === state.selectedClientId);
    $('#authorizationAppSelect').innerHTML = state.clients.map((client) => `<option value="${esc(client.client_id)}" ${client.client_id === state.selectedClientId ? 'selected' : ''}>${esc(client.name)} · ${esc(client.client_id)}</option>`).join('');
    if (!app) {
      $('#permissionsList').innerHTML = '<div class="empty-state">Register an application to manage scopes.</div>';
      $('#rolesList').innerHTML = '';
      return;
    }
    $('#permissionsList').innerHTML = state.permissions.map((permission) => `
      <div class="stack-row"><div><strong>${esc(permission.name)}</strong><small>${esc(permission.description || 'No description')}</small></div><button class="icon-danger" data-action="delete-permission" data-id="${esc(permission.id)}" title="Delete scope">×</button></div>`).join('') || '<div class="empty-state">No permission scopes registered.</div>';
    $('#rolesList').innerHTML = state.appRoles.map((role) => `
      <div class="stack-row role-row"><div><strong>${esc(role.name)}</strong><small>${esc(role.description || 'No description')}</small></div><button class="row-action" data-action="edit-role" data-id="${esc(role.id)}">Manage scopes</button><button class="icon-danger" data-action="delete-role" data-id="${esc(role.id)}" title="Delete role">×</button></div>`).join('') || '<div class="empty-state">No application roles registered.</div>';
    renderRoleEditor();
  }

  function renderRoleEditor() {
    const editor = $('#roleEditor');
    if (!state.roleDetail) { editor.hidden = true; editor.innerHTML = ''; return; }
    editor.hidden = false;
    const selected = new Set((state.roleDetail.permissions || []).map((permission) => permission.id));
    editor.innerHTML = `<div class="role-editor-heading"><div><span class="console-kicker">EDIT ROLE</span><strong>${esc(state.roleDetail.role.name)}</strong></div><button type="button" class="dialog-close" data-action="close-role-editor">×</button></div><div class="check-grid">${state.permissions.map((permission) => `<label class="check-item"><input type="checkbox" data-role-permission="${esc(permission.id)}" ${selected.has(permission.id) ? 'checked' : ''}><span><strong>${esc(permission.name)}</strong><small>${esc(permission.description || '')}</small></span></label>`).join('') || '<span class="muted">No permissions available.</span>'}</div><button class="console-small-button" data-action="save-role">Save role permissions</button>`;
  }

  async function loadAuthorization() {
    if (!state.selectedClientId && state.clients[0]) state.selectedClientId = state.clients[0].client_id;
    if (!state.selectedClientId) return renderAuthorization();
    const [permissions, roles] = await Promise.all([
      api('GET', `/clients/${routeId(state.selectedClientId)}/permissions`),
      api('GET', `/clients/${routeId(state.selectedClientId)}/roles`),
    ]);
    state.permissions = permissions.permissions || [];
    state.appRoles = roles.roles || [];
    state.roleDetail = null;
    renderAuthorization();
  }

  async function loadDelegations() {
    const entries = await Promise.all(state.clients.map(async (client) => [client.client_id, (await api('GET', `/clients/${routeId(client.client_id)}/delegations`)).policies || []]));
    state.delegations = Object.fromEntries(entries);
    populateDelegationApps();
    renderDelegations();
  }

  function populateDelegationApps() {
    const source = $('#delegationSource');
    const target = $('#delegationTarget');
    const currentSource = source.value || state.clients[0]?.client_id || '';
    source.innerHTML = state.clients.map((client) => `<option value="${esc(client.client_id)}">${esc(client.name)} · ${esc(client.client_id)}</option>`).join('');
    source.value = currentSource;
    const currentTarget = target.value;
    target.innerHTML = state.clients.filter((client) => client.client_id !== source.value).map((client) => `<option value="${esc(client.client_id)}">${esc(client.name)} · ${esc(client.client_id)}</option>`).join('');
    if (state.clients.some((client) => client.client_id === currentTarget && currentTarget !== source.value)) target.value = currentTarget;
    renderDelegationScopes();
  }

  async function renderDelegationScopes() {
    const targetId = $('#delegationTarget').value;
    if (!targetId) { $('#delegationScopes').innerHTML = '<span class="empty-state">No target API selected.</span>'; return; }
    try {
      if (!state.permissionCache) state.permissionCache = {};
      if (!state.permissionCache[targetId]) state.permissionCache[targetId] = (await api('GET', `/clients/${routeId(targetId)}/permissions`)).permissions || [];
      const permissions = state.permissionCache[targetId];
      $('#delegationScopes').innerHTML = permissions.length ? permissions.map((permission) => `<label class="check-item"><input type="checkbox" value="${esc(permission.name)}"><span><strong>${esc(permission.name)}</strong><small>${esc(permission.description || '')}</small></span></label>`).join('') : '<span class="empty-state">Target has no registered permission scopes.</span>';
    } catch (error) { $('#delegationScopes').innerHTML = `<span class="empty-state">${esc(error.message)}</span>`; }
  }

  function renderDelegations() {
    const rows = [];
    state.clients.forEach((source) => (state.delegations[source.client_id] || []).forEach((policy) => rows.push(`<tr><td><strong>${esc(source.name)}</strong><small>${esc(source.client_id)}</small></td><td><strong>${esc(policy.targetClientId)}</strong></td><td><div class="tag-row">${(policy.allowedScopes || []).map((scope) => `<span class="mini-tag">${esc(scope)}</span>`).join('')}</div></td><td class="muted">${esc(formatDate(policy.updatedAt))}</td><td class="align-right"><button class="row-action danger" data-action="delete-delegation" data-source="${esc(source.client_id)}" data-target="${esc(policy.targetClientId)}">Revoke</button></td></tr>`)));
    $('#delegationsTable').innerHTML = rows.join('') || '<tr><td colspan="5"><div class="empty-state">No delegated trust policies configured.</div></td></tr>';
  }

  function renderAudit() {
    $('#auditTable').innerHTML = state.audit.map((event) => `<tr><td><strong>${esc(event.event_type.replaceAll('_', ' '))}</strong><small>${esc(event.id)}</small></td><td>${esc(event.user_id || 'System')}</td><td>${esc(event.client_id || '—')}</td><td><span class="status-pill ${event.success ? 'active' : 'suspended'}">${event.success ? 'Success' : 'Denied'}</span></td><td class="muted">${esc(formatDate(event.created_at))}</td></tr>`).join('') || '<tr><td colspan="5"><div class="empty-state">No audit events found.</div></td></tr>';
  }

  function openDialog(id) { const dialog = document.getElementById(id); if (typeof dialog.showModal === 'function') dialog.showModal(); else dialog.setAttribute('open', ''); }
  function closeDialogs() { $$('dialog[open]').forEach((dialog) => dialog.close()); }

  function openAppEditor(clientId = '') {
    const client = state.clients.find((item) => item.client_id === clientId);
    $('#appDialogTitle').textContent = client ? 'Edit application' : 'Register application';
    $('#appEditId').value = client?.client_id || '';
    $('#appClientId').value = client?.client_id || '';
    $('#appClientId').disabled = !!client;
    $('#appName').value = client?.name || '';
    $('#appDescription').value = client?.description || '';
    $('#appClientType').value = client?.client_type || 'confidential';
    $('#appEnabled').value = client?.enabled === false ? 'false' : 'true';
    $('#appGrantTypes').value = (client?.grant_types || ['authorization_code', 'refresh_token']).join(', ');
    $('#appRedirectUris').value = (client?.redirect_uris || []).join('\n');
    $('#appAllowedScopes').value = (client?.allowed_scopes || []).join(', ');
    showFormMessage('appFormMessage', '');
    openDialog('appDialog');
  }

  function renderUserRoleChoices(selected = []) {
    $('#userRoles').innerHTML = state.systemRoles.map((role) => `<label class="check-item compact"><input type="checkbox" value="${esc(role.name)}" ${selected.includes(role.name) ? 'checked' : ''}><span><strong>${esc(role.name)}</strong><small>${esc(role.description || '')}</small></span></label>`).join('');
  }

  function openUserEditor(userId = '') {
    const user = state.users.find((item) => item.id === userId);
    $('#userDialogTitle').textContent = user ? 'Edit user' : 'Create user';
    $('#userEditId').value = user?.id || '';
    $('#userUsername').value = user?.username || '';
    $('#userUsername').disabled = !!user;
    $('#userDisplayName').value = user?.display_name || '';
    $('#userEmail').value = user?.email || '';
    $('#userStatus').value = user?.status || 'active';
    $('#userPassword').value = '';
    renderUserRoleChoices(user?.roles || ['member']);
    showFormMessage('userFormMessage', '');
    openDialog('userDialog');
  }

  function showCredential(secret) {
    $('#credentialValue').textContent = secret;
    $('#credentialDialog').hidden = false;
  }

  async function loadData() {
    const [users, clients, roles, audit] = await Promise.all([
      api('GET', '/users'), api('GET', '/clients'), api('GET', '/roles'), api('GET', '/audit-events?limit=50'),
    ]);
    state.users = users.users || [];
    state.clients = clients.clients || [];
    state.systemRoles = roles.roles || [];
    state.audit = audit.events || [];
    if (!state.selectedClientId || !state.clients.some((client) => client.client_id === state.selectedClientId)) state.selectedClientId = state.clients[0]?.client_id || '';
    renderOverview(); renderUsers(); renderApplications(); renderAuthorization(); renderAudit();
    if (state.view === 'delegations') await loadDelegations();
  }

  async function submitApp(event) {
    event.preventDefault();
    const editId = $('#appEditId').value;
    const grantTypes = $('#appGrantTypes').value.split(',').map((value) => value.trim()).filter(Boolean);
    const redirectUris = $('#appRedirectUris').value.split(/\r?\n|,/).map((value) => value.trim()).filter(Boolean);
    const allowedScopes = $('#appAllowedScopes').value.split(',').map((value) => value.trim()).filter(Boolean);
    const payload = { name: $('#appName').value.trim(), description: $('#appDescription').value.trim(), clientType: $('#appClientType').value, grantTypes, redirectUris, allowedScopes, enabled: $('#appEnabled').value === 'true' };
    if (!editId) payload.clientId = $('#appClientId').value.trim();
    try {
      const result = await api(editId ? 'PUT' : 'POST', editId ? `/clients/${routeId(editId)}` : '/clients', payload);
      closeDialogs(); await loadData(); showToast(editId ? 'Application updated' : 'Application registered');
      if (result.secret) showCredential(result.secret);
    } catch (error) { showFormMessage('appFormMessage', error.message); }
  }

  async function submitUser(event) {
    event.preventDefault();
    const editId = $('#userEditId').value;
    const roles = $$('#userRoles input:checked').map((input) => input.value);
    const payload = { displayName: $('#userDisplayName').value.trim(), email: $('#userEmail').value.trim() || null, status: $('#userStatus').value, roles };
    const password = $('#userPassword').value;
    if (password) payload.password = password;
    if (!editId) { payload.username = $('#userUsername').value.trim(); if (!password) delete payload.password; }
    try { await api(editId ? 'PUT' : 'POST', editId ? `/users/${routeId(editId)}` : '/users', payload); closeDialogs(); await loadData(); showToast(editId ? 'User updated' : 'User created'); }
    catch (error) { showFormMessage('userFormMessage', error.message); }
  }

  async function submitPermission(event) {
    event.preventDefault();
    try { await api('POST', `/clients/${routeId(state.selectedClientId)}/permissions`, { name: $('#permissionName').value.trim(), description: $('#permissionDescription').value.trim() }); closeDialogs(); await loadAuthorization(); await loadData(); showToast('Permission scope added'); }
    catch (error) { showFormMessage('permissionFormMessage', error.message); }
  }

  async function submitRole(event) {
    event.preventDefault();
    try { await api('POST', `/clients/${routeId(state.selectedClientId)}/roles`, { name: $('#roleName').value.trim(), description: $('#roleDescription').value.trim() }); closeDialogs(); await loadAuthorization(); await loadData(); showToast('Role added'); }
    catch (error) { showFormMessage('roleFormMessage', error.message); }
  }

  async function saveRole() {
    if (!state.roleDetail) return;
    const permissions = $$('[data-role-permission]:checked').map((input) => input.dataset.rolePermission);
    try { await api('PUT', `/clients/${routeId(state.selectedClientId)}/roles/${routeId(state.roleDetail.role.id)}`, { permissions }); state.roleDetail = null; await loadAuthorization(); await loadData(); showToast('Role permissions updated'); }
    catch (error) { showToast(error.message, 'err'); }
  }

  async function submitDelegation(event) {
    event.preventDefault();
    const source = $('#delegationSource').value;
    const target = $('#delegationTarget').value;
    const allowedScopes = $$('#delegationScopes input:checked').map((input) => input.value);
    if (!allowedScopes.length) return showToast('Select at least one target scope', 'err');
    try { await api('POST', `/clients/${routeId(source)}/delegations`, { targetClientId: target, allowedScopes }); await loadDelegations(); showToast('Delegation policy created'); }
    catch (error) { showToast(error.message, 'err'); }
  }

  async function handleAction(action, element) {
    const id = element.dataset.id;
    if (action === 'open-profile') return showProfile(state.me);
    if (action === 'open-console') return showAdmin().catch((error) => showToast(error.message, 'err'));
    if (action === 'open-app-create') return openAppEditor();
    if (action === 'edit-app') return openAppEditor(id);
    if (action === 'manage-app') { state.selectedClientId = id; setView('authorization'); return; }
    if (action === 'open-user-create') return openUserEditor();
    if (action === 'edit-user') return openUserEditor(id);
    if (action === 'open-permission-create') return openDialog('permissionDialog');
    if (action === 'open-role-create') return openDialog('roleDialog');
    if (action === 'close-dialog') return closeDialogs();
    if (action === 'close-role-editor') { state.roleDetail = null; return renderRoleEditor(); }
    if (action === 'save-role') return saveRole();
    if (action === 'edit-role') {
      try { state.roleDetail = await api('GET', `/clients/${routeId(state.selectedClientId)}/roles/${routeId(id)}`); renderRoleEditor(); }
      catch (error) { showToast(error.message, 'err'); }
      return;
    }
    if (action === 'delete-user' && window.confirm('Delete this user? This cannot be undone.')) {
      try { await api('DELETE', `/users/${routeId(id)}`); await loadData(); showToast('User deleted'); } catch (error) { showToast(error.message, 'err'); }
    }
    if (action === 'delete-permission' && window.confirm('Delete this permission? Roles using it must be updated first.')) {
      try { await api('DELETE', `/clients/${routeId(state.selectedClientId)}/permissions/${routeId(id)}`); await loadAuthorization(); await loadData(); showToast('Permission deleted'); } catch (error) { showToast(error.message, 'err'); }
    }
    if (action === 'delete-role' && window.confirm('Delete this role? Existing user assignments must be removed first.')) {
      try { await api('DELETE', `/clients/${routeId(state.selectedClientId)}/roles/${routeId(id)}`); await loadAuthorization(); await loadData(); showToast('Role deleted'); } catch (error) { showToast(error.message, 'err'); }
    }
    if (action === 'rotate-secret' && window.confirm('Rotate this client secret? The existing secret will stop working immediately.')) {
      try { const result = await api('POST', `/clients/${routeId(id)}/rotate-secret`); showCredential(result.secret); showToast('Client secret rotated'); } catch (error) { showToast(error.message, 'err'); }
    }
    if (action === 'delete-app' && window.confirm('Delete this application and its authorization data?')) {
      try { await api('DELETE', `/clients/${routeId(id)}`); await loadData(); showToast('Application deleted'); } catch (error) { showToast(error.message, 'err'); }
    }
    if (action === 'delete-delegation') {
      if (!window.confirm('Revoke this delegated access policy?')) return;
      try { await api('DELETE', `/clients/${routeId(element.dataset.source)}/delegations/${routeId(element.dataset.target)}`); await loadDelegations(); showToast('Delegation revoked'); } catch (error) { showToast(error.message, 'err'); }
    }
  }

  document.addEventListener('click', (event) => {
    const authScreen = event.target.closest('[data-auth-screen]');
    if (authScreen) {
      event.preventDefault();
      showAuthScreen(authScreen.dataset.authScreen);
      return;
    }
    const actionElement = event.target.closest('[data-action]');
    if (actionElement) {
      if (actionElement.tagName === 'A') event.preventDefault();
      handleAction(actionElement.dataset.action, actionElement);
    }
    const targetView = event.target.closest('[data-view-target]')?.dataset.viewTarget;
    if (targetView) setView(targetView);
    if (event.target.matches('[data-action="close-credential"]')) { $('#credentialDialog').hidden = true; $('#credentialValue').textContent = ''; }
  });

  $$('.console-nav-item').forEach((item) => item.addEventListener('click', () => setView(item.dataset.view)));
  $('#refreshBtn').addEventListener('click', () => loadData().then(() => showToast('Console refreshed')).catch((error) => showToast(error.message, 'err')));
  $('#signoutBtn').addEventListener('click', () => signOut().catch((error) => showToast(error.message, 'err')));
  $('#loginForm').addEventListener('submit', (event) => submitLogin(event).catch((error) => showMessage('loginMessage', error.message)));
  $('#signupForm').addEventListener('submit', (event) => submitSignup(event).catch((error) => showMessage('signupMessage', error.message)));
  $('#recoveryMode').addEventListener('change', updateRecoveryMode);
  $('#forgotForm').addEventListener('submit', (event) => submitForgot(event).catch((error) => showMessage('forgotMessage', error.message)));
  $('#resetForm').addEventListener('submit', (event) => submitReset(event).catch((error) => showMessage('resetMessage', error.message)));
  $('#changePasswordForm').addEventListener('submit', (event) => submitChangePassword(event).catch((error) => showMessage('passwordMessage', error.message)));
  $('#globalSearch').addEventListener('input', (event) => { state.query = event.target.value.trim(); renderUsers(); renderApplications(); });
  $('#userSearch').addEventListener('input', renderUsers);
  $('#userStatusFilter').addEventListener('change', renderUsers);
  $('#authorizationAppSelect').addEventListener('change', (event) => { state.selectedClientId = event.target.value; loadAuthorization().catch((error) => showToast(error.message, 'err')); });
  $('#delegationSource').addEventListener('change', () => { populateDelegationApps(); loadDelegations().catch((error) => showToast(error.message, 'err')); });
  $('#delegationTarget').addEventListener('change', renderDelegationScopes);
  $('#appForm').addEventListener('submit', submitApp);
  $('#userForm').addEventListener('submit', submitUser);
  $('#permissionForm').addEventListener('submit', submitPermission);
  $('#roleForm').addEventListener('submit', submitRole);
  $('#delegationForm').addEventListener('submit', submitDelegation);
  $('#copyCredential').addEventListener('click', async () => { try { await navigator.clipboard.writeText($('#credentialValue').textContent); showToast('Secret copied to clipboard'); } catch { showToast('Copy failed; select the secret manually', 'err'); } });

  (async function init() {
    try {
      state.me = await IAM.me();
      if (!state.me) return showAuthScreen('login');
      await routeUser(state.me);
    } catch (error) {
      document.body.classList.remove('is-loading');
      showToast(error.message, 'err');
    }
  })();
})();
