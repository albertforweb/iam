import { Router } from 'express';
import crypto from 'node:crypto';
import {
  listClients,
  getClientById,
  getClientByPublicId,
  createClient,
  updateClient,
  rotateClientSecret,
  deleteClient,
  listRoles,
  getRole,
  createRole,
  updateRole,
  deleteRole,
  countRoleUsers,
  isRoleNameTakenInClient,
  listPermissions,
  getPermission,
  createPermission,
  updatePermission,
  deletePermission,
  countPermissionUsage,
  isPermissionNameTakenInClient,
  getRolePermissions,
  setRolePermissions,
  getUser,
  getUserRolesForClient,
  userPermissionsForClient,
  setUserRolesForClient,
  listDelegationPolicies,
  getDelegationPolicy,
  createDelegationPolicy,
  deleteDelegationPolicy,
  getAuthorizationManifest,
  reconcileAuthorizationManifest,
  recordAuditEvent,
} from '../db.js';
import { requireAdmin, requireAdminOrClient } from '../middleware.js';

const router = Router();

const CLIENT_ID_RE = /^[a-zA-Z0-9._-]{1,64}$/;
const ROLE_NAME_RE = /^[a-zA-Z0-9_-]{1,50}$/;
const PERM_NAME_RE = /^[a-zA-Z0-9_:.-]{1,80}$/;
const CLIENT_TYPES = ['public', 'confidential', 'service'];
const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const GRANT_TYPES = ['authorization_code', 'refresh_token', 'client_credentials', TOKEN_EXCHANGE_GRANT];
const CONTEXT_TYPES = ['global', 'tenant', 'organization', 'project', 'resource'];

function validateClientId(clientId) {
  if (typeof clientId !== 'string' || clientId.trim() !== clientId || !clientId.trim()) {
    return 'client_id cannot be empty or contain leading/trailing spaces';
  }
  if (!CLIENT_ID_RE.test(clientId)) return 'client_id must be 1-64 chars: letters, digits, "_", "-", "."';
  return null;
}

function validateNameLike(name, re, kind) {
  if (typeof name !== 'string' || name.trim() !== name || !name.trim()) {
    return `${kind} cannot be empty or contain leading/trailing spaces`;
  }
  if (!re.test(name)) return `${kind} has invalid characters`;
  return null;
}

function validateRedirectUris(uris) {
  if (uris === undefined) return null;
  if (!Array.isArray(uris)) return 'redirect_uris must be an array of urls';
  for (const u of uris) {
    try {
      if (!['http:', 'https:'].includes(new URL(u).protocol)) return `invalid redirect_uri: ${u}`;
    } catch {
      return `invalid redirect_uri: ${u}`;
    }
  }
  return null;
}

/**
 * Resolve which client a route operates on. Priority:
 *   1. req.params.clientId (public identifier)
 *   2. req.authClient.id (authenticated application)
 * If the caller is a client application, it may only operate on itself.
 */
function resolveClient(req, res, next) {
  const publicId = req.params.clientId ?? req.authClient?.client_id;
  if (!publicId) return res.status(400).json({ error: 'client_id is required' });
  const client = getClientByPublicId(publicId);
  if (!client) return res.status(404).json({ error: 'Client not found' });
  if (req.authClient && req.authClient.id !== client.id) {
    return res.status(403).json({ error: 'Clients may only manage their own configuration' });
  }
  req.contextClient = client;
  next();
}

function resolveUserForAssignments(req, res, next) {
  const user = getUser(req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  req.targetUser = user;
  next();
}

function resolveAssignmentContext(req, res, body = {}) {
  const contextType = body.contextType ?? req.query.contextType ?? 'global';
  const contextId = body.contextId ?? req.query.contextId ?? null;
  if (!CONTEXT_TYPES.includes(contextType)) {
    res.status(400).json({ error: `contextType must be one of: ${CONTEXT_TYPES.join(', ')}` });
    return null;
  }
  if (contextType === 'global' && contextId !== null) {
    res.status(400).json({ error: 'global assignments cannot have a contextId' });
    return null;
  }
  if (contextType !== 'global' && (typeof contextId !== 'string' || !contextId.trim())) {
    res.status(400).json({ error: 'contextId is required for non-global assignments' });
    return null;
  }
  return { contextType, contextId };
}

function delegationDto(policy) {
  const source = getClientById(policy.source_client_id);
  const target = getClientById(policy.target_client_id);
  return {
    id: policy.id,
    sourceClientId: source?.client_id,
    targetClientId: target?.client_id,
    allowedScopes: policy.allowed_scopes,
    enabled: policy.enabled,
    createdAt: policy.created_at,
    updatedAt: policy.updated_at,
  };
}

function validateAuthorizationManifest(body) {
  const version = body?.version;
  if (typeof version !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(version)) {
    return { error: 'version must be 1-64 characters using letters, digits, ".", "_", or "-"' };
  }
  if (!Array.isArray(body?.permissions) || body.permissions.length > 500) {
    return { error: 'permissions must be an array with at most 500 entries' };
  }
  if (!Array.isArray(body?.roles) || body.roles.length > 200) {
    return { error: 'roles must be an array with at most 200 entries' };
  }

  const permissionNames = new Map();
  const permissions = [];
  for (const permission of body.permissions) {
    const nameError = validateNameLike(permission?.name, PERM_NAME_RE, 'permission name');
    if (nameError) return { error: nameError };
    const name = permission.name.trim();
    const normalizedName = name.toLowerCase();
    if (permissionNames.has(normalizedName)) return { error: `duplicate permission name: ${name}` };
    if (permission.description !== undefined && (typeof permission.description !== 'string' || permission.description.length > 500)) {
      return { error: `permission description is invalid: ${name}` };
    }
    permissionNames.set(normalizedName, name);
    permissions.push({ name, description: permission.description?.trim() ?? null });
  }

  const roleNames = new Set();
  const roles = [];
  for (const role of body.roles) {
    const nameError = validateNameLike(role?.name, ROLE_NAME_RE, 'role name');
    if (nameError) return { error: nameError };
    const name = role.name.trim();
    if (roleNames.has(name.toLowerCase())) return { error: `duplicate role name: ${name}` };
    if (role.description !== undefined && (typeof role.description !== 'string' || role.description.length > 500)) {
      return { error: `role description is invalid: ${name}` };
    }
    if (!Array.isArray(role.permissions) || role.permissions.length > 500) {
      return { error: `permissions must be an array for role: ${name}` };
    }
    const rolePermissions = [...new Set(role.permissions)];
    if (rolePermissions.some((permissionName) => typeof permissionName !== 'string' || !permissionNames.has(permissionName.toLowerCase()))) {
      return { error: `role ${name} references an undeclared permission` };
    }
    const canonicalPermissions = rolePermissions.map((permissionName) => permissionNames.get(permissionName.toLowerCase()));
    roleNames.add(name.toLowerCase());
    roles.push({ name, description: role.description?.trim() ?? null, permissions: canonicalPermissions });
  }

  return { value: { version, permissions, roles } };
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

// GET /api/auth/clients (Iam admin only)
router.get('/clients', (req, res, next) => {
  if (req.authClient) {
    return res.json({ clients: [req.authClient] });
  }
  next();
}, requireAdminOrClient, (req, res) => {
  res.json({ clients: listClients() });
});

// POST /api/auth/clients (Iam admin) — registers an application
router.post('/clients', requireAdmin, (req, res) => {
  const { clientId, name, description, secret, redirectUris } = req.body ?? {};
  const clientType = req.body?.clientType ?? 'confidential';
  const defaultGrants = clientType === 'service' ? ['client_credentials'] : ['authorization_code', 'refresh_token'];
  const grantTypes = req.body?.grantTypes ?? defaultGrants;
  const allowedScopes = req.body?.allowedScopes ?? [];

  const err = validateClientId(clientId);
  if (err) return res.status(400).json({ error: err });
  if (typeof name !== 'string' || name.trim() !== name || !name.trim() || name.length > 100) {
    return res.status(400).json({ error: 'name cannot be empty, exceed 100 chars, or have leading/trailing spaces' });
  }

  if (getClientByPublicId(clientId)) return res.status(409).json({ error: 'client_id already exists' });
  if (secret !== undefined && (typeof secret !== 'string' || secret.length < 8)) {
    return res.status(400).json({ error: 'secret must be a string with at least 8 characters' });
  }
  const uriErr = validateRedirectUris(redirectUris);
  if (uriErr) return res.status(400).json({ error: uriErr });
  if (!CLIENT_TYPES.includes(clientType)) {
    return res.status(400).json({ error: `clientType must be one of: ${CLIENT_TYPES.join(', ')}` });
  }
  if (!Array.isArray(grantTypes) || grantTypes.some((grant) => !GRANT_TYPES.includes(grant))) {
    return res.status(400).json({ error: `grantTypes must contain only: ${GRANT_TYPES.join(', ')}` });
  }
  if (!Array.isArray(allowedScopes) || allowedScopes.some((scope) => typeof scope !== 'string' || !PERM_NAME_RE.test(scope))) {
    return res.status(400).json({ error: 'allowedScopes must be an array of valid permission names' });
  }
  if (clientType === 'public' && secret !== undefined) {
    return res.status(400).json({ error: 'public clients must not have a client secret' });
  }
  if (clientType === 'public' && grantTypes.includes(TOKEN_EXCHANGE_GRANT)) {
    return res.status(400).json({ error: 'public clients cannot use token exchange' });
  }
  if (clientType === 'service' && !grantTypes.includes('client_credentials')) {
    return res.status(400).json({ error: 'service clients must allow client_credentials' });
  }

  const clientSecret = clientType === 'public' ? null : (secret ?? cryptoSecret());
  const client = createClient({ clientId, name, description, secret: clientSecret, redirectUris, clientType, grantTypes, allowedScopes });
  recordAuditEvent({ eventType: 'client_created', clientId: client.id, metadata: { client_id: client.client_id, client_type: clientType } });
  res.status(201).json({ client, ...(clientSecret ? { secret: clientSecret } : {}) });
});

// GET /api/auth/clients/:clientId
router.get('/clients/:clientId', requireAdminOrClient, resolveClient, (req, res) => {
  res.json({ client: req.contextClient });
});

// PUT /api/auth/clients/:clientId (Iam admin or the client itself)
router.put('/clients/:clientId', requireAdminOrClient, resolveClient, (req, res) => {
  const { name, description, redirectUris, clientId, enabled, clientType, grantTypes, allowedScopes } = req.body ?? {};
  const err = validateRedirectUris(redirectUris);
  if (err) return res.status(400).json({ error: err });
  if (clientId !== undefined) {
    const cidErr = validateClientId(clientId);
    if (cidErr) return res.status(400).json({ error: cidErr });
  }
  if (enabled !== undefined && typeof enabled !== 'boolean') {
    return res.status(400).json({ error: 'enabled must be a boolean' });
  }
  if (clientType !== undefined && !CLIENT_TYPES.includes(clientType)) {
    return res.status(400).json({ error: `clientType must be one of: ${CLIENT_TYPES.join(', ')}` });
  }
  const nextGrantTypes = grantTypes ?? req.contextClient.grant_types;
  if (grantTypes !== undefined && (!Array.isArray(grantTypes) || grantTypes.some((grant) => !GRANT_TYPES.includes(grant)))) {
    return res.status(400).json({ error: `grantTypes must contain only: ${GRANT_TYPES.join(', ')}` });
  }
  if (allowedScopes !== undefined && (!Array.isArray(allowedScopes) || allowedScopes.some((scope) => typeof scope !== 'string' || !PERM_NAME_RE.test(scope)))) {
    return res.status(400).json({ error: 'allowedScopes must be an array of valid permission names' });
  }
  if (req.authClient && allowedScopes !== undefined) {
    const ownPermissions = new Set(listPermissions(req.contextClient.id).map((permission) => permission.name));
    const invalid = allowedScopes.filter((scope) => !ownPermissions.has(scope));
    if (invalid.length) return res.status(400).json({ error: `allowedScopes must reference this client's permissions: ${invalid.join(', ')}` });
  }
  if (clientType === 'public' && req.contextClient.has_secret) {
    return res.status(400).json({ error: 'rotate the client to a public registration without a secret' });
  }
  if ((clientType ?? req.contextClient.client_type) === 'public' && nextGrantTypes.includes(TOKEN_EXCHANGE_GRANT)) {
    return res.status(400).json({ error: 'public clients cannot use token exchange' });
  }

  const result = updateClient(req.contextClient.id, {
    name: name === undefined ? undefined : name.trim(),
    description,
    redirectUris,
    clientId,
    clientType,
    grantTypes,
    allowedScopes,
    enabled,
  });
  if (result?.error) return res.status(400).json({ error: result.error });
  recordAuditEvent({ eventType: 'client_updated', clientId: req.contextClient.id, metadata: { client_id: result.client_id } });
  res.json({ client: result });
});

// POST /api/auth/clients/:clientId/rotate-secret
router.post('/clients/:clientId/rotate-secret', requireAdminOrClient, resolveClient, (req, res) => {
  if (req.contextClient.is_system) {
    return res.status(400).json({ error: 'The system client has no secret' });
  }
  if (req.contextClient.client_type === 'public') {
    return res.status(400).json({ error: 'Public clients do not use client secrets' });
  }
  const { secret } = rotateClientSecret(req.contextClient.id);
  res.json({ secret });
});

// DELETE /api/auth/clients/:clientId (Iam admin only)
router.delete('/clients/:clientId', (req, res, next) => {
  if (req.authClient) return res.status(403).json({ error: 'Only IAM administrators can delete clients' });
  next();
}, requireAdminOrClient, resolveClient, (req, res) => {
  const result = deleteClient(req.contextClient.id);
  if (result.error) return res.status(400).json({ error: result.error });
  recordAuditEvent({ eventType: 'client_deleted', clientId: req.contextClient.id });
  res.status(204).end();
});

// ---------------------------------------------------------------------------
// Delegated application access
// ---------------------------------------------------------------------------

// Delegation policies are platform security configuration. Applications cannot
// grant themselves permission to mint tokens for another application's API.
router.get('/clients/:clientId/delegations', requireAdmin, resolveClient, (req, res) => {
  res.json({ policies: listDelegationPolicies(req.contextClient.id).map(delegationDto) });
});

router.post('/clients/:clientId/delegations', requireAdmin, resolveClient, (req, res) => {
  const { targetClientId, allowedScopes } = req.body ?? {};
  if (typeof targetClientId !== 'string' || !targetClientId.trim()) {
    return res.status(400).json({ error: 'targetClientId is required' });
  }
  if (!Array.isArray(allowedScopes) || allowedScopes.length === 0 || allowedScopes.some((scope) => typeof scope !== 'string' || !PERM_NAME_RE.test(scope))) {
    return res.status(400).json({ error: 'allowedScopes must be a non-empty array of valid permission names' });
  }
  const target = getClientByPublicId(targetClientId);
  if (!target || !target.enabled) return res.status(404).json({ error: 'Target client not found' });
  const targetPermissions = new Set(listPermissions(target.id).map((permission) => permission.name));
  const invalid = [...new Set(allowedScopes)].filter((scope) => !targetPermissions.has(scope));
  if (invalid.length) return res.status(400).json({ error: `allowedScopes must reference target permissions: ${invalid.join(', ')}` });

  const policy = createDelegationPolicy({
    sourceClientId: req.contextClient.id,
    targetClientId: target.id,
    allowedScopes,
  });
  if (policy?.error) return res.status(409).json({ error: policy.error });
  recordAuditEvent({
    eventType: 'delegation_policy_created',
    clientId: req.contextClient.id,
    metadata: { target_client_id: target.client_id, allowed_scopes: policy.allowed_scopes },
  });
  return res.status(201).json({ policy: delegationDto(policy) });
});

router.delete('/clients/:clientId/delegations/:targetClientId', requireAdmin, resolveClient, (req, res) => {
  const target = getClientByPublicId(req.params.targetClientId);
  if (!target) return res.status(404).json({ error: 'Target client not found' });
  const policy = getDelegationPolicy(req.contextClient.id, target.id);
  if (!policy) return res.status(404).json({ error: 'Delegation policy not found' });
  deleteDelegationPolicy(policy.id);
  recordAuditEvent({
    eventType: 'delegation_policy_deleted',
    clientId: req.contextClient.id,
    metadata: { target_client_id: target.client_id },
  });
  return res.status(204).end();
});

// ---------------------------------------------------------------------------
// Application-owned authorization manifests
// ---------------------------------------------------------------------------

// Applications reconcile their own role/permission definitions through this
// endpoint. IAM stores the definitions and assignments, but does not invent
// their meaning. Removal is intentionally not destructive; see db.js.
router.get('/clients/:clientId/authorization-manifest', requireAdminOrClient, resolveClient, (req, res) => {
  const manifest = getAuthorizationManifest(req.contextClient.id);
  if (!manifest) return res.status(404).json({ error: 'Authorization manifest not registered' });
  res.json({ clientId: req.contextClient.client_id, manifest });
});

router.put('/clients/:clientId/authorization-manifest', requireAdminOrClient, resolveClient, (req, res) => {
  const result = validateAuthorizationManifest(req.body);
  if (result.error) return res.status(400).json({ error: result.error });

  try {
    const manifest = reconcileAuthorizationManifest({ clientId: req.contextClient.id, ...result.value });
    if (manifest?.error) return res.status(404).json({ error: manifest.error });
    recordAuditEvent({
      eventType: 'authorization_manifest_reconciled',
      clientId: req.contextClient.id,
      metadata: { version: result.value.version, checksum: manifest.checksum },
    });
    return res.json({ clientId: req.contextClient.client_id, manifest });
  } catch (error) {
    console.error('[authorization-manifest] reconciliation failed', error);
    return res.status(500).json({ error: 'Authorization manifest reconciliation failed' });
  }
});

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

// GET /api/auth/clients/:clientId/permissions
router.get('/clients/:clientId/permissions', requireAdminOrClient, resolveClient, (req, res) => {
  res.json({ permissions: listPermissions(req.contextClient.id) });
});

// POST /api/auth/clients/:clientId/permissions
router.post('/clients/:clientId/permissions', requireAdminOrClient, resolveClient, (req, res) => {
  const { name, description } = req.body ?? {};
  const err = validateNameLike(name, PERM_NAME_RE, 'permission name');
  if (err) return res.status(400).json({ error: err });

  if (isPermissionNameTakenInClient(name, req.contextClient.id)) {
    return res.status(409).json({ error: 'permission name already exists for this client' });
  }
  const permission = createPermission({ clientId: req.contextClient.id, name: name.trim(), description });
  recordAuditEvent({ eventType: 'permission_created', clientId: req.contextClient.id, metadata: { permission_id: permission.id } });
  res.status(201).json({ permission });
});

// PUT /api/auth/clients/:clientId/permissions/:permId
router.put('/clients/:clientId/permissions/:permId', requireAdminOrClient, resolveClient, (req, res) => {
  const target = getPermission(req.params.permId);
  if (!target) return res.status(404).json({ error: 'Permission not found' });
  if (target.client_id !== req.contextClient.id) return res.status(404).json({ error: 'Permission not found for this client' });
  const { name, description } = req.body ?? {};
  if (name !== undefined) {
    const err = validateNameLike(name, PERM_NAME_RE, 'permission name');
    if (err) return res.status(400).json({ error: err });
    if (isPermissionNameTakenInClient(name, req.contextClient.id, req.params.permId)) {
      return res.status(409).json({ error: 'permission name already exists for this client' });
    }
  }
  const permission = updatePermission(req.params.permId, { name: name?.trim(), description });
  recordAuditEvent({ eventType: 'permission_updated', clientId: req.contextClient.id, metadata: { permission_id: permission.id } });
  res.json({ permission });
});

// DELETE /api/auth/clients/:clientId/permissions/:permId
router.delete('/clients/:clientId/permissions/:permId', requireAdminOrClient, resolveClient, (req, res) => {
  const target = getPermission(req.params.permId);
  if (!target) return res.status(404).json({ error: 'Permission not found' });
  if (target.client_id !== req.contextClient.id) return res.status(404).json({ error: 'Permission not found for this client' });
  if (countPermissionUsage(req.params.permId) > 0) {
    return res.status(409).json({ error: 'Permission is in use by one or more roles; remove it from those roles first' });
  }
  deletePermission(req.params.permId);
  recordAuditEvent({ eventType: 'permission_deleted', clientId: req.contextClient.id, metadata: { permission_id: req.params.permId } });
  res.status(204).end();
});

// ---------------------------------------------------------------------------
// Roles (client-scoped)
// ---------------------------------------------------------------------------

// GET /api/auth/clients/:clientId/roles
router.get('/clients/:clientId/roles', requireAdminOrClient, resolveClient, (req, res) => {
  res.json({ roles: listRoles(req.contextClient.id) });
});

// POST /api/auth/clients/:clientId/roles
router.post('/clients/:clientId/roles', requireAdminOrClient, resolveClient, (req, res) => {
  const { name, description } = req.body ?? {};
  const err = validateNameLike(name, ROLE_NAME_RE, 'role name');
  if (err) return res.status(400).json({ error: err });

  if (isRoleNameTakenInClient(name, req.contextClient.id)) {
    return res.status(409).json({ error: 'role name already exists for this client' });
  }
  const role = createRole({ clientId: req.contextClient.id, name: name.trim(), description });
  recordAuditEvent({ eventType: 'role_created', clientId: req.contextClient.id, metadata: { role_id: role.id } });
  res.status(201).json({ role });
});

// GET /api/auth/clients/:clientId/roles/:roleId
router.get('/clients/:clientId/roles/:roleId', requireAdminOrClient, resolveClient, (req, res) => {
  const role = getRole(req.params.roleId);
  if (!role) return res.status(404).json({ error: 'Role not found' });
  if (role.client_id !== req.contextClient.id) return res.status(404).json({ error: 'Role not found for this client' });
  res.json({ role, permissions: getRolePermissions(role.id) });
});

// PUT /api/auth/clients/:clientId/roles/:roleId
router.put('/clients/:clientId/roles/:roleId', requireAdminOrClient, resolveClient, (req, res) => {
  const role = getRole(req.params.roleId);
  if (!role) return res.status(404).json({ error: 'Role not found' });
  if (role.client_id !== req.contextClient.id) {
    return res.status(404).json({ error: 'Role not found for this client' });
  }

  const { name, description, permissions } = req.body ?? {};
  if (name !== undefined) {
    const err = validateNameLike(name, ROLE_NAME_RE, 'role name');
    if (err) return res.status(400).json({ error: err });
    if (isRoleNameTakenInClient(name, req.contextClient.id, req.params.roleId)) {
      return res.status(409).json({ error: 'role name already exists for this client' });
    }
  }
  if (permissions !== undefined) {
    if (!Array.isArray(permissions)) return res.status(400).json({ error: 'permissions must be an array of permission IDs' });
    const own = new Set(listPermissions(req.contextClient.id).map((p) => p.id));
    const bad = permissions.filter((p) => !own.has(p));
    if (bad.length) return res.status(400).json({ error: `permission(s) not found in this client: ${bad.join(', ')}` });
  }

  const updated = updateRole(req.params.roleId, {
    name: name === undefined ? undefined : name.trim(),
    description,
    permissionIds: permissions,
  });
  recordAuditEvent({ eventType: 'role_updated', clientId: req.contextClient.id, metadata: { role_id: updated.id } });
  res.json({ role: updated, permissions: getRolePermissions(updated.id) });
});

// DELETE /api/auth/clients/:clientId/roles/:roleId
router.delete('/clients/:clientId/roles/:roleId', requireAdminOrClient, resolveClient, (req, res) => {
  const role = getRole(req.params.roleId);
  if (!role) return res.status(404).json({ error: 'Role not found' });
  if (role.client_id !== req.contextClient.id) return res.status(404).json({ error: 'Role not found for this client' });
  if (countRoleUsers(role.id) > 0) {
    return res.status(409).json({ error: 'Role is assigned to users; reassign them first' });
  }
  if (role.client_id === 'sys_iam') {
    const system = ['admin', 'member'];
    if (system.includes(role.name)) {
      return res.status(400).json({ error: `Cannot delete system role "${role.name}"` });
    }
  }
  deleteRole(role.id);
  recordAuditEvent({ eventType: 'role_deleted', clientId: req.contextClient.id, metadata: { role_id: role.id } });
  res.status(204).end();
});

// ---------------------------------------------------------------------------
// Assignments (user <-> client role)
// ---------------------------------------------------------------------------

// GET /api/auth/clients/:clientId/users/:userId/roles
router.get('/clients/:clientId/users/:userId/roles', requireAdminOrClient, resolveClient, resolveUserForAssignments, (req, res) => {
  const context = resolveAssignmentContext(req, res);
  if (!context) return;
  res.json({
    userId: req.targetUser.id,
    username: req.targetUser.username,
    clientId: req.contextClient.client_id,
    context,
    roles: getUserRolesForClient(req.targetUser.id, req.contextClient.id, context),
    permissions: userPermissionsForClient(req.targetUser.id, req.contextClient.id, context),
  });
});

// PUT /api/auth/clients/:clientId/users/:userId/roles
router.put('/clients/:clientId/users/:userId/roles', requireAdminOrClient, resolveClient, resolveUserForAssignments, (req, res) => {
  const { roles } = req.body ?? {};
  if (!Array.isArray(roles)) return res.status(400).json({ error: 'roles must be an array of role names' });
  const context = resolveAssignmentContext(req, res, req.body);
  if (!context) return;

  const valid = new Set(listRoles(req.contextClient.id).map((r) => r.name));
  const bad = roles.filter((r) => !valid.has(r));
  if (bad.length) return res.status(400).json({ error: `invalid role name(s) for client: ${bad.join(', ')}` });

  setUserRolesForClient(req.targetUser.id, req.contextClient.id, roles, context);
  recordAuditEvent({ eventType: 'role_assignment_replaced', userId: req.targetUser.id, clientId: req.contextClient.id, metadata: { context, roles } });
  res.json({ user: getUser(req.targetUser.id, { clientId: req.contextClient.id, ...context }), context });
});

function cryptoSecret() {
  return crypto.randomBytes(24).toString('base64url');
}

export default router;
