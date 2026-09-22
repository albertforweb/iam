import { Router } from 'express';
import {
  SYSTEM_CLIENT_ID,
  listRoles,
  getRole,
  createRole,
  updateRole,
  deleteRole,
  countRoleUsers,
  countActiveAdmins,
  getUser,
  setUserRoles,
  isRoleNameTakenInClient,
  getAllUserGrants,
} from '../db.js';
import { requireAuth, requireRole } from '../middleware.js';

const router = Router();

const SYSTEM_ROLES = ['admin', 'member'];

const ROLE_NAME_RE = /^[a-zA-Z0-9_-]{1,50}$/;

function validateRoleName(name) {
  if (name === undefined || name === null || String(name).trim() !== name || !String(name).trim()) {
    return 'name cannot be empty or contain leading/trailing spaces';
  }
  if (!ROLE_NAME_RE.test(name)) return 'name must be 1-50 chars: letters, digits, "_", "-"';
  return null;
}

function validateRoles(roles) {
  if (!Array.isArray(roles)) {
    return 'roles must be an array of role names';
  }
  const valid = listRoles(SYSTEM_CLIENT_ID).map((r) => r.name);
  const bad = roles.filter((r) => !valid.includes(r));
  if (bad.length) return `invalid role name(s): ${bad.join(', ')}`;
  return null;
}

// GET /api/auth/roles (admin)
router.get('/roles', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ roles: listRoles(SYSTEM_CLIENT_ID) });
});

// POST /api/auth/roles (admin)
router.post('/roles', requireAuth, requireRole('admin'), (req, res) => {
  const { name, description } = req.body ?? {};

  const err = validateRoleName(name);
  if (err) return res.status(400).json({ error: err });

  if (description !== undefined && typeof description !== 'string') {
    return res.status(400).json({ error: 'description must be a string' });
  }

  if (isRoleNameTakenInClient(name, SYSTEM_CLIENT_ID)) {
    return res.status(409).json({ error: 'role name already exists' });
  }

  const role = createRole({ clientId: SYSTEM_CLIENT_ID, name: name.trim(), description });
  res.status(201).json({ role });
});

// PUT /api/auth/roles/:id (admin)
router.put('/roles/:id', requireAuth, requireRole('admin'), (req, res) => {
  const { name, description } = req.body ?? {};
  if (!getRole(req.params.id)) return res.status(404).json({ error: 'Role not found' });

  if (name !== undefined) {
    const err = validateRoleName(name);
    if (err) return res.status(400).json({ error: err });
    if (isRoleNameTakenInClient(name, SYSTEM_CLIENT_ID, req.params.id)) {
      return res.status(409).json({ error: 'role name already exists' });
    }
  }

  const role = updateRole(req.params.id, { name: name?.trim(), description });
  res.json({ role });
});

// DELETE /api/auth/roles/:id (admin)
router.delete('/roles/:id', requireAuth, requireRole('admin'), (req, res) => {
  const role = getRole(req.params.id);
  if (!role) return res.status(404).json({ error: 'Role not found' });

  if (SYSTEM_ROLES.includes(role.name)) {
    return res.status(400).json({ error: `Cannot delete system role "${role.name}"` });
  }

  if (countRoleUsers(role.id) > 0) {
    return res.status(409).json({ error: 'Role is assigned to users; reassign them first' });
  }

  deleteRole(req.params.id);
  res.status(204).end();
});

// GET /api/auth/users/:id/roles (admin)
router.get('/users/:id/roles', requireAuth, requireRole('admin'), (req, res) => {
  const user = getUser(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({ userId: user.id, username: user.username, roles: user.roles, grants: user.grants ?? getAllUserGrants(user.id) });
});

// PUT /api/auth/users/:id/roles (admin)
router.put('/users/:id/roles', requireAuth, requireRole('admin'), (req, res) => {
  const { roles } = req.body ?? {};
  const user = getUser(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const roleErr = validateRoles(roles);
  if (roleErr) return res.status(400).json({ error: roleErr });

  const isActiveAdmin = user.roles.includes('admin') && user.status === 'active';
  const keepsAdmin = roles.includes('admin');
  if (isActiveAdmin && !keepsAdmin && countActiveAdmins() <= 1) {
    return res.status(400).json({ error: 'Cannot remove the "admin" role from the last active administrator' });
  }

  const updated = setUserRoles(user.id, roles);
  res.json({ user: updated });
});

export default router;