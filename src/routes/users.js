import { Router } from 'express';
import {
  SYSTEM_CLIENT_ID,
  listUsers,
  getUser,
  getUserByUsername,
  verifyPassword,
  deleteSession,
  createUser,
  updateUser,
  deleteUser,
  isUsernameTaken,
  isEmailTaken,
  listRoles,
  countActiveAdmins,
  changePassword,
  createResetTokenForUsername,
  resetPasswordByToken,
  getUsernameByEmail,
  recordAuditEvent,
} from '../db.js';
import { requireAuth, requireRole, authUser, COOKIE_NAME, COOKIE_OPTIONS, rateLimit } from '../middleware.js';

const router = Router();

const ALLOWED_STATUSES = ['active', 'inactive', 'suspended'];
const loginLimit = rateLimit({ name: 'login', max: 10, windowMs: 60_000 });
const recoveryLimit = rateLimit({ name: 'recovery', max: 5, windowMs: 60_000 });

function missing(required, body) {
  const absent = required.filter((k) => body[k] === undefined || body[k] === null || body[k] === '');
  if (absent.length) return `Missing required field(s): ${absent.join(', ')}`;
  return null;
}

function validateRoles(roles) {
  if (roles === undefined) return null;
  if (!Array.isArray(roles)) {
    return 'roles must be an array of role names';
  }
  const valid = listRoles(SYSTEM_CLIENT_ID).map((r) => r.name);
  const bad = roles.filter((r) => !valid.includes(r));
  if (bad.length) return `invalid role name(s): ${bad.join(', ')}`;
  return null;
}

function lastAdminGuard(req, targetUser, newRoles) {
  if (!targetUser.roles.includes('admin') || targetUser.status !== 'active') return null;
  const keepsAdmin = newRoles.includes('admin');
  if (!keepsAdmin && countActiveAdmins() <= 1) {
    return 'Cannot remove the "admin" role from the last active administrator';
  }
  return null;
}

// GET /api/auth/users
router.get('/users', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ users: listUsers() });
});

// POST /api/auth/login
router.post('/login', loginLimit, (req, res) => {
  const { username, password } = req.body ?? {};

  const err = missing(['username', 'password'], req.body ?? {});
  if (err) return res.status(400).json({ error: err });

  const user = verifyPassword(username, password);
  if (!user) {
    const exists = getUserByUsername(username);
    const message = exists && exists.status !== 'active'
      ? `Account is ${exists.status}`
      : 'Invalid username or password';
    recordAuditEvent({ eventType: 'login_failed', success: false, metadata: { username: typeof username === 'string' ? username.slice(0, 128) : undefined } });
    return res.status(401).json({ error: message });
  }
  recordAuditEvent({ eventType: 'login_succeeded', userId: user.id });
  authUser(res, user);
});

// POST /api/auth/register (public)
router.post('/register', (req, res) => {
  const { username, displayName, email, password } = req.body ?? {};

  const err = missing(['username', 'displayName', 'password'], req.body ?? {});
  if (err) return res.status(400).json({ error: err });

  if (username.trim() !== username || !username.trim()) {
    return res.status(400).json({ error: 'username cannot be empty or contain leading/trailing spaces' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'password must be a string with at least 8 characters' });
  }
  if (email !== undefined && typeof email !== 'string') {
    return res.status(400).json({ error: 'email must be a string' });
  }

  if (isUsernameTaken(username)) {
    return res.status(409).json({ error: 'username already exists' });
  }
  if (email && isEmailTaken(email)) {
    return res.status(409).json({ error: 'email already exists' });
  }

  const user = createUser({
    username: username.trim(),
    displayName,
    email,
    status: 'active',
    password,
    roles: ['member'],
  });
  authUser(res, user);
});

const DEV_MODE = (process.env.IAM_DEV_MODE ?? (process.env.NODE_ENV !== 'production' ? 'true' : 'false')) === 'true';

// POST /api/auth/forgot-password (public)
router.post('/forgot-password', recoveryLimit, (req, res) => {
  const { username, email } = req.body ?? {};
  const hasUsername = typeof username === 'string' && username.trim();
  const hasEmail = typeof email === 'string' && email.trim();
  if (!hasUsername && !hasEmail) {
    return res.status(400).json({ error: 'Provide username or email' });
  }

  if (hasUsername) {
    const result = createResetTokenForUsername(username.trim());
    if (!result) return res.json({ ok: true, message: 'If the account exists, a reset token was generated.' });
    if (DEV_MODE) {
      console.log(`[forgot-password] Reset token for ${result.username}: ${result.token}`);
      return res.json({
        ok: true,
        username: result.username,
        resetToken: result.token,
        expiresAt: result.expiresAt,
        message: 'Reset token generated (dev mode).',
      });
    }
    return res.json({ ok: true, message: 'If the account exists, a reset link was sent.' });
  }

  const uname = getUsernameByEmail(email.trim());
  if (DEV_MODE) {
    return res.json({
      ok: true,
      username: uname ?? null,
      message: uname ? 'Username recovered (dev mode).' : 'No account found with that email (dev mode).',
    });
  }
  return res.json({ ok: true });
});

// POST /api/auth/reset-password (public)
router.post('/reset-password', recoveryLimit, (req, res) => {
  const { username, token, newPassword } = req.body ?? {};

  const err = missing(['username', 'token', 'newPassword'], req.body ?? {});
  if (err) return res.status(400).json({ error: err });

  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    return res.status(400).json({ error: 'new password must be a string with at least 8 characters' });
  }

  const result = resetPasswordByToken(token, username, newPassword);
  if (!result.ok) return res.status(400).json({ error: result.error });

  res.json({ ok: true });
});

// GET /api/auth/me
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// POST /api/auth/change-password
router.post('/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body ?? {};

  const err = missing(['currentPassword', 'newPassword'], req.body ?? {});
  if (err) return res.status(400).json({ error: err });

  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    return res.status(400).json({ error: 'new password must be a string with at least 8 characters' });
  }

  const result = changePassword(req.user.id, currentPassword, newPassword);
  if (!result.ok) return res.status(400).json({ error: result.error });

  res.json({ ok: true });
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
  const token = req.cookies?.[COOKIE_NAME];
  if (token) deleteSession(token);
  res.clearCookie(COOKIE_NAME, COOKIE_OPTIONS);
  res.status(204).end();
});

// GET /api/auth/users/:id
router.get('/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const user = getUser(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

// POST /api/auth/users
router.post('/users', requireAuth, requireRole('admin'), (req, res) => {
  const { username, displayName, email, status, password, roles } = req.body ?? {};

  const err = missing(['username', 'displayName'], req.body ?? {});
  if (err) return res.status(400).json({ error: err });

  if (status !== undefined && !ALLOWED_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${ALLOWED_STATUSES.join(', ')}` });
  }

  if (username.trim() !== username || !username.trim()) {
    return res.status(400).json({ error: 'username cannot be empty or contain leading/trailing spaces' });
  }

  if (password !== undefined && (typeof password !== 'string' || password.length < 8)) {
    return res.status(400).json({ error: 'password must be a string with at least 8 characters' });
  }

  if (email !== undefined && typeof email !== 'string') {
    return res.status(400).json({ error: 'email must be a string' });
  }

  const roleErr = validateRoles(roles);
  if (roleErr) return res.status(400).json({ error: roleErr });

  if (isUsernameTaken(username)) {
    return res.status(409).json({ error: 'username already exists' });
  }
  if (email && isEmailTaken(email)) {
    return res.status(409).json({ error: 'email already exists' });
  }

  const user = createUser({ username: username.trim(), displayName, email, status, password, roles });
  res.status(201).json({ user });
});

// PUT /api/auth/users/:id
router.put('/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const { displayName, email, status, password, roles } = req.body ?? {};
  const target = getUser(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });

  if (status !== undefined && !ALLOWED_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${ALLOWED_STATUSES.join(', ')}` });
  }

  if (email && isEmailTaken(email, req.params.id)) {
    return res.status(409).json({ error: 'email already exists' });
  }

  const roleErr = validateRoles(roles);
  if (roleErr) return res.status(400).json({ error: roleErr });

  if (roles) {
    const guardErr = lastAdminGuard(req, target, roles);
    if (guardErr) return res.status(400).json({ error: guardErr });
  }

  const user = updateUser(req.params.id, { displayName, email, status, password, roles });
  res.json({ user });
});

// DELETE /api/auth/users/:id
router.delete('/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const target = getUser(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });

  const guardErr = lastAdminGuard(req, target, []);
  if (guardErr) return res.status(400).json({ error: guardErr });

  const removed = deleteUser(req.params.id);
  if (!removed) return res.status(404).json({ error: 'User not found' });
  res.status(204).end();
});

export default router;
