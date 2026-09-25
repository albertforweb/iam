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
  createResetTokenForEmail,
  deleteResetToken,
  resetPasswordByToken,
  getUsernameByEmail,
  recordAuditEvent,
  getClientById,
  getClientByPublicId,
  getUserRolesForClient,
} from '../db.js';
import { requireAuth, requireRole, authUser, COOKIE_NAME, COOKIE_OPTIONS, rateLimit } from '../middleware.js';
import { isMailConfigured, sendPasswordResetEmail } from '../mailer.js';

const router = Router();

const ALLOWED_STATUSES = ['active', 'inactive', 'suspended'];
const loginLimit = rateLimit({ name: 'login', max: 10, windowMs: 60_000 });
const recoveryLimit = rateLimit({ name: 'recovery', max: 5, windowMs: 60_000 });

function normalizeRecoveryReturnTo(value) {
  if (typeof value !== 'string' || !value || value.length > 4096 || value.includes('\\')) return '';
  if (!value.startsWith('/') || value.startsWith('//')) return '';
  try {
    const parsed = new URL(value, 'http://iam.local');
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return '';
  }
}

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
router.get('/users', requireAuth, (req, res) => {
  const requestedClientId = typeof req.query.client_id === 'string' ? req.query.client_id : SYSTEM_CLIENT_ID;
  const client = requestedClientId === SYSTEM_CLIENT_ID
    ? getClientById(SYSTEM_CLIENT_ID)
    : getClientByPublicId(requestedClientId);
  if (!client) return res.status(404).json({ error: 'Client not found' });
  const isSystemAdmin = getUserRolesForClient(req.user.id, SYSTEM_CLIENT_ID).includes('admin');
  const isApplicationAdmin = getUserRolesForClient(req.user.id, client.id).includes('admin');
  if (!isSystemAdmin && !isApplicationAdmin) return res.status(403).json({ error: 'Forbidden: insufficient role' });
  res.json({ users: listUsers(client.id) });
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

  const err = missing(['username', 'displayName', 'email', 'password'], req.body ?? {});
  if (err) return res.status(400).json({ error: err });

  if (username.trim() !== username || !username.trim()) {
    return res.status(400).json({ error: 'username cannot be empty or contain leading/trailing spaces' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'password must be a string with at least 8 characters' });
  }
  if (typeof email !== 'string' || !email.trim()) {
    return res.status(400).json({ error: 'email is required' });
  }

  if (isUsernameTaken(username)) {
    return res.status(409).json({ error: 'username already exists' });
  }
  if (isEmailTaken(email)) {
    return res.status(409).json({ error: 'email already exists' });
  }

  const user = createUser({
    username: username.trim(),
    displayName,
    email: email.trim(),
    status: 'active',
    password,
    roles: ['member'],
  });
  authUser(res, user);
});

const DEV_MODE = (process.env.IAM_DEV_MODE ?? (process.env.NODE_ENV !== 'production' ? 'true' : 'false')) === 'true';

// POST /api/auth/forgot-password (public)
router.post('/forgot-password', recoveryLimit, async (req, res) => {
  const { username, email, returnTo } = req.body ?? {};
  const recoveryReturnTo = normalizeRecoveryReturnTo(returnTo);
  const hasUsername = typeof username === 'string' && username.trim();
  const hasEmail = typeof email === 'string' && email.trim();
  if (!hasUsername && !hasEmail) {
    return res.status(400).json({ error: 'Provide username or email' });
  }

  if (hasUsername) {
    if (!DEV_MODE && !isMailConfigured()) {
      return res.status(503).json({
        error: 'Password recovery delivery is not configured. Contact an IAM administrator.',
      });
    }
    const result = createResetTokenForUsername(username.trim(), { allowWithoutEmail: DEV_MODE });
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
    return deliverResetEmail(result, res, recoveryReturnTo);
  }

  if (!DEV_MODE && !isMailConfigured()) {
    return res.status(503).json({
      error: 'Password recovery delivery is not configured. Contact an IAM administrator.',
    });
  }
  if (DEV_MODE) {
    const uname = getUsernameByEmail(email.trim());
    return res.json({
      ok: true,
      username: uname ?? null,
      message: uname ? 'Username recovered (dev mode).' : 'No account found with that email (dev mode).',
    });
  }
  const result = createResetTokenForEmail(email.trim());
  if (result) return deliverResetEmail(result, res, recoveryReturnTo);
  return res.json({ ok: true, message: 'If the account exists, a reset link was sent.' });
});

async function deliverResetEmail(result, res, returnTo = '') {
  const publicBaseUrl = (process.env.IAM_PUBLIC_BASE_URL ?? 'http://localhost:3000').replace(/\/+$/, '');
  const resetUrl = new URL(`${publicBaseUrl}/login`);
  resetUrl.searchParams.set('username', result.username);
  resetUrl.searchParams.set('token', result.token);
  if (returnTo) resetUrl.searchParams.set('next', returnTo);
  try {
    await sendPasswordResetEmail({ ...result, to: result.email, resetUrl: resetUrl.toString() });
    return res.json({ ok: true, message: 'If the account exists, a reset link was sent.' });
  } catch (error) {
    deleteResetToken(result.token);
    console.error(`[forgot-password] Failed to deliver reset email: ${error.message}`);
    return res.status(503).json({ error: 'Password recovery delivery is temporarily unavailable.' });
  }
}

// POST /api/auth/reset-password (public)
router.post('/reset-password', recoveryLimit, (req, res) => {
  if (!DEV_MODE && !isMailConfigured()) {
    return res.status(503).json({
      error: 'Password recovery delivery is not configured. Contact an IAM administrator.',
    });
  }
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

  const err = missing(['username', 'displayName', 'email'], req.body ?? {});
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

  if (typeof email !== 'string' || !email.trim()) {
    return res.status(400).json({ error: 'email is required' });
  }

  const roleErr = validateRoles(roles);
  if (roleErr) return res.status(400).json({ error: roleErr });

  if (isUsernameTaken(username)) {
    return res.status(409).json({ error: 'username already exists' });
  }
  if (isEmailTaken(email)) {
    return res.status(409).json({ error: 'email already exists' });
  }

  const user = createUser({ username: username.trim(), displayName, email: email.trim(), status, password, roles });
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
