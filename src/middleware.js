import { createSession, getSession, getOauthToken, getUser, getClientById, SYSTEM_CLIENT_ID, verifyClientSecret, getUserRolesForClient, getClientByPublicId } from './db.js';
import { incrementMetric } from './observability.js';

export const COOKIE_NAME = 'auth_token';

export const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.IAM_COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
  path: '/',
};

const buckets = new Map();

export function rateLimit({ name, max = 60, windowMs = 60_000, key = (req) => req.ip }) {
  return (req, res, next) => {
    const now = Date.now();
    const bucketKey = `${name}:${key(req)}`;
    const current = buckets.get(bucketKey);
    if (!current || current.expiresAt <= now) {
      buckets.set(bucketKey, { count: 1, expiresAt: now + windowMs });
      return next();
    }
    current.count += 1;
    if (current.count > max) {
      incrementMetric('rate_limit_rejections_total');
      res.set('Retry-After', Math.ceil((current.expiresAt - now) / 1000));
      return res.status(429).json({ error: 'rate_limited' });
    }
    next();
  };
}

export function authUser(res, user) {
  const { token, expiresAt } = createSession(user.id);
  res.cookie(COOKIE_NAME, token, {
    ...COOKIE_OPTIONS,
    maxAge: new Date(expiresAt).getTime() - Date.now(),
  });
  res.json({ user });
}

export function requireAuth(req, res, next) {
  const bearer = req.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  const oauth = bearer ? getOauthToken(bearer) : null;
  const bearerUser = oauth?.kind === 'access' && oauth.user_id ? getUser(oauth.user_id) : null;
  const cookieToken = req.cookies?.[COOKIE_NAME];
  const cookieUser = cookieToken ? getSession(cookieToken) : null;
  const user = bearer ? bearerUser : cookieUser;
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  req.user = user;
  if (oauth?.kind === 'access') {
    req.oauthToken = oauth;
    req.authClient = getClientById(oauth.audience_client_id ?? oauth.client_id);
  }
  next();
}

/**
 * requireRole(...) checks membership against a client. Defaults to the IAM
 * system client (the platform's own console roles). Pass clientId to scope
 * the check to a specific application, e.g. requireRole('admin', 'blog').
 */
export function requireRole(...roles) {
  return (req, res, next) => {
    let clientId = SYSTEM_CLIENT_ID;
    if (roles.includes('__client__')) {
      clientId = req.authClient?.id ?? req.query?.client_id ?? SYSTEM_CLIENT_ID;
    }
    const names = roles.filter((r) => r !== '__client__');
    const has = getUserRolesForClient(req.user?.id, clientId).some((r) => names.includes(r));
    if (!has) return res.status(403).json({ error: 'Forbidden: insufficient role' });
    next();
  };
}

/**
 * Authenticate an application using its client credentials (client_id + secret).
 * Supports "Authorization: Basic base64(client_id:secret)" or the non-standard
 * "Authorization: Bearer <secret>" combined with "X-Client-Id: <client_id>".
 * Optionally allows the request to proceed as an admin session instead.
 */
export function requireClientAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  let client = null;

  if (/^Basic /i.test(auth)) {
    const decoded = Buffer.from(auth.slice(6).trim(), 'base64').toString('utf8');
    const [publicId, secret] = decoded.split(':');
    client = verifyClientSecret(publicId ?? '', secret ?? '');
  } else if (/^Bearer /i.test(auth)) {
    const secret = auth.slice(7).trim();
    const publicId = req.get('X-Client-Id') || '';
    client = verifyClientSecret(publicId, secret);
  }

  if (client) {
    req.authClient = client;
    return next();
  }
  res.status(401).json({ error: 'Invalid client credentials' });
}

/**
 * Accepts either a logged-in admin session or valid client credentials.
 * Sets req.user and/or req.authClient accordingly.
 */
export function requireAdminOrClient(req, res, next) {
  const bearer = req.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  const oauth = bearer ? getOauthToken(bearer) : null;
  const bearerUser = oauth?.kind === 'access' && oauth.user_id ? getUser(oauth.user_id) : null;
  const sessionUser = bearer ? bearerUser : (() => {
    const token = req.cookies?.[COOKIE_NAME];
    return token ? getSession(token) : null;
  })();

  if (sessionUser) {
    const isSystemAdmin = getUserRolesForClient(sessionUser.id, SYSTEM_CLIENT_ID).includes('admin');
    const requestedClient = req.params?.clientId ? getClientByPublicId(req.params.clientId) : null;
    const isApplicationAdmin = requestedClient
      && getUserRolesForClient(sessionUser.id, requestedClient.id).includes('admin');
    if (!isSystemAdmin && !isApplicationAdmin) return res.status(403).json({ error: 'Forbidden: insufficient role' });
    req.user = sessionUser;
    if (oauth?.kind === 'access') {
      req.oauthToken = oauth;
      req.authClient = getClientById(oauth.audience_client_id ?? oauth.client_id);
    }
    return next();
  }

  requireClientAuth(req, res, next);
}

export function requireAdmin(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME];
  const sessionUser = token ? getSession(token) : null;
  if (!sessionUser) return res.status(401).json({ error: 'Not authenticated' });
  if (!getUserRolesForClient(sessionUser.id, SYSTEM_CLIENT_ID).includes('admin')) {
    return res.status(403).json({ error: 'Forbidden: insufficient role' });
  }
  req.user = sessionUser;
  next();
}
