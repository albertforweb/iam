import crypto from 'node:crypto';
import { Router } from 'express';
import {
  getClientByPublicId,
  getClientById,
  getEffectiveUiSettings,
  verifyClientSecret,
  getUser,
  getUserRolesForClient,
  userPermissionsForClient,
  ensureDefaultRoleForClient,
  createAuthorizationCode,
  getAuthorizationCode,
  consumeAuthorizationCode,
  createOauthToken,
  getOauthToken,
  deleteOauthToken,
  getSession,
  listPermissions,
  getDelegationPolicy,
  recordAuditEvent,
  getOauthConsent,
  saveOauthConsent,
} from '../db.js';
import { COOKIE_NAME, rateLimit } from '../middleware.js';
import { issuerFor, oidcJwks, signIdToken } from '../oidc.js';

const router = Router();

export const OAUTH_ENABLED = (process.env.IAM_OAUTH_ENABLED ?? 'true') === 'true';
const BUILTIN_SCOPES = new Set(['openid', 'profile', 'email']);
const CONTEXT_TYPES = new Set(['global', 'tenant', 'organization', 'project', 'resource']);
const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const authorizeLimit = rateLimit({ name: 'authorize', max: 30, windowMs: 60_000 });
const tokenLimit = rateLimit({ name: 'token', max: 60, windowMs: 60_000 });

function bearerToken(req) {
  const auth = req.headers.authorization || '';
  if (/^Bearer /i.test(auth)) return auth.slice(7).trim();
  return null;
}

function parseScopes(raw) {
  if (!raw || typeof raw !== 'string') return [];
  return [...new Set(raw.split(/\s+/).map((s) => s.trim()).filter(Boolean))];
}

function urlEncodeForm(obj) {
  return new URLSearchParams(obj).toString();
}

function redirectWith(res, uri, params) {
  const url = new URL(uri);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) url.searchParams.set(key, value);
  }
  res.redirect(url.toString());
}

function parseBasicCredentials(req) {
  const auth = req.headers.authorization || '';
  if (!/^Basic /i.test(auth)) return null;
  try {
    const decoded = Buffer.from(auth.slice(6).trim(), 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    if (separator < 0) return null;
    return { clientId: decoded.slice(0, separator), secret: decoded.slice(separator + 1) };
  } catch {
    return null;
  }
}

function clientGrantAllowed(client, grantType) {
  return Array.isArray(client?.grant_types) && client.grant_types.includes(grantType);
}

function clientAllowedScopes(client, requested) {
  const configured = new Set(client?.allowed_scopes ?? []);
  const unsupported = requested.filter((scope) => !BUILTIN_SCOPES.has(scope) && !configured.has(scope));
  return unsupported.length === 0;
}

function validatePkce(challenge, method) {
  if (typeof challenge !== 'string' || !/^[A-Za-z0-9._~-]{43,128}$/.test(challenge)) return false;
  return method === 'S256';
}

function verifyPkce(code, verifier) {
  if (!code.code_challenge) return process.env.IAM_OAUTH_REQUIRE_PKCE !== 'true';
  if (typeof verifier !== 'string' || verifier.length < 43 || verifier.length > 128) return false;
  const expected = crypto.createHash('sha256').update(verifier).digest('base64url');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(code.code_challenge));
}

function authenticateTokenClient(req, body, grantType) {
  const basic = parseBasicCredentials(req);
  const clientId = basic?.clientId ?? body.client_id;
  const client = getClientByPublicId(String(clientId ?? ''));
  if (!client || !client.enabled) return null;

  // Public clients authenticate browser exchanges with PKCE and do not have
  // a secret to present for refresh or revocation.
  if (client.client_type === 'public') {
    return ['authorization_code', 'refresh_token', 'revoke'].includes(grantType) ? client : null;
  }

  const secret = basic?.secret ?? body.client_secret;
  return verifyClientSecret(client.client_id, secret) ? client : null;
}

function requestedAuthorizationScopes(client, rawScope) {
  const requested = parseScopes(rawScope);
  if (!clientAllowedScopes(client, requested)) return { error: 'invalid_scope' };
  return { requested };
}

function parseContext(params) {
  const contextType = params.context_type ?? 'global';
  const contextId = params.context_id ?? null;
  if (!CONTEXT_TYPES.has(contextType)) return { error: 'invalid_context' };
  if (contextType === 'global' && contextId !== null && contextId !== '') return { error: 'invalid_context' };
  if (contextType !== 'global' && (!contextId || typeof contextId !== 'string')) return { error: 'invalid_context' };
  return { contextType, contextId: contextId || null };
}

function userGrantedScopes(user, client, requested, context) {
  const userPermissions = new Set(userPermissionsForClient(user.id, client.id, context));
  return requested.filter((scope) => BUILTIN_SCOPES.has(scope) || userPermissions.has(scope));
}

function issueIdToken(req, client, user, code, scopes) {
  if (!scopes.includes('openid')) return undefined;
  return signIdToken({
    issuer: issuerFor(req),
    clientId: client.client_id,
    user,
    nonce: code.nonce,
    authTime: Math.floor(new Date(code.auth_time ?? code.created_at).getTime() / 1000),
    scopes,
  });
}

function encodeAuthorizationRequest(query) {
  return Buffer.from(urlEncodeForm(query)).toString('base64url');
}

function decodeAuthorizationRequest(encoded) {
  try {
    return Object.fromEntries(new URLSearchParams(Buffer.from(String(encoded), 'base64url').toString('utf8')));
  } catch {
    return null;
  }
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function themeColor(value, fallback) {
  return typeof value === 'string' && /^#[0-9a-fA-F]{6}$/.test(value) ? value : fallback;
}

function issueAuthorizationCode(req, res, client, user, params, requested) {
  const context = parseContext(params);
  if (context.error) return res.status(400).json({ error: context.error });
  const scopes = userGrantedScopes(user, client, requested, context);
  const code = createAuthorizationCode({
    clientId: client.id,
    userId: user.id,
    scopes,
    redirectUri: params.redirect_uri,
    codeChallenge: params.code_challenge,
    codeChallengeMethod: params.code_challenge_method,
    nonce: params.nonce,
    contextType: context.contextType,
    contextId: context.contextId,
    authTime: new Date().toISOString(),
  });
  redirectWith(res, params.redirect_uri, { code: code.code, state: params.state });
}

router.get('/.well-known/openid-configuration', (req, res) => {
  const issuer = issuerFor(req);
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    introspection_endpoint: `${issuer}/oauth/introspect`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials', TOKEN_EXCHANGE_GRANT],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['openid', 'profile', 'email'],
  });
});

router.get('/.well-known/jwks.json', (req, res) => {
  res.json(oidcJwks());
});

/** GET /oauth/authorize: Authorization Code + PKCE browser flow. */
router.get('/oauth/authorize', authorizeLimit, (req, res) => {
  const clientId = String(req.query.client_id ?? '');
  const redirectUri = typeof req.query.redirect_uri === 'string' ? req.query.redirect_uri : '';
  const responseType = req.query.response_type;
  const scope = typeof req.query.scope === 'string' ? req.query.scope : '';
  const state = typeof req.query.state === 'string' ? req.query.state : '';
  const codeChallenge = typeof req.query.code_challenge === 'string' ? req.query.code_challenge : '';
  const codeChallengeMethod = typeof req.query.code_challenge_method === 'string' ? req.query.code_challenge_method : '';
  const nonce = typeof req.query.nonce === 'string' ? req.query.nonce : '';

  const client = getClientByPublicId(clientId);
  if (!client || !client.enabled) return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid client_id' });
  if (!clientGrantAllowed(client, 'authorization_code')) return res.status(400).json({ error: 'unauthorized_client' });
  if (responseType !== 'code') return res.status(400).json({ error: 'unsupported_response_type' });
  if (!redirectUri || !client.redirect_uris.includes(redirectUri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri is not registered for this client' });
  }
  if (!state) return res.status(400).json({ error: 'invalid_request', error_description: 'state is required' });
  if (process.env.IAM_OAUTH_REQUIRE_PKCE !== 'false' && !validatePkce(codeChallenge, codeChallengeMethod)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'A S256 code_challenge is required' });
  }
  if (scope.split(/\s+/).includes('openid') && !nonce) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'nonce is required for OpenID Connect' });
  }
  const context = parseContext(req.query);
  if (context.error) return res.status(400).json({ error: context.error });
  const scopeResult = requestedAuthorizationScopes(client, scope);
  if (scopeResult.error) return res.status(400).json(scopeResult);

  const token = req.cookies?.[COOKIE_NAME];
  const user = token ? getSession(token) : null;
  if (!user) {
    const loginUrl = new URL(`${issuerFor(req)}/login`);
    loginUrl.searchParams.set('next', `/api/auth/oauth/authorize?${urlEncodeForm(req.query)}`);
    return res.redirect(loginUrl.toString());
  }

  // The application owns the role definition; IAM only applies the
  // application's declared default role when this user has no membership in
  // that application yet. Existing app-specific assignments are preserved.
  const provisioning = ensureDefaultRoleForClient(user.id, client.id, client.default_role, context);
  if (provisioning.error) {
    recordAuditEvent({
      eventType: 'application_default_role_provisioning_failed',
      userId: user.id,
      clientId: client.id,
      metadata: { role: client.default_role, error: provisioning.error },
    });
    return res.status(503).json({ error: 'server_error', error_description: 'Application authorization is not configured correctly' });
  }
  if (provisioning.assigned) {
    recordAuditEvent({
      eventType: 'application_default_role_provisioned',
      userId: user.id,
      clientId: client.id,
      metadata: { role: client.default_role, context_type: context.contextType, context_id: context.contextId },
    });
  }

  const granted = userGrantedScopes(user, client, scopeResult.requested, context);
  const consented = new Set(getOauthConsent(user.id, client.id));
  if (granted.some((requestedScope) => !consented.has(requestedScope))) {
    const encoded = encodeAuthorizationRequest(req.query);
    return res.redirect(`/oauth/consent?request=${encodeURIComponent(encoded)}`);
  }
  issueAuthorizationCode(req, res, client, user, req.query, scopeResult.requested);
});

router.get('/oauth/consent', (req, res) => {
  const params = decodeAuthorizationRequest(req.query.request);
  if (!params) return res.status(400).json({ error: 'invalid_request' });
  const client = getClientByPublicId(params.client_id);
  const user = req.cookies?.[COOKIE_NAME] ? getSession(req.cookies[COOKIE_NAME]) : null;
  if (!client || !user) return res.status(400).json({ error: 'invalid_request' });
  const requested = parseScopes(params.scope);
  if (!client.redirect_uris.includes(params.redirect_uri) || !clientAllowedScopes(client, requested)) {
    return res.status(400).json({ error: 'invalid_request' });
  }
  const ui = getEffectiveUiSettings(client.id);
  const theme = {
    pageTitle: ui.pageTitle || client.name,
    brandName: ui.brandName || client.name,
    logoText: ui.logoText || 'I',
    subtitle: ui.subtitle || 'Secure access request',
    backgroundColor: themeColor(ui.backgroundColor, '#070b18'),
    surfaceColor: themeColor(ui.surfaceColor, '#141d36'),
    inputBackgroundColor: themeColor(ui.inputBackgroundColor, '#0a1123'),
    inputBorderColor: themeColor(ui.inputBorderColor, '#8199dd'),
    textColor: themeColor(ui.textColor, '#f3f5ff'),
    mutedTextColor: themeColor(ui.mutedTextColor, '#9caacc'),
    accentColor: themeColor(ui.accentColor, '#7c83ff'),
    accentStrongColor: themeColor(ui.accentStrongColor, '#6366f1'),
    buttonTextColor: themeColor(ui.buttonTextColor, '#ffffff'),
  };
  const granted = userGrantedScopes(user, client, requested);
  const scopeCopy = (scope) => {
    const builtIn = {
      openid: ['Basic identity', 'Confirm your identity to this application'],
      profile: ['Profile information', 'Share your display name and username'],
      email: ['Email address', 'Share your email address'],
    }[scope];
    if (builtIn) return builtIn;
    const parts = scope.split(':');
    const application = parts[0] || 'Application';
    const action = parts.slice(1).join(' · ') || 'Access';
    return [`${application} · ${action}`, 'Application-specific access permission'];
  };
  const labels = granted.map((scope) => {
    const [label, description] = scopeCopy(scope);
    return `<li><span class="scope-check" aria-hidden="true">✓</span><span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(description)}</small></span></li>`;
  }).join('');
  const requestValue = escapeHtml(req.query.request);
  res.set('Cache-Control', 'no-store');
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(theme.pageTitle)} · Authorize ${escapeHtml(client.name)}</title>
  <style>
    :root {
      --bg: ${theme.backgroundColor};
      --panel: ${theme.surfaceColor};
      --panel-soft: ${theme.inputBackgroundColor};
      --border: ${theme.inputBorderColor};
      --text: ${theme.textColor};
      --muted: ${theme.mutedTextColor};
      --accent: ${theme.accentColor};
      --accent-strong: ${theme.accentStrongColor};
      --button-text: ${theme.buttonTextColor};
    }
    * { box-sizing: border-box; }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 32px 18px;
      color: var(--text);
      background: linear-gradient(135deg, var(--bg), var(--panel));
      font: 15px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .shell { width: min(100%, 520px); }
    .brand { display: flex; align-items: center; gap: 12px; margin: 0 auto 22px; width: fit-content; }
    .brand-mark {
      display: grid; place-items: center; width: 42px; height: 42px; border-radius: 13px;
      color: var(--button-text); font-size: 21px; font-weight: 800;
      background: linear-gradient(135deg, var(--accent), var(--accent-strong));
      box-shadow: 0 12px 30px rgba(0, 0, 0, .24);
    }
    .brand strong { font-size: 19px; letter-spacing: -.02em; }
    .brand small { display: block; color: var(--muted); font-size: 12px; }
    .card {
      padding: 34px;
      border: 1px solid var(--border);
      border-radius: 24px;
      background: var(--panel);
      box-shadow: 0 28px 80px rgba(0, 0, 0, .38), inset 0 1px rgba(255, 255, 255, .04);
    }
    .eyebrow { margin: 0 0 8px; color: var(--accent); font-size: 11px; font-weight: 800; letter-spacing: .18em; text-transform: uppercase; }
    h1 { margin: 0; font-size: clamp(26px, 5vw, 34px); line-height: 1.12; letter-spacing: -.04em; }
    .intro { margin: 12px 0 0; color: var(--muted); }
    .intro strong { color: var(--text); font-weight: 650; }
    .permissions { margin: 26px 0 0; padding: 18px; border: 1px solid var(--border); border-radius: 16px; background: var(--panel-soft); }
    .permissions-heading { display: flex; justify-content: space-between; gap: 16px; margin-bottom: 12px; color: var(--muted); font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
    .permissions-heading span:last-child { color: var(--accent); }
    ul { display: grid; gap: 4px; margin: 0; padding: 0; list-style: none; }
    li { display: flex; gap: 12px; align-items: flex-start; padding: 10px 8px; border-radius: 10px; }
    li:hover { background: var(--panel); }
    .scope-check { flex: 0 0 auto; display: grid; place-items: center; width: 22px; height: 22px; margin-top: 1px; border-radius: 50%; color: var(--button-text); background: var(--accent-strong); font-size: 13px; font-weight: 800; }
    li strong, li small { display: block; }
    li strong { color: var(--text); font-size: 14px; font-weight: 650; }
    li small { margin-top: 2px; color: var(--muted); font-size: 12px; }
    .notice { margin: 18px 0 0; color: var(--muted); font-size: 12px; }
    .actions { display: flex; gap: 12px; margin-top: 28px; }
    button { flex: 1; min-height: 46px; padding: 0 18px; border-radius: 11px; font: inherit; font-weight: 750; cursor: pointer; transition: transform .15s ease, filter .15s ease, background .15s ease; }
    button:hover { transform: translateY(-1px); filter: brightness(1.08); }
    button:focus-visible { outline: 3px solid var(--accent); outline-offset: 3px; }
    .deny { color: var(--text); border: 1px solid var(--border); background: transparent; }
    .allow { color: var(--button-text); border: 0; background: linear-gradient(135deg, var(--accent), var(--accent-strong)); box-shadow: 0 10px 24px rgba(0, 0, 0, .24); }
    .footer { margin-top: 18px; color: var(--muted); text-align: center; font-size: 11px; }
    @media (max-width: 480px) { .card { padding: 26px 20px; border-radius: 20px; } .actions { flex-direction: column-reverse; } }
  </style>
</head>
<body>
  <main class="shell">
    <div class="brand"><span class="brand-mark">${escapeHtml(theme.logoText)}</span><span><strong>${escapeHtml(theme.brandName)}</strong><small>${escapeHtml(theme.subtitle)}</small></span></div>
    <section class="card" aria-labelledby="consent-title">
      <p class="eyebrow">Authorization request</p>
      <h1 id="consent-title">${escapeHtml(client.name)} requests access</h1>
      <p class="intro">You are signed in as <strong>@${escapeHtml(user.username)}</strong>.</p>
      <section class="permissions" aria-labelledby="permissions-title">
        <div class="permissions-heading"><span id="permissions-title">This app can</span><span>${granted.length} permission${granted.length === 1 ? '' : 's'}</span></div>
        <ul>${labels || '<li><span class="scope-check" aria-hidden="true">✓</span><span><strong>Sign in</strong><small>Confirm your identity to this application</small></span></li>'}</ul>
      </section>
      <p class="notice">Only the permissions listed above will be shared with this application.</p>
      <form method="post" action="/oauth/consent">
        <input type="hidden" name="request" value="${requestValue}">
        <div class="actions">
          <button class="deny" name="decision" value="deny" type="submit">Deny</button>
          <button class="allow" name="decision" value="allow" type="submit">Allow access</button>
        </div>
      </form>
    </section>
    <p class="footer">You can close this window if you do not recognize the application.</p>
  </main>
</body>
</html>`);
});

router.post('/oauth/consent', (req, res) => {
  const params = decodeAuthorizationRequest(req.body?.request);
  if (!params) return res.status(400).json({ error: 'invalid_request' });
  const client = getClientByPublicId(params.client_id);
  const user = req.cookies?.[COOKIE_NAME] ? getSession(req.cookies[COOKIE_NAME]) : null;
  if (!client || !user || !client.redirect_uris.includes(params.redirect_uri)) {
    return res.status(400).json({ error: 'invalid_request' });
  }
  const requested = parseScopes(params.scope);
  if (!clientAllowedScopes(client, requested)) return res.status(400).json({ error: 'invalid_scope' });
  if (req.body?.decision !== 'allow') {
    recordAuditEvent({ eventType: 'consent_denied', userId: user.id, clientId: client.id, success: false });
    return redirectWith(res, params.redirect_uri, { error: 'access_denied', state: params.state });
  }
  const granted = userGrantedScopes(user, client, requested);
  saveOauthConsent(user.id, client.id, granted);
  recordAuditEvent({ eventType: 'consent_granted', userId: user.id, clientId: client.id, metadata: { scopes: granted } });
  issueAuthorizationCode(req, res, client, user, params, requested);
});

/** POST /oauth/token: code, refresh_token, client_credentials, and controlled token exchange. */
router.post('/oauth/token', tokenLimit, (req, res) => {
  const body = req.body ?? {};
  const grantType = body.grant_type;
  if (!grantType) return res.status(400).json({ error: 'invalid_request', error_description: 'grant_type is required' });

  const client = authenticateTokenClient(req, body, grantType);
  if (!client) return res.status(401).json({ error: 'invalid_client' });
  if (!clientGrantAllowed(client, grantType)) return res.status(400).json({ error: 'unauthorized_client' });

  if (grantType === 'authorization_code') {
    const code = getAuthorizationCode(body.code);
    if (!code || code.client_id !== client.id || !verifyPkce(code, body.code_verifier)) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid authorization code or code_verifier' });
    }
    if (body.redirect_uri !== code.redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    }
    consumeAuthorizationCode(code.code);

    const user = getUser(code.user_id);
    if (!user || user.status !== 'active') {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'User account is not active' });
    }
    const scopes = userGrantedScopes(user, client, code.scopes, code);
    const access = createOauthToken({ clientId: client.id, userId: user.id, scopes, kind: 'access', contextType: code.context_type, contextId: code.context_id });
    const refresh = createOauthToken({ clientId: client.id, userId: user.id, scopes, kind: 'refresh', contextType: code.context_type, contextId: code.context_id });
    const response = {
      access_token: access.token,
      token_type: 'Bearer',
      expires_in: access.expiresIn,
      refresh_token: refresh.token,
      scope: scopes.join(' '),
    };
    const idToken = issueIdToken(req, client, user, code, scopes);
    if (idToken) response.id_token = idToken;
    recordAuditEvent({ eventType: 'token_issued', userId: user.id, clientId: client.id, metadata: { grant_type: grantType, scopes } });
    return res.json(response);
  }

  if (grantType === 'client_credentials') {
    const requested = parseScopes(body.scope);
    if (!clientAllowedScopes(client, requested)) return res.status(400).json({ error: 'invalid_scope' });
    const registered = new Set(listPermissions(client.id).map((permission) => permission.name));
    const allowed = new Set((client.allowed_scopes ?? []).filter((scope) => registered.has(scope)));
    const scopes = requested.filter((scope) => allowed.has(scope));
    if (scopes.length !== requested.length) return res.status(400).json({ error: 'invalid_scope' });
    const access = createOauthToken({ clientId: client.id, userId: null, scopes, kind: 'access' });
    recordAuditEvent({ eventType: 'service_token_issued', clientId: client.id, metadata: { grant_type: grantType, scopes } });
    return res.json({ access_token: access.token, token_type: 'Bearer', expires_in: access.expiresIn, scope: scopes.join(' ') });
  }

  if (grantType === TOKEN_EXCHANGE_GRANT) {
    const subjectTokenType = body.subject_token_type ?? ACCESS_TOKEN_TYPE;
    if (subjectTokenType !== ACCESS_TOKEN_TYPE) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Only access-token subject tokens are supported' });
    }

    const subjectToken = getOauthToken(String(body.subject_token ?? ''));
    if (!subjectToken || subjectToken.kind !== 'access' || !subjectToken.user_id || subjectToken.client_id !== client.id || (subjectToken.audience_client_id ?? subjectToken.client_id) !== client.id) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'The subject token is invalid for this client' });
    }

    const audience = typeof body.audience === 'string' ? body.audience.trim() : '';
    const target = getClientByPublicId(audience);
    if (!target || !target.enabled || target.id === client.id) {
      return res.status(400).json({ error: 'invalid_target', error_description: 'The target audience is not valid' });
    }

    const policy = getDelegationPolicy(client.id, target.id);
    if (!policy || !policy.enabled) {
      recordAuditEvent({
        eventType: 'token_exchange_denied',
        userId: subjectToken.user_id,
        clientId: client.id,
        success: false,
        metadata: { target_client_id: target.client_id, reason: 'delegation_policy' },
      });
      return res.status(403).json({ error: 'unauthorized_client', error_description: 'This client is not allowed to delegate to the target audience' });
    }

    const requested = parseScopes(body.scope);
    if (!requested.length || requested.some((scope) => BUILTIN_SCOPES.has(scope))) {
      return res.status(400).json({ error: 'invalid_scope', error_description: 'Token exchange requires one or more target API scopes' });
    }
    const allowedByPolicy = new Set(policy.allowed_scopes);
    const targetRegisteredPermissions = new Set(listPermissions(target.id).map((permission) => permission.name));
    const targetAllowedScopes = new Set(target.allowed_scopes ?? []);
    const user = getUser(subjectToken.user_id);
    if (!user || user.status !== 'active') {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'User account is not active' });
    }

    const context = body.context_type || body.context_id
      ? parseContext(body)
      : { contextType: 'global', contextId: null };
    if (context.error) return res.status(400).json({ error: context.error });
    const userPermissions = new Set(userPermissionsForClient(user.id, target.id, context));
    const invalid = requested.filter((scope) => !allowedByPolicy.has(scope) || !targetAllowedScopes.has(scope) || !targetRegisteredPermissions.has(scope) || !userPermissions.has(scope));
    if (invalid.length) {
      recordAuditEvent({
        eventType: 'token_exchange_denied',
        userId: user.id,
        clientId: client.id,
        success: false,
        metadata: { target_client_id: target.client_id, requested_scopes: requested, invalid_scopes: invalid },
      });
      return res.status(400).json({ error: 'invalid_scope', error_description: 'Requested scopes are not allowed for this user and target audience' });
    }

    const access = createOauthToken({
      clientId: client.id,
      audienceClientId: target.id,
      userId: user.id,
      scopes: requested,
      kind: 'access',
      contextType: context.contextType,
      contextId: context.contextId,
    });
    recordAuditEvent({
      eventType: 'token_exchanged',
      userId: user.id,
      clientId: client.id,
      metadata: { target_client_id: target.client_id, scopes: requested, context },
    });
    return res.json({
      access_token: access.token,
      token_type: 'Bearer',
      expires_in: access.expiresIn,
      scope: requested.join(' '),
      issued_token_type: ACCESS_TOKEN_TYPE,
    });
  }

  if (grantType === 'refresh_token') {
    const token = getOauthToken(body.refresh_token);
    if (!token || token.client_id !== client.id || token.kind !== 'refresh') {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid refresh token' });
    }
    if (token.user_id) {
      const user = getUser(token.user_id);
      if (!user || user.status !== 'active') {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'User account is not active' });
      }
    }
    deleteOauthToken(token.token);
    const audienceClientId = token.audience_client_id ?? token.client_id;
    const access = createOauthToken({ clientId: client.id, audienceClientId, userId: token.user_id, scopes: token.scopes, kind: 'access', contextType: token.context_type, contextId: token.context_id });
    const refresh = createOauthToken({ clientId: client.id, audienceClientId, userId: token.user_id, scopes: token.scopes, kind: 'refresh', contextType: token.context_type, contextId: token.context_id });
    recordAuditEvent({ eventType: 'token_refreshed', userId: token.user_id, clientId: client.id, metadata: { grant_type: grantType, scopes: token.scopes } });
    return res.json({
      access_token: access.token,
      token_type: 'Bearer',
      expires_in: access.expiresIn,
      refresh_token: refresh.token,
      scope: token.scopes.join(' '),
    });
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

/** POST /oauth/introspect: only the owning confidential client may introspect. */
router.post('/oauth/introspect', (req, res) => {
  const tokenValue = String(req.body?.token ?? '');
  const token = getOauthToken(tokenValue);
  const client = authenticateTokenClient(req, {}, 'introspection');
  if (!client) return res.status(401).json({ error: 'invalid_client' });
  const audienceClientId = token?.audience_client_id ?? token?.client_id;
  if (!token || token.kind !== 'access' || (token.client_id !== client.id && audienceClientId !== client.id)) return res.json({ active: false });
  return res.json(introspectPayload(token, req));
});

router.post('/oauth/revoke', (req, res) => {
  const client = authenticateTokenClient(req, req.body ?? {}, 'revoke');
  if (!client) return res.status(401).json({ error: 'invalid_client' });
  const token = getOauthToken(String(req.body?.token ?? ''));
  if (token?.client_id === client.id) deleteOauthToken(token.token);
  res.status(200).end();
});

function introspectPayload(token, req) {
  const client = getClientById(token.client_id);
  const audience = getClientById(token.audience_client_id ?? token.client_id);
  const user = token.user_id ? getUser(token.user_id) : null;
  const permissions = user && audience ? userPermissionsForClient(user.id, audience.id, token) : [];
  const roles = user && audience ? getUserRolesForClient(user.id, audience.id, token) : [];
  return {
    active: true,
    iss: issuerFor(req),
    scope: token.scopes.join(' '),
    client_id: client?.client_id,
    aud: audience?.client_id,
    azp: client?.client_id,
    sub: user?.id ?? null,
    username: user?.username ?? null,
    display_name: user?.display_name ?? null,
    token_type: 'Bearer',
    iat: Math.floor(new Date(token.created_at).getTime() / 1000),
    exp: Math.floor(new Date(token.expires_at).getTime() / 1000),
    context_type: token.context_type,
    context_id: token.context_id,
    roles,
    permissions,
  };
}

/** GET /oauth/userinfo: user-scoped access token claims. */
router.get('/oauth/userinfo', (req, res) => {
  const token = getOauthToken(bearerToken(req) ?? '');
  if (!token || token.kind !== 'access') return res.status(401).json({ error: 'invalid_token' });
  if (!token.user_id) return res.status(401).json({ error: 'invalid_token', error_description: 'Token is not user-scoped' });

  const user = getUser(token.user_id);
  const sourceClient = getClientById(token.client_id);
  const audienceClient = getClientById(token.audience_client_id ?? token.client_id);
  if (!user || user.status !== 'active' || !sourceClient || !audienceClient) return res.status(401).json({ error: 'invalid_token' });

  const response = {
    sub: user.id,
    client_id: audienceClient.client_id,
    aud: audienceClient.client_id,
    ...(sourceClient.id !== audienceClient.id ? { azp: sourceClient.client_id } : {}),
    scope: token.scopes,
    permissions: userPermissionsForClient(user.id, audienceClient.id, token),
    roles: getUserRolesForClient(user.id, audienceClient.id, token),
    context_type: token.context_type,
    context_id: token.context_id,
  };
  if (token.scopes.includes('profile')) {
    response.username = user.username;
    response.name = user.display_name;
  }
  if (token.scopes.includes('email')) {
    response.email = user.email;
    response.email_verified = false;
  }
  res.json(response);
});

export default router;
