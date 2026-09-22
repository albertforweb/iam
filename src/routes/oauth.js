import crypto from 'node:crypto';
import { Router } from 'express';
import {
  getClientByPublicId,
  getClientById,
  verifyClientSecret,
  getUser,
  getUserRolesForClient,
  userPermissionsForClient,
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

  // Public clients authenticate the authorization-code exchange with PKCE.
  if (client.client_type === 'public') return grantType === 'authorization_code' ? client : null;

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
    const next = encodeURIComponent(`/api/auth/oauth/authorize?${urlEncodeForm(req.query)}`);
    return res.redirect(`/?next=${next}`);
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
  const granted = userGrantedScopes(user, client, requested);
  const labels = granted.map((scope) => `<li>${escapeHtml(scope)}</li>`).join('');
  const requestValue = escapeHtml(req.query.request);
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Authorize ${escapeHtml(client.name)}</title></head><body><main><h1>${escapeHtml(client.name)} requests access</h1><p>Signed in as ${escapeHtml(user.username)}.</p><ul>${labels || '<li>basic sign-in</li>'}</ul><form method="post" action="/oauth/consent"><input type="hidden" name="request" value="${requestValue}"><button name="decision" value="deny" type="submit">Deny</button><button name="decision" value="allow" type="submit">Allow</button></form></main></body></html>`);
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
  const client = authenticateTokenClient(req, {}, 'revoke');
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
