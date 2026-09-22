import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'svc-iam-'));
process.env.IAM_DB_PATH = path.join(tempDir, 'iam.db');
process.env.IAM_UI_ENABLED = 'false';
process.env.IAM_ADMIN_PASSWORD = 'test-admin-password-123';
process.env.IAM_OAUTH_REQUIRE_PKCE = 'true';
process.env.IAM_OIDC_KEY_FILE = path.join(tempDir, 'oidc.key');

const { createApp } = await import('../src/app.js');
const {
  createClient,
  createPermission,
  createRole,
  setRolePermissions,
  createUser,
  setUserRolesForClient,
  getUserRolesForClient,
  userPermissionsForClient,
  createDelegationPolicy,
  getClientByPublicId,
  verifyClientSecret,
} = await import('../src/db.js');
const { bootstrapConfiguredApplications } = await import('../src/application-bootstrap.js');

const client = createClient({
  clientId: 'test-app',
  name: 'Test App',
  secret: 'test-client-secret-123',
  redirectUris: ['http://127.0.0.1/callback'],
  clientType: 'confidential',
  grantTypes: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:token-exchange'],
  allowedScopes: ['reports:read'],
});
const permission = createPermission({ clientId: client.id, name: 'reports:read', description: 'Read reports' });
const role = createRole({ clientId: client.id, name: 'reader', description: 'Application reader' });
setRolePermissions(role.id, [permission.id]);
const tenantRole = createRole({ clientId: client.id, name: 'tenant-reader', description: 'Tenant-scoped reader' });
setRolePermissions(tenantRole.id, [permission.id]);
const user = createUser({
  username: 'test-user',
  displayName: 'Test User',
  email: 'test-user@example.test',
  password: 'test-user-password',
  roles: [],
});
setUserRolesForClient(user.id, client.id, ['reader']);
setUserRolesForClient(user.id, client.id, ['tenant-reader'], { contextType: 'tenant', contextId: 'tenant-1' });

const blogsApi = createClient({
  clientId: 'blogs-api',
  name: 'Blogs API',
  secret: 'blogs-api-secret-123',
  clientType: 'service',
  grantTypes: ['client_credentials'],
  allowedScopes: ['blogs:read', 'blogs:comment'],
});
const blogsRead = createPermission({ clientId: blogsApi.id, name: 'blogs:read', description: 'Read blogs content' });
const blogsReader = createRole({ clientId: blogsApi.id, name: 'reader', description: 'Blogs reader' });
setRolePermissions(blogsReader.id, [blogsRead.id]);
setUserRolesForClient(user.id, blogsApi.id, ['reader']);
createDelegationPolicy({ sourceClientId: client.id, targetClientId: blogsApi.id, allowedScopes: ['blogs:read'] });

let mainsiteAccessToken;

const app = createApp();
const server = await new Promise((resolve) => {
  const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
});
const base = `http://127.0.0.1:${server.address().port}`;

test('publishes OIDC discovery and rejects unconfigured CORS origins', async () => {
  const discoveryResponse = await fetch(`${base}/.well-known/openid-configuration`);
  assert.equal(discoveryResponse.status, 200);
  const discovery = await discoveryResponse.json();
  assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']);
  assert.match(discovery.jwks_uri, /\.well-known\/jwks\.json$/);

  const preflight = await fetch(`${base}/health`, {
    method: 'OPTIONS',
    headers: { Origin: 'https://untrusted.example' },
  });
  assert.equal(preflight.status, 403);
});

test('bootstraps configured applications and preserves vault secrets across restarts', async () => {
  const configPath = path.join(tempDir, 'applications.json');
  const vaultPath = path.join(tempDir, '.vaults');
  fs.writeFileSync(configPath, JSON.stringify({
    applications: [{
      clientId: 'bootstrap-app',
      name: 'Bootstrap App',
      clientType: 'service',
      grantTypes: ['client_credentials'],
    }],
  }));

  const first = bootstrapConfiguredApplications({ configPath, vaultPath });
  assert.equal(first.applications[0].clientId, 'bootstrap-app');
  assert.equal(first.applications[0].created, true);
  const vault = JSON.parse(fs.readFileSync(vaultPath, 'utf8'));
  const secret = vault.clients['bootstrap-app'].clientSecret;
  assert.equal(secret.length >= 16, true);
  assert.ok(verifyClientSecret('bootstrap-app', secret));
  assert.equal(fs.statSync(vaultPath).mode & 0o777, 0o600);

  const second = bootstrapConfiguredApplications({ configPath, vaultPath });
  assert.equal(second.changed, false);
  assert.equal(second.applications[0].created, false);
  assert.ok(getClientByPublicId('bootstrap-app'));
});

test('does not allow an application credential to register another client', async () => {
  const response = await fetch(`${base}/v1/clients`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${client.client_id}:test-client-secret-123`).toString('base64')}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ clientId: 'unexpected-client', name: 'Unexpected Client' }),
  });
  assert.equal(response.status, 401);
});

test('keeps delegation policy management with IAM administrators', async () => {
  const denied = await fetch(`${base}/v1/clients/${client.client_id}/delegations`, {
    headers: { Authorization: `Basic ${Buffer.from(`${client.client_id}:test-client-secret-123`).toString('base64')}` },
  });
  assert.equal(denied.status, 401);

  const login = await fetch(`${base}/v1/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'test-admin-password-123' }),
  });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie')?.split(';')[0];
  assert.ok(cookie);

  const response = await fetch(`${base}/v1/clients/${client.client_id}/delegations`, { headers: { Cookie: cookie } });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.policies[0].allowedScopes, ['blogs:read']);
  assert.equal(body.policies[0].targetClientId, blogsApi.client_id);
});

test('reconciles an application-owned authorization manifest idempotently', async () => {
  const manifest = {
    version: '2.0.0',
    permissions: [
      { name: 'reports:read', description: 'Read reports' },
      { name: 'reports:export', description: 'Export reports' },
    ],
    roles: [
      { name: 'reader', description: 'Application reader', permissions: ['reports:read'] },
      { name: 'exporter', description: 'Can export reports', permissions: ['reports:read', 'reports:export'] },
    ],
  };
  const headers = {
    Authorization: `Basic ${Buffer.from(`${client.client_id}:test-client-secret-123`).toString('base64')}`,
    'content-type': 'application/json',
  };

  const first = await fetch(`${base}/v1/clients/${client.client_id}/authorization-manifest`, {
    method: 'PUT', headers, body: JSON.stringify(manifest),
  });
  assert.equal(first.status, 200);
  const firstBody = await first.json();
  assert.equal(firstBody.manifest.version, '2.0.0');
  assert.ok(firstBody.manifest.checksum);
  assert.ok(firstBody.manifest.permissions.some((permission) => permission.name === 'reports:export'));
  assert.ok(firstBody.manifest.roles.some((role) => role.name === 'exporter'));

  const clientAfterReconcile = await fetch(`${base}/v1/clients/${client.client_id}`, { headers });
  assert.equal(clientAfterReconcile.status, 200);
  const clientBody = await clientAfterReconcile.json();
  assert.ok(clientBody.client.allowed_scopes.includes('reports:export'));

  const second = await fetch(`${base}/v1/clients/${client.client_id}/authorization-manifest`, {
    method: 'PUT', headers, body: JSON.stringify(manifest),
  });
  assert.equal(second.status, 200);
  const secondBody = await second.json();
  assert.equal(secondBody.manifest.checksum, firstBody.manifest.checksum);

  const foreign = await fetch(`${base}/v1/clients/${client.client_id}/authorization-manifest`, {
    method: 'PUT',
    headers: {
      Authorization: `Basic ${Buffer.from(`${blogsApi.client_id}:blogs-api-secret-123`).toString('base64')}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(manifest),
  });
  assert.equal(foreign.status, 403);
});

test('exchanges a PKCE code into application-scoped claims', async () => {
  const login = await fetch(`${base}/v1/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: user.username, password: 'test-user-password' }),
  });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie')?.split(';')[0];
  assert.ok(cookie);

  const verifier = 'test-verifier-abcdefghijklmnopqrstuvwxyz-1234567890';
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const authorizeUrl = new URL(`${base}/oauth/authorize`);
  authorizeUrl.search = new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: 'http://127.0.0.1/callback',
    scope: 'openid profile reports:read',
    state: 'state-123',
    nonce: 'nonce-123',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  const authorize = await fetch(authorizeUrl, { headers: { Cookie: cookie }, redirect: 'manual' });
  assert.equal(authorize.status, 302);
  const consentUrl = new URL(authorize.headers.get('location'), base);
  assert.equal(consentUrl.pathname, '/oauth/consent');
  const consentPage = await fetch(consentUrl, { headers: { Cookie: cookie } });
  assert.equal(consentPage.status, 200);
  const consent = await fetch(consentUrl, {
    method: 'POST',
    headers: { Cookie: cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ request: consentUrl.searchParams.get('request'), decision: 'allow' }),
    redirect: 'manual',
  });
  assert.equal(consent.status, 302);
  const callback = new URL(consent.headers.get('location'));
  assert.equal(callback.searchParams.get('state'), 'state-123');

  const token = await fetch(`${base}/oauth/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${client.client_id}:test-client-secret-123`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: callback.searchParams.get('code'),
      redirect_uri: 'http://127.0.0.1/callback',
      code_verifier: verifier,
    }),
  });
  assert.equal(token.status, 200);
  const tokens = await token.json();
  assert.ok(tokens.access_token);
  assert.ok(tokens.id_token);
  assert.ok(tokens.refresh_token);

  const userinfo = await fetch(`${base}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  assert.equal(userinfo.status, 200);
  const claims = await userinfo.json();
  assert.equal(claims.sub, user.id);
  assert.deepEqual(claims.roles, ['reader']);
  assert.deepEqual(claims.permissions, ['reports:read']);
  mainsiteAccessToken = tokens.access_token;
});

test('exchanges a user token for an explicitly delegated target audience', async () => {
  const exchange = await fetch(`${base}/oauth/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${client.client_id}:test-client-secret-123`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: mainsiteAccessToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      audience: blogsApi.client_id,
      scope: 'blogs:read',
    }),
  });
  assert.equal(exchange.status, 200);
  const delegated = await exchange.json();
  assert.ok(delegated.access_token);
  assert.equal(delegated.scope, 'blogs:read');
  assert.equal(delegated.issued_token_type, 'urn:ietf:params:oauth:token-type:access_token');
  assert.equal(delegated.refresh_token, undefined);

  const introspection = await fetch(`${base}/oauth/introspect`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${blogsApi.client_id}:blogs-api-secret-123`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ token: delegated.access_token }),
  });
  assert.equal(introspection.status, 200);
  const details = await introspection.json();
  assert.equal(details.active, true);
  assert.equal(details.aud, blogsApi.client_id);
  assert.equal(details.azp, client.client_id);
  assert.equal(details.sub, user.id);
  assert.deepEqual(details.roles, ['reader']);
  assert.deepEqual(details.permissions, ['blogs:read']);

  const userinfo = await fetch(`${base}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${delegated.access_token}` },
  });
  assert.equal(userinfo.status, 200);
  const claims = await userinfo.json();
  assert.equal(claims.client_id, blogsApi.client_id);
  assert.equal(claims.aud, blogsApi.client_id);
  assert.equal(claims.azp, client.client_id);
  assert.deepEqual(claims.roles, ['reader']);
  assert.deepEqual(claims.permissions, ['blogs:read']);
});

test('does not let token exchange widen target permissions', async () => {
  const exchange = await fetch(`${base}/oauth/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${client.client_id}:test-client-secret-123`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: mainsiteAccessToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      audience: blogsApi.client_id,
      scope: 'blogs:comment',
    }),
  });
  assert.equal(exchange.status, 400);
  assert.equal((await exchange.json()).error, 'invalid_scope');
});

test('keeps role and permission grants isolated by context', () => {
  assert.deepEqual(getUserRolesForClient(user.id, client.id), ['reader']);
  assert.deepEqual(getUserRolesForClient(user.id, client.id, { contextType: 'tenant', contextId: 'tenant-1' }), ['tenant-reader']);
  assert.deepEqual(userPermissionsForClient(user.id, client.id, { contextType: 'tenant', contextId: 'tenant-1' }), ['reports:read']);
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(tempDir, { recursive: true, force: true });
});
