import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.IAM_DB_PATH ?? path.join(__dirname, '..', 'iam.db');

export const db = new DatabaseSync(DB_PATH);

export const SYSTEM_CLIENT_ID = 'sys_iam';

const SESSION_TTL_MS =
  parseInt(process.env.IAM_SESSION_TTL_HOURS ?? '24', 10) * 60 * 60 * 1000;
const RESET_TTL_MS =
  parseInt(process.env.IAM_RESET_TTL_MINUTES ?? '15', 10) * 60 * 1000;
const CODE_TTL_MS = 10 * 60 * 1000;
const ACCESS_TOKEN_TTL_MS =
  parseInt(process.env.IAM_ACCESS_TOKEN_TTL_MINUTES ?? '60', 10) * 60 * 1000;
const REFRESH_TOKEN_TTL_MS =
  parseInt(process.env.IAM_REFRESH_TOKEN_TTL_HOURS ?? '168', 10) * 60 * 60 * 1000;

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
`);

function tableCols(table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
}

// ---- Schema (fresh installs get the full shape) ----------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL,
    email         TEXT UNIQUE COLLATE NOCASE,
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'inactive', 'suspended')),
    password_hash TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS clients (
    id            TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name          TEXT NOT NULL,
    description   TEXT,
    secret_hash   TEXT,
    redirect_uris TEXT,
    client_type   TEXT NOT NULL DEFAULT 'confidential',
    grant_types   TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]',
    allowed_scopes TEXT NOT NULL DEFAULT '[]',
    is_system     INTEGER NOT NULL DEFAULT 0,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS delegation_policies (
    id                 TEXT PRIMARY KEY,
    source_client_id   TEXT NOT NULL,
    target_client_id   TEXT NOT NULL,
    allowed_scopes     TEXT NOT NULL,
    enabled            INTEGER NOT NULL DEFAULT 1,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    UNIQUE (source_client_id, target_client_id),
    FOREIGN KEY (source_client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (target_client_id) REFERENCES clients(id) ON DELETE CASCADE,
    CHECK (source_client_id != target_client_id)
  );

  CREATE TABLE IF NOT EXISTS authorization_manifests (
    client_id    TEXT PRIMARY KEY,
    version      TEXT NOT NULL,
    checksum     TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS roles (
    id          TEXT PRIMARY KEY,
    client_id   TEXT,
    name        TEXT NOT NULL COLLATE NOCASE,
    description TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (client_id, name),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS permissions (
    id          TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL,
    name        TEXT NOT NULL COLLATE NOCASE,
    description TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (client_id, name),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS user_roles (
    user_id   TEXT NOT NULL,
    role_id   TEXT NOT NULL,
    client_id TEXT,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS role_assignments (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    role_id       TEXT NOT NULL,
    client_id     TEXT,
    context_type  TEXT NOT NULL DEFAULT 'global',
    context_id    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    expires_at    TEXT,
    UNIQUE (user_id, role_id, client_id, context_type, context_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS oauth_consents (
    user_id      TEXT NOT NULL,
    client_id    TEXT NOT NULL,
    scopes       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (user_id, client_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS audit_events (
    id          TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    user_id     TEXT,
    client_id   TEXT,
    success     INTEGER NOT NULL DEFAULT 1,
    metadata    TEXT,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS reset_tokens (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS oauth_codes (
    code         TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    scopes       TEXT,
    redirect_uri TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    nonce        TEXT,
    auth_time    TEXT,
    context_type TEXT NOT NULL DEFAULT 'global',
    context_id   TEXT,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS oauth_tokens (
    token         TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    audience_client_id TEXT,
    user_id       TEXT,
    kind          TEXT NOT NULL DEFAULT 'access',
    scopes        TEXT,
    context_type  TEXT NOT NULL DEFAULT 'global',
    context_id    TEXT,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (audience_client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

function ensureColumn(table, column, definition) {
  if (!tableCols(table).includes(column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

// Keep existing local databases compatible with the expanded OAuth contract.
ensureColumn('clients', 'client_type', "TEXT NOT NULL DEFAULT 'confidential'");
ensureColumn('clients', 'grant_types', "TEXT NOT NULL DEFAULT '[\"authorization_code\",\"refresh_token\"]'");
ensureColumn('clients', 'allowed_scopes', "TEXT NOT NULL DEFAULT '[]'");
ensureColumn('oauth_codes', 'code_challenge', 'TEXT');
ensureColumn('oauth_codes', 'code_challenge_method', 'TEXT');
ensureColumn('oauth_codes', 'nonce', 'TEXT');
ensureColumn('oauth_codes', 'auth_time', 'TEXT');
ensureColumn('oauth_codes', 'context_type', "TEXT NOT NULL DEFAULT 'global'");
ensureColumn('oauth_codes', 'context_id', 'TEXT');
ensureColumn('oauth_tokens', 'context_type', "TEXT NOT NULL DEFAULT 'global'");
ensureColumn('oauth_tokens', 'context_id', 'TEXT');
ensureColumn('oauth_tokens', 'audience_client_id', 'TEXT');
db.exec('UPDATE oauth_tokens SET audience_client_id = client_id WHERE audience_client_id IS NULL');

// ---- Migration: add client scoping to an existing (legacy) database ---------
function migrateClientScoping() {
  const roleCols = tableCols('roles');
  const urCols = tableCols('user_roles');

  const needRolesRebuild = !roleCols.includes('client_id');
  const needUrsRebuild = !urCols.includes('client_id');

  if (!needRolesRebuild && !needUrsRebuild) return;

  db.exec('PRAGMA foreign_keys = OFF');
  db.exec('BEGIN');

  if (needRolesRebuild) {
    db.exec(`
      CREATE TABLE roles_new (
        id          TEXT PRIMARY KEY,
        client_id   TEXT,
        name        TEXT NOT NULL COLLATE NOCASE,
        description TEXT,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        UNIQUE (client_id, name),
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
      );
    `);
    db.exec(`
      INSERT INTO roles_new (id, client_id, name, description, created_at, updated_at)
      SELECT id, NULL, name, description, created_at, updated_at FROM roles
    `);
    db.exec('DROP TABLE roles');
    db.exec('ALTER TABLE roles_new RENAME TO roles');
  }

  if (needUrsRebuild) {
    db.exec(`
      CREATE TABLE user_roles_new (
        user_id   TEXT NOT NULL,
        role_id   TEXT NOT NULL,
        client_id TEXT,
        PRIMARY KEY (user_id, role_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
      );
    `);
    db.exec(`
      INSERT INTO user_roles_new (user_id, role_id, client_id)
      SELECT user_id, role_id, NULL FROM user_roles
    `);
    db.exec('DROP TABLE user_roles');
    db.exec('ALTER TABLE user_roles_new RENAME TO user_roles');
  }

  db.exec('COMMIT');
  db.exec('PRAGMA foreign_keys = ON');
}

migrateClientScoping();

// Preserve existing user-role grants while adding explicit context support.
db.exec(`
  INSERT OR IGNORE INTO role_assignments
    (id, user_id, role_id, client_id, context_type, context_id, created_at)
  SELECT lower(hex(randomblob(16))), user_id, role_id, client_id, 'global', '', datetime('now')
  FROM user_roles
`);
db.exec(`
  DELETE FROM role_assignments
  WHERE rowid NOT IN (
    SELECT MIN(rowid)
    FROM role_assignments
    GROUP BY user_id, role_id, client_id, context_type, COALESCE(context_id, '')
  )
`);
db.exec("UPDATE role_assignments SET context_id = '' WHERE context_id IS NULL");
db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS role_assignments_context_unique
  ON role_assignments (user_id, role_id, client_id, context_type, COALESCE(context_id, ''))
`);

const stmts = {
  // clients
  clientById: db.prepare('SELECT * FROM clients WHERE id = ?'),
  clientByPublicId: db.prepare('SELECT * FROM clients WHERE client_id = ?'),
  listClients: db.prepare('SELECT * FROM clients ORDER BY name'),
  insertClient: db.prepare(`
    INSERT INTO clients (id, client_id, name, description, secret_hash, redirect_uris, client_type, grant_types, allowed_scopes, is_system, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  updateClient: db.prepare(`
    UPDATE clients SET name = ?, description = ?, redirect_uris = ?, client_type = ?, grant_types = ?, allowed_scopes = ?, enabled = ?, updated_at = ? WHERE id = ?
  `),
  setClientSecret: db.prepare('UPDATE clients SET secret_hash = ?, updated_at = ? WHERE id = ?'),
  deleteClient: db.prepare('DELETE FROM clients WHERE id = ?'),

  // delegated application access
  delegationPolicyBySourceTarget: db.prepare('SELECT * FROM delegation_policies WHERE source_client_id = ? AND target_client_id = ?'),
  listDelegationPoliciesBySource: db.prepare('SELECT * FROM delegation_policies WHERE source_client_id = ? ORDER BY created_at'),
  insertDelegationPolicy: db.prepare(`
    INSERT INTO delegation_policies (id, source_client_id, target_client_id, allowed_scopes, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `),
  deleteDelegationPolicy: db.prepare('DELETE FROM delegation_policies WHERE id = ?'),

  // Application-owned authorization manifests
  authorizationManifestByClient: db.prepare('SELECT * FROM authorization_manifests WHERE client_id = ?'),
  upsertAuthorizationManifest: db.prepare(`
    INSERT INTO authorization_manifests (client_id, version, checksum, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(client_id) DO UPDATE SET
      version = excluded.version,
      checksum = excluded.checksum,
      updated_at = excluded.updated_at
  `),

  // roles (client-scoped)
  roleById: db.prepare('SELECT * FROM roles WHERE id = ?'),
  roleByNameInClient: db.prepare('SELECT * FROM roles WHERE client_id = ? AND name = ?'),
  listRolesByClient: db.prepare('SELECT * FROM roles WHERE client_id = ? ORDER BY name'),
  insertRole: db.prepare(`
    INSERT INTO roles (id, client_id, name, description, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
  updateRole: db.prepare('UPDATE roles SET name = ?, description = ?, updated_at = ? WHERE id = ?'),
  deleteRole: db.prepare('DELETE FROM roles WHERE id = ?'),
  roleUsage: db.prepare('SELECT COUNT(*) AS n FROM role_assignments WHERE role_id = ?'),
  adminsCount: db.prepare(`
    SELECT COUNT(*) AS n FROM role_assignments ur
    JOIN roles r ON r.id = ur.role_id
    JOIN users u ON u.id = ur.user_id
    WHERE r.name = 'admin' AND r.client_id = ? AND ur.context_type = 'global'
      AND ur.context_id = '' AND u.status = 'active'
  `),

  // permissions
  permissionById: db.prepare('SELECT * FROM permissions WHERE id = ?'),
  permissionByNameInClient: db.prepare('SELECT * FROM permissions WHERE client_id = ? AND name = ?'),
  listPermissionsByClient: db.prepare('SELECT * FROM permissions WHERE client_id = ? ORDER BY name'),
  insertPermission: db.prepare(`
    INSERT INTO permissions (id, client_id, name, description, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
  updatePermission: db.prepare('UPDATE permissions SET name = ?, description = ?, updated_at = ? WHERE id = ?'),
  deletePermission: db.prepare('DELETE FROM permissions WHERE id = ?'),
  rolePermissions: db.prepare(`
    SELECT p.* FROM permissions p
    JOIN role_permissions rp ON rp.permission_id = p.id
    WHERE rp.role_id = ? ORDER BY p.name
  `),
  permissionUsage: db.prepare('SELECT COUNT(*) AS n FROM role_permissions WHERE permission_id = ?'),
  clearRolePermissions: db.prepare('DELETE FROM role_permissions WHERE role_id = ?'),
  addRolePermission: db.prepare('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)'),

  // assignments
  allUserAssignments: db.prepare(`
    SELECT r.name, r.client_id, ur.context_type, ur.context_id FROM roles r
    JOIN role_assignments ur ON ur.role_id = r.id
    WHERE ur.user_id = ? AND (ur.expires_at IS NULL OR ur.expires_at > datetime('now'))
    ORDER BY r.name
  `),
  userRolesForClient: db.prepare(`
    SELECT r.name FROM roles r
    JOIN role_assignments ur ON ur.role_id = r.id
    WHERE ur.user_id = ? AND r.client_id = ? AND (ur.client_id = ? OR ur.client_id IS NULL)
      AND ur.context_type = ? AND ur.context_id = ?
      AND (ur.expires_at IS NULL OR ur.expires_at > datetime('now'))
    ORDER BY r.name
  `),
  globalUserRoleNames: db.prepare(`
    SELECT DISTINCT r.name FROM roles r
    JOIN role_assignments ur ON ur.role_id = r.id
    WHERE ur.user_id = ?
    ORDER BY r.name
  `),
  assignRole: db.prepare('INSERT INTO role_assignments (id, user_id, role_id, client_id, context_type, context_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  clearUserRolesForClient: db.prepare('DELETE FROM role_assignments WHERE user_id = ? AND client_id = ? AND context_type = ? AND context_id = ?'),
  clearAllUserRoles: db.prepare('DELETE FROM role_assignments WHERE user_id = ?'),
  userPermissionsForClient: db.prepare(`
    SELECT DISTINCT p.name FROM permissions p
    JOIN role_permissions rp ON rp.permission_id = p.id
    JOIN roles r ON r.id = rp.role_id
    JOIN role_assignments ur ON ur.role_id = r.id
    WHERE ur.user_id = ? AND r.client_id = ? AND (ur.client_id = ? OR ur.client_id IS NULL)
      AND ur.context_type = ? AND ur.context_id = ?
      AND (ur.expires_at IS NULL OR ur.expires_at > datetime('now'))
    ORDER BY p.name
  `),

  // users
  list: db.prepare('SELECT * FROM users ORDER BY created_at'),
  byId: db.prepare('SELECT * FROM users WHERE id = ?'),
  byUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  byEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  insert: db.prepare(`
    INSERT INTO users (id, username, display_name, email, status, password_hash, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `),
  update: db.prepare(`
    UPDATE users SET display_name = ?, email = ?, status = ?, updated_at = ? WHERE id = ?
  `),
  setPassword: db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?'),
  remove: db.prepare('DELETE FROM users WHERE id = ?'),

  // sessions / reset tokens
  insertSession: db.prepare(`
    INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)
  `),
  sessionByToken: db.prepare('SELECT * FROM sessions WHERE token = ?'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  deleteExpiredSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
  deleteUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
  resetTokenByToken: db.prepare('SELECT * FROM reset_tokens WHERE token = ?'),
  insertResetToken: db.prepare(`
    INSERT INTO reset_tokens (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)
  `),
  deleteResetToken: db.prepare('DELETE FROM reset_tokens WHERE token = ?'),
  deleteExpiredResetTokens: db.prepare('DELETE FROM reset_tokens WHERE expires_at <= ?'),

  // oauth
  oauthCodeByCode: db.prepare('SELECT * FROM oauth_codes WHERE code = ?'),
  insertOauthCode: db.prepare(`
    INSERT INTO oauth_codes (code, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, nonce, auth_time, context_type, context_id, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  deleteOauthCode: db.prepare('DELETE FROM oauth_codes WHERE code = ?'),
  oauthTokenByToken: db.prepare('SELECT * FROM oauth_tokens WHERE token = ?'),
  insertOauthToken: db.prepare(`
    INSERT INTO oauth_tokens (token, client_id, audience_client_id, user_id, kind, scopes, context_type, context_id, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  deleteOauthToken: db.prepare('DELETE FROM oauth_tokens WHERE token = ?'),
  deleteUserOauthTokens: db.prepare('DELETE FROM oauth_tokens WHERE user_id = ?'),
  deleteClientOauthTokens: db.prepare('DELETE FROM oauth_tokens WHERE client_id = ?'),
  deleteExpiredOauthTokens: db.prepare('DELETE FROM oauth_tokens WHERE expires_at <= ?'),
  deleteExpiredOauthCodes: db.prepare('DELETE FROM oauth_codes WHERE expires_at <= ?'),
  consentByUserClient: db.prepare('SELECT * FROM oauth_consents WHERE user_id = ? AND client_id = ?'),
  upsertConsent: db.prepare(`
    INSERT INTO oauth_consents (user_id, client_id, scopes, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id, client_id) DO UPDATE SET scopes = excluded.scopes, updated_at = excluded.updated_at
  `),
  insertAuditEvent: db.prepare(`
    INSERT INTO audit_events (id, event_type, user_id, client_id, success, metadata, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `),
  listAuditEvents: db.prepare('SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ? OFFSET ?'),
};

// ---------------------------------------------------------------------------
// Secrets / helpers
// ---------------------------------------------------------------------------

function now() {
  return new Date().toISOString();
}

function hashSecret(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifySecret(plain, stored) {
  if (!plain || !stored) return false;
  const [salt, hash] = stored.split(':');
  const candidate = crypto.scryptSync(plain, salt, 64).toString('hex');
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function hashPassword(plain) {
  return hashSecret(plain);
}

// ---------------------------------------------------------------------------
// System client bootstrap
// ---------------------------------------------------------------------------

function ensureSystemClient() {
  const existing = stmts.clientById.get(SYSTEM_CLIENT_ID);
  if (!existing) {
    stmts.insertClient.run(
      SYSTEM_CLIENT_ID,
      'iam',
      'IAM Console',
      'Built-in system client for the IAM platform itself',
      null,
      null,
      'public',
      '[]',
      '[]',
      1,
      1,
      now(),
      now(),
    );
  }
  // Backfill legacy rows (migration) + seed system roles
  db.prepare('UPDATE roles SET client_id = ? WHERE client_id IS NULL').run(SYSTEM_CLIENT_ID);
  db.prepare('UPDATE user_roles SET client_id = ? WHERE client_id IS NULL').run(SYSTEM_CLIENT_ID);
  db.prepare('UPDATE role_assignments SET client_id = ? WHERE client_id IS NULL').run(SYSTEM_CLIENT_ID);
}

function ensureDefaultRoles() {
  const defaults = [
    { name: 'admin', description: 'Full system administrator' },
    { name: 'member', description: 'Default role for new users' },
  ];
  for (const role of defaults) {
    if (!stmts.roleByNameInClient.get(SYSTEM_CLIENT_ID, role.name)) {
      stmts.insertRole.run(crypto.randomUUID(), SYSTEM_CLIENT_ID, role.name, role.description, now(), now());
    }
  }
}

function ensureIntegrityTriggers() {
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS role_permissions_client_guard
    BEFORE INSERT ON role_permissions
    WHEN (SELECT client_id FROM roles WHERE id = NEW.role_id) IS NULL
      OR (SELECT client_id FROM permissions WHERE id = NEW.permission_id) IS NULL
      OR (SELECT client_id FROM roles WHERE id = NEW.role_id) != (SELECT client_id FROM permissions WHERE id = NEW.permission_id)
    BEGIN SELECT RAISE(ABORT, 'role and permission must belong to the same client'); END;

    CREATE TRIGGER IF NOT EXISTS role_permissions_client_update_guard
    BEFORE UPDATE OF role_id, permission_id ON role_permissions
    WHEN (SELECT client_id FROM roles WHERE id = NEW.role_id) IS NULL
      OR (SELECT client_id FROM permissions WHERE id = NEW.permission_id) IS NULL
      OR (SELECT client_id FROM roles WHERE id = NEW.role_id) != (SELECT client_id FROM permissions WHERE id = NEW.permission_id)
    BEGIN SELECT RAISE(ABORT, 'role and permission must belong to the same client'); END;

    CREATE TRIGGER IF NOT EXISTS role_assignments_client_guard
    BEFORE INSERT ON role_assignments
    WHEN NEW.client_id IS NULL
      OR (SELECT client_id FROM roles WHERE id = NEW.role_id) != NEW.client_id
    BEGIN SELECT RAISE(ABORT, 'role assignment must belong to the role client'); END;

    CREATE TRIGGER IF NOT EXISTS role_assignments_client_update_guard
    BEFORE UPDATE OF role_id, client_id ON role_assignments
    WHEN NEW.client_id IS NULL
      OR (SELECT client_id FROM roles WHERE id = NEW.role_id) != NEW.client_id
    BEGIN SELECT RAISE(ABORT, 'role assignment must belong to the role client'); END;
  `);
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

function toClientDto(client) {
  if (!client) return null;
  const { secret_hash, ...rest } = client;
  rest.has_secret = !!secret_hash;
  rest.redirect_uris = rest.redirect_uris ? JSON.parse(rest.redirect_uris) : [];
  rest.grant_types = rest.grant_types ? JSON.parse(rest.grant_types) : [];
  rest.allowed_scopes = rest.allowed_scopes ? JSON.parse(rest.allowed_scopes) : [];
  rest.is_system = !!rest.is_system;
  rest.enabled = !!rest.enabled;
  return rest;
}

export function listClients() {
  return stmts.listClients.all().map(toClientDto);
}

export function getClientById(id) {
  return toClientDto(stmts.clientById.get(id));
}

export function getClientByPublicId(publicId) {
  return toClientDto(stmts.clientByPublicId.get(publicId));
}

export function verifyClientSecret(publicId, secret) {
  const client = stmts.clientByPublicId.get(publicId);
  if (!client || !client.enabled) return null;
  if (!verifySecret(secret, client.secret_hash)) return null;
  return toClientDto(client);
}

export function createClient({ clientId, name, description, secret, redirectUris, clientType, grantTypes, allowedScopes }) {
  const client = {
    id: crypto.randomUUID(),
    client_id: clientId.trim(),
    name: name.trim(),
    description: description ?? null,
    secret_hash: secret ? hashSecret(secret) : null,
    redirect_uris: redirectUris?.length ? JSON.stringify(redirectUris) : null,
    client_type: clientType ?? 'confidential',
    grant_types: JSON.stringify(grantTypes ?? ['authorization_code', 'refresh_token']),
    allowed_scopes: JSON.stringify(allowedScopes ?? []),
    is_system: 0,
    enabled: 1,
    created_at: now(),
    updated_at: now(),
  };
  stmts.insertClient.run(
    client.id,
    client.client_id,
    client.name,
    client.description,
    client.secret_hash,
    client.redirect_uris,
    client.client_type,
    client.grant_types,
    client.allowed_scopes,
    client.is_system,
    client.enabled,
    client.created_at,
    client.updated_at,
  );
  return toClientDto(client);
}

export function updateClient(id, { name, description, redirectUris, clientId, clientType, grantTypes, allowedScopes, enabled }) {
  const row = stmts.clientById.get(id);
  if (!row) return null;
  if (clientId && row.is_system) return { error: 'Cannot change the system client identifier' };
  if (clientId && clientId !== row.client_id) {
    const clash = stmts.clientByPublicId.get(clientId);
    if (clash && clash.id !== id) return { error: 'client_id already exists' };
  }
  stmts.updateClient.run(
    name ?? row.name,
    description !== undefined ? description : row.description,
    redirectUris !== undefined ? JSON.stringify(redirectUris) : row.redirect_uris,
    clientType ?? row.client_type,
    grantTypes !== undefined ? JSON.stringify(grantTypes) : row.grant_types,
    allowedScopes !== undefined ? JSON.stringify(allowedScopes) : row.allowed_scopes,
    enabled !== undefined ? (enabled ? 1 : 0) : row.enabled,
    now(),
    id,
  );
  if (clientId && clientId !== row.client_id) {
    db.prepare('UPDATE clients SET client_id = ? WHERE id = ?').run(clientId.trim(), id);
  }
  return getClientById(id);
}

export function rotateClientSecret(id) {
  const row = stmts.clientById.get(id);
  if (!row) return null;
  const secret = crypto.randomBytes(24).toString('base64url');
  stmts.setClientSecret.run(hashSecret(secret), now(), id);
  return { secret };
}

export function deleteClient(id) {
  const row = stmts.clientById.get(id);
  if (!row) return { error: 'Client not found' };
  if (row.is_system) return { error: 'Cannot delete the system client' };
  stmts.deleteUserOauthTokens.run(null);
  stmts.deleteClientOauthTokens.run(id);
  return { ok: stmts.deleteClient.run(id).changes > 0 };
}

// ---------------------------------------------------------------------------
// Delegation policies (source client -> target audience)
// ---------------------------------------------------------------------------

function parseDelegationPolicy(row) {
  if (!row) return null;
  return {
    ...row,
    allowed_scopes: row.allowed_scopes ? JSON.parse(row.allowed_scopes) : [],
    enabled: !!row.enabled,
  };
}

export function getDelegationPolicy(sourceClientId, targetClientId) {
  return parseDelegationPolicy(stmts.delegationPolicyBySourceTarget.get(sourceClientId, targetClientId));
}

export function listDelegationPolicies(sourceClientId) {
  return stmts.listDelegationPoliciesBySource.all(sourceClientId).map(parseDelegationPolicy);
}

export function createDelegationPolicy({ sourceClientId, targetClientId, allowedScopes }) {
  if (!stmts.clientById.get(sourceClientId) || !stmts.clientById.get(targetClientId)) {
    return { error: 'Source or target client not found' };
  }
  if (sourceClientId === targetClientId) return { error: 'Source and target clients must be different' };
  if (getDelegationPolicy(sourceClientId, targetClientId)) {
    return { error: 'Delegation policy already exists' };
  }
  const id = crypto.randomUUID();
  const timestamp = now();
  stmts.insertDelegationPolicy.run(
    id,
    sourceClientId,
    targetClientId,
    JSON.stringify([...new Set(allowedScopes)]),
    1,
    timestamp,
    timestamp,
  );
  return getDelegationPolicy(sourceClientId, targetClientId);
}

export function deleteDelegationPolicy(id) {
  return stmts.deleteDelegationPolicy.run(id).changes > 0;
}

function authorizationManifestDto(clientId, manifestRow) {
  if (!manifestRow) return null;
  const permissions = listPermissions(clientId).map(({ id, client_id, created_at, updated_at, ...permission }) => ({
    ...permission,
  }));
  const roles = listRoles(clientId).map(({ id, client_id, created_at, updated_at, ...role }) => ({
    ...role,
    permissions: getRolePermissions(id).map((permission) => permission.name),
  }));
  return {
    version: manifestRow.version,
    checksum: manifestRow.checksum,
    permissions,
    roles,
    createdAt: manifestRow.created_at,
    updatedAt: manifestRow.updated_at,
  };
}

export function getAuthorizationManifest(clientId) {
  return authorizationManifestDto(clientId, stmts.authorizationManifestByClient.get(clientId));
}

/**
 * Reconcile an application-owned authorization manifest.
 *
 * Reconciliation is intentionally additive/non-destructive. Existing roles and
 * permissions keep their stable IAM IDs and assignments. Definitions omitted
 * from a newer manifest remain available until an explicit administrative
 * deprecation/removal workflow is implemented.
 */
export function reconcileAuthorizationManifest({ clientId, version, permissions, roles }) {
  const client = stmts.clientById.get(clientId);
  if (!client) return { error: 'Client not found' };

  const timestamp = now();
  const permissionIds = new Map();
  const manifest = {
    version,
    permissions: permissions.map(({ name, description }) => ({ name, description: description ?? null })),
    roles: roles.map(({ name, description, permissions: rolePermissions }) => ({
      name,
      description: description ?? null,
      permissions: [...rolePermissions],
    })),
  };
  const checksum = crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex');

  try {
    db.exec('BEGIN');
    for (const permission of manifest.permissions) {
      const existing = stmts.permissionByNameInClient.get(clientId, permission.name);
      if (existing) {
        stmts.updatePermission.run(permission.name, permission.description, timestamp, existing.id);
        permissionIds.set(permission.name, existing.id);
      } else {
        const id = crypto.randomUUID();
        stmts.insertPermission.run(id, clientId, permission.name, permission.description, timestamp, timestamp);
        permissionIds.set(permission.name, id);
      }
    }

    for (const role of manifest.roles) {
      const existing = stmts.roleByNameInClient.get(clientId, role.name);
      const roleId = existing?.id ?? crypto.randomUUID();
      if (existing) {
        stmts.updateRole.run(role.name, role.description, timestamp, roleId);
      } else {
        stmts.insertRole.run(roleId, clientId, role.name, role.description, timestamp, timestamp);
      }
      stmts.clearRolePermissions.run(roleId);
      for (const permissionName of role.permissions) {
        stmts.addRolePermission.run(roleId, permissionIds.get(permissionName));
      }
    }

    const declaredScopes = manifest.permissions.map(({ name }) => name);
    const existingScopes = client.allowed_scopes ? JSON.parse(client.allowed_scopes) : [];
    const allowedScopes = [...new Set([...existingScopes, ...declaredScopes])];
    stmts.updateClient.run(
      client.name,
      client.description,
      client.redirect_uris,
      client.client_type,
      client.grant_types,
      JSON.stringify(allowedScopes),
      client.enabled,
      timestamp,
      clientId,
    );
    stmts.upsertAuthorizationManifest.run(
      clientId,
      version,
      checksum,
      stmts.authorizationManifestByClient.get(clientId)?.created_at ?? timestamp,
      timestamp,
    );
    db.exec('COMMIT');
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch { /* preserve the original failure */ }
    throw error;
  }

  return authorizationManifestDto(clientId, stmts.authorizationManifestByClient.get(clientId));
}

// ---------------------------------------------------------------------------
// Roles (client-scoped)
// ---------------------------------------------------------------------------

export function isRoleNameTakenInClient(name, clientId, excludeId) {
  const row = stmts.roleByNameInClient.get(clientId, name);
  return !!row && row.id !== (excludeId ?? null);
}

export function listRoles(clientId) {
  return stmts.listRolesByClient.all(clientId).map((r) => ({ ...r }));
}

export function getRole(id) {
  const row = stmts.roleById.get(id);
  if (!row) return null;
  return { ...row };
}

export function createRole({ clientId, name, description, permissionIds }) {
  const role = {
    id: crypto.randomUUID(),
    client_id: clientId,
    name,
    description: description ?? null,
    created_at: now(),
    updated_at: now(),
  };
  stmts.insertRole.run(role.id, role.client_id, role.name, role.description, role.created_at, role.updated_at);
  const updated = getRole(role.id);
  if (permissionIds) setRolePermissions(role.id, permissionIds);
  return updated;
}

export function updateRole(id, { name, description, permissionIds }) {
  const row = stmts.roleById.get(id);
  if (!row) return null;
  stmts.updateRole.run(name ?? row.name, description ?? row.description, now(), id);
  if (permissionIds) setRolePermissions(id, permissionIds);
  return getRole(id);
}

export function deleteRole(id) {
  return stmts.deleteRole.run(id).changes > 0;
}

export function countRoleUsers(roleId) {
  return stmts.roleUsage.get(roleId).n;
}

export function countActiveAdmins() {
  return stmts.adminsCount.get(SYSTEM_CLIENT_ID).n;
}

export function getRolePermissions(roleId) {
  return stmts.rolePermissions.all(roleId).map(({ password_hash, ...p }) => ({ ...p }));
}

export function setRolePermissions(roleId, permissionIds) {
  const role = stmts.roleById.get(roleId);
  if (!role) return;
  stmts.clearRolePermissions.run(roleId);
  for (const id of permissionIds) {
    const permission = stmts.permissionById.get(id);
    if (permission && permission.client_id === role.client_id) {
      stmts.addRolePermission.run(roleId, id);
    }
  }
}

// ---------------------------------------------------------------------------
// Permissions (client-scoped)
// ---------------------------------------------------------------------------

export function listPermissions(clientId) {
  return stmts.listPermissionsByClient.all(clientId).map((p) => ({ ...p }));
}

export function getPermission(id) {
  const row = stmts.permissionById.get(id);
  if (!row) return null;
  return { ...row };
}

export function isPermissionNameTakenInClient(name, clientId, excludeId) {
  const row = stmts.permissionByNameInClient.get(clientId, name);
  return !!row && row.id !== (excludeId ?? null);
}

export function createPermission({ clientId, name, description }) {
  const perm = {
    id: crypto.randomUUID(),
    client_id: clientId,
    name,
    description: description ?? null,
    created_at: now(),
    updated_at: now(),
  };
  stmts.insertPermission.run(perm.id, perm.client_id, perm.name, perm.description, perm.created_at, perm.updated_at);
  return getPermission(perm.id);
}

export function updatePermission(id, { name, description }) {
  const row = stmts.permissionById.get(id);
  if (!row) return null;
  stmts.updatePermission.run(name ?? row.name, description ?? row.description, now(), id);
  return getPermission(id);
}

export function deletePermission(id) {
  return stmts.deletePermission.run(id).changes > 0;
}

export function countPermissionUsage(permissionId) {
  return stmts.permissionUsage.get(permissionId).n;
}

// ---------------------------------------------------------------------------
// User DTO + assignments
// ---------------------------------------------------------------------------

function assignmentContext(context = {}) {
  return {
    contextType: context.contextType ?? context.context_type ?? 'global',
    contextId: context.contextId ?? context.context_id ?? '',
  };
}

export function userPermissionsForClient(userId, clientId, context) {
  const { contextType, contextId } = assignmentContext(context);
  return stmts.userPermissionsForClient.all(userId, clientId, clientId, contextType, contextId).map((r) => r.name);
}

export function toUserDto(row, opts = {}) {
  if (!row) return null;
  const { password_hash, ...user } = row;
  const clientId = opts.clientId ?? SYSTEM_CLIENT_ID;
  const context = assignmentContext(opts);
  const grants = {};
  for (const a of stmts.allUserAssignments.all(user.id)) {
    (grants[a.client_id] ??= []).push(a.name);
  }
  user.roles = stmts.userRolesForClient.all(user.id, clientId, clientId, context.contextType, context.contextId).map((r) => r.name);
  user.grants = grants;
  user.permissions = userPermissionsForClient(user.id, clientId, context);
  return user;
}

export function getUserRolesForClient(userId, clientId, context) {
  const { contextType, contextId } = assignmentContext(context);
  return stmts.userRolesForClient.all(userId, clientId, clientId, contextType, contextId).map((r) => r.name);
}

export function setUserRolesForClient(userId, clientId, roleNames, context) {
  const { contextType, contextId } = assignmentContext(context);
  stmts.clearUserRolesForClient.run(userId, clientId, contextType, contextId);
  for (const name of roleNames) {
    const role = stmts.roleByNameInClient.get(clientId, name);
    if (role) stmts.assignRole.run(crypto.randomUUID(), userId, role.id, clientId, contextType, contextId, now());
  }
  return toUserDto(stmts.byId.get(userId), { clientId, contextType, contextId });
}

export function setUserRoles(userId, roles) {
  return setUserRolesForClient(userId, SYSTEM_CLIENT_ID, roles);
}

export function getAllUserGrants(userId) {
  const grants = {};
  for (const a of stmts.allUserAssignments.all(userId)) {
    (grants[a.client_id] ??= []).push(a.name);
  }
  return grants;
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export function listUsers() {
  return stmts.list.all().map((row) => toUserDto(row));
}

export function getUser(id, opts) {
  return toUserDto(stmts.byId.get(id), opts);
}

export function getUserByUsername(username) {
  return stmts.byUsername.get(username);
}

export function verifyPassword(username, plain) {
  const row = stmts.byUsername.get(username);
  if (!row || !row.password_hash) return null;
  if (row.status !== 'active') return null;
  const [salt, hash] = row.password_hash.split(':');
  const candidate = crypto.scryptSync(plain ?? '', salt, 64).toString('hex');
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return toUserDto(row);
}

export function createUser({ username, displayName, email, status, password, roles }) {
  const user = {
    id: crypto.randomUUID(),
    username,
    display_name: displayName,
    email: email ?? null,
    status: status ?? 'active',
    password_hash: password ? hashPassword(password) : null,
    created_at: now(),
    updated_at: now(),
  };
  stmts.insert.run(
    user.id,
    user.username,
    user.display_name,
    user.email,
    user.status,
    user.password_hash,
    user.created_at,
    user.updated_at,
  );
  const roleNames = roles && roles.length ? roles : ['member'];
  for (const name of roleNames) {
    const role = stmts.roleByNameInClient.get(SYSTEM_CLIENT_ID, name);
    if (role) stmts.assignRole.run(crypto.randomUUID(), user.id, role.id, SYSTEM_CLIENT_ID, 'global', '', now());
  }
  return toUserDto(user);
}

export function updateUser(id, fields) {
  const row = stmts.byId.get(id);
  if (!row) return null;
  stmts.update.run(
    fields.displayName ?? row.display_name,
    fields.email ?? row.email,
    fields.status ?? row.status,
    now(),
    id,
  );
  if (fields.password) stmts.setPassword.run(hashPassword(fields.password), now(), id);
  if (fields.roles) setUserRoles(id, fields.roles);
  return toUserDto(stmts.byId.get(id));
}

export function deleteUser(id) {
  return stmts.remove.run(id).changes > 0;
}

export function isUsernameTaken(username, excludeId) {
  const row = stmts.byUsername.get(username);
  return !!row && row.id !== (excludeId ?? null);
}

export function isEmailTaken(email, excludeId) {
  if (!email) return false;
  const row = stmts.byEmail.get(email);
  return !!row && row.id !== (excludeId ?? null);
}

// ---------------------------------------------------------------------------
// Password change / recovery
// ---------------------------------------------------------------------------

export function changePassword(userId, current, next) {
  const row = stmts.byId.get(userId);
  if (!row || !row.password_hash) return { error: 'This account has no password to change' };
  const [salt, hash] = row.password_hash.split(':');
  const candidate = crypto.scryptSync(current ?? '', salt, 64).toString('hex');
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { error: 'Current password is incorrect' };
  }
  if (next === current) return { error: 'New password must be different from the current password' };
  stmts.setPassword.run(hashPassword(next), now(), userId);
  return { ok: true };
}

export function createResetTokenForUsername(username) {
  const row = stmts.byUsername.get(username);
  if (!row || !row.email || !row.password_hash) return null;
  const token = crypto.randomBytes(32).toString('base64url');
  const created = new Date();
  const expires = new Date(created.getTime() + RESET_TTL_MS);
  stmts.insertResetToken.run(token, row.id, created.toISOString(), expires.toISOString());
  return { token, expiresAt: expires.toISOString(), userId: row.id, username: row.username, email: row.email };
}

export function resetPasswordByToken(token, username, newPlain) {
  const row = stmts.resetTokenByToken.get(token);
  if (!row) return { error: 'Invalid or expired reset token' };
  if (new Date(row.expires_at) <= new Date()) {
    stmts.deleteResetToken.run(token);
    return { error: 'Invalid or expired reset token' };
  }
  const user = stmts.byId.get(row.user_id);
  if (!user || user.username.toLowerCase() !== String(username ?? '').toLowerCase()) {
    return { error: 'Username does not match the reset token' };
  }
  stmts.setPassword.run(hashPassword(newPlain), now(), user.id);
  stmts.deleteResetToken.run(token);
  stmts.deleteUserSessions.run(user.id);
  stmts.deleteUserOauthTokens.run(user.id);
  return { ok: true, user: toUserDto(user) };
}

export function getUsernameByEmail(email) {
  const row = stmts.byEmail.get(email);
  if (!row) return null;
  return row.username;
}

export function cleanupResetTokens() {
  stmts.deleteExpiredResetTokens.run(new Date().toISOString());
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const created = new Date();
  const expires = new Date(created.getTime() + SESSION_TTL_MS);
  stmts.insertSession.run(token, userId, created.toISOString(), expires.toISOString());
  return { token, expiresAt: expires.toISOString() };
}

export function getSession(token) {
  const row = stmts.sessionByToken.get(token);
  if (!row) return null;
  if (new Date(row.expires_at) <= new Date()) {
    stmts.deleteSession.run(token);
    return null;
  }
  return toUserDto(stmts.byId.get(row.user_id));
}

export function deleteSession(token) {
  stmts.deleteSession.run(token);
}

export function deleteAllUserSessions(userId) {
  stmts.deleteUserSessions.run(userId);
}

export function cleanupSessions() {
  stmts.deleteExpiredSessions.run(new Date().toISOString());
}

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

export function createAuthorizationCode({ clientId, userId, scopes, redirectUri, codeChallenge, codeChallengeMethod, nonce, authTime, contextType = 'global', contextId = null }) {
  const code = crypto.randomBytes(24).toString('base64url');
  const created = new Date();
  const expires = new Date(created.getTime() + CODE_TTL_MS);
  stmts.insertOauthCode.run(
    code,
    clientId,
    userId,
    JSON.stringify(scopes),
    redirectUri,
    codeChallenge ?? null,
    codeChallengeMethod ?? null,
    nonce ?? null,
    authTime ?? created.toISOString(),
    contextType,
    contextId,
    created.toISOString(),
    expires.toISOString(),
  );
  return { code, expiresAt: expires.toISOString() };
}

export function getAuthorizationCode(code) {
  const row = stmts.oauthCodeByCode.get(code);
  if (!row) return null;
  if (new Date(row.expires_at) <= new Date()) {
    stmts.deleteOauthCode.run(code);
    return null;
  }
  return { ...row, scopes: row.scopes ? JSON.parse(row.scopes) : [] };
}

export function consumeAuthorizationCode(code) {
  stmts.deleteOauthCode.run(code);
}

export function createOauthToken({ clientId, audienceClientId = clientId, userId, scopes, kind, contextType = 'global', contextId = null }) {
  const token = crypto.randomBytes(32).toString('base64url');
  const created = new Date();
  const ttl = kind === 'refresh' ? REFRESH_TOKEN_TTL_MS : ACCESS_TOKEN_TTL_MS;
  const expires = new Date(created.getTime() + ttl);
  stmts.insertOauthToken.run(token, clientId, audienceClientId, userId ?? null, kind, JSON.stringify(scopes), contextType, contextId, created.toISOString(), expires.toISOString());
  return { token, expiresIn: Math.floor(ttl / 1000), expiresAt: expires.toISOString() };
}

export function getOauthToken(token) {
  const row = stmts.oauthTokenByToken.get(token);
  if (!row) return null;
  if (new Date(row.expires_at) <= new Date()) {
    stmts.deleteOauthToken.run(token);
    return null;
  }
  return { ...row, scopes: row.scopes ? JSON.parse(row.scopes) : [] };
}

export function recordAuditEvent({ eventType, userId = null, clientId = null, success = true, metadata = {} }) {
  stmts.insertAuditEvent.run(
    crypto.randomUUID(),
    eventType,
    userId,
    clientId,
    success ? 1 : 0,
    JSON.stringify(metadata),
    now(),
  );
}

export function listAuditEvents({ limit = 100, offset = 0 } = {}) {
  return stmts.listAuditEvents.all(limit, offset).map((event) => ({
    ...event,
    success: !!event.success,
    metadata: event.metadata ? JSON.parse(event.metadata) : {},
  }));
}

export function getOauthConsent(userId, clientId) {
  const row = stmts.consentByUserClient.get(userId, clientId);
  return row ? (row.scopes ? JSON.parse(row.scopes) : []) : [];
}

export function saveOauthConsent(userId, clientId, scopes) {
  const timestamp = now();
  stmts.upsertConsent.run(userId, clientId, JSON.stringify([...new Set(scopes)]), timestamp, timestamp);
}

export function deleteOauthToken(token) {
  stmts.deleteOauthToken.run(token);
}

export function cleanupOauth() {
  stmts.deleteExpiredOauthTokens.run(new Date().toISOString());
  stmts.deleteExpiredOauthCodes.run(new Date().toISOString());
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

export function bootstrapAdmin() {
  ensureSystemClient();
  ensureDefaultRoles();
  ensureIntegrityTriggers();
  ensureSystemClient();

  const username = (process.env.IAM_ADMIN_USERNAME ?? 'admin').trim();
  const existing = getUserByUsername(username);
  if (existing && !getUserRolesForClient(existing.id, SYSTEM_CLIENT_ID).length) {
    setUserRoles(existing.id, ['admin']);
    console.log(`[bootstrap] Granted "admin" role to existing user "${username}"`);
  }
  if (existing) return false;

  const configuredPassword = process.env.IAM_ADMIN_PASSWORD;
  if (process.env.NODE_ENV === 'production' && (!configuredPassword || configuredPassword.length < 12)) {
    throw new Error('IAM_ADMIN_PASSWORD must be configured with at least 12 characters in production');
  }

  const user = createUser({
    username,
    displayName: 'Administrator',
    email: null,
    status: 'active',
    password: configuredPassword ?? 'admin123',
    roles: ['admin'],
  });
  console.log(`[bootstrap] Created default admin user "${username}" with admin role`);
  return true;
}

bootstrapAdmin();
cleanupSessions();
cleanupResetTokens();
cleanupOauth();
