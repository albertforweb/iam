import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createClient,
  getClientByPublicId,
  updateClient,
  clearClientSecret,
  verifyClientSecret,
  reconcileAuthorizationManifest,
  getUserByUsername,
  setUserRolesForClient,
  recordAuditEvent,
} from './db.js';

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_APPLICATIONS_CONFIG = path.join(ROOT_DIR, 'applications.json');
export const DEFAULT_VAULTS_FILE = path.join(ROOT_DIR, '.vaults');

const CLIENT_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const PERMISSION_RE = /^[A-Za-z0-9_:.-]{1,80}$/;
const ROLE_RE = /^[A-Za-z0-9_-]{1,50}$/;
const GRANTS = new Set(['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange']);

function readJson(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    throw new Error(`Invalid JSON configuration: ${filePath}`);
  }
  return parsed;
}

function validateApplications(config) {
  if (!config || !Array.isArray(config.applications) || config.applications.length > 100) {
    throw new Error('Application bootstrap config must contain at most 100 applications');
  }
  const ids = new Set();
  return config.applications.map((application) => {
    const clientId = application?.clientId;
    if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) {
      throw new Error('Application bootstrap clientId is invalid');
    }
    if (ids.has(clientId.toLowerCase())) throw new Error(`Duplicate application clientId: ${clientId}`);
    ids.add(clientId.toLowerCase());
    if (typeof application.name !== 'string' || !application.name.trim() || application.name.length > 100) {
      throw new Error(`Application name is invalid: ${clientId}`);
    }
    if (!['public', 'confidential', 'service'].includes(application.clientType)) {
      throw new Error(`Application ${clientId} must be public, confidential, or service type`);
    }
    if (!Array.isArray(application.grantTypes) || application.grantTypes.length === 0 || application.grantTypes.some((grant) => !GRANTS.has(grant))) {
      throw new Error(`Application grantTypes are invalid: ${clientId}`);
    }
    if (application.clientType === 'service' && !application.grantTypes.includes('client_credentials')) {
      throw new Error(`Service application ${clientId} must allow client_credentials`);
    }
    if (application.clientType === 'public' && application.grantTypes.some((grant) => !['authorization_code', 'refresh_token'].includes(grant))) {
      throw new Error(`Public application ${clientId} may only allow authorization_code and refresh_token`);
    }
    if (application.allowedScopes !== undefined && (!Array.isArray(application.allowedScopes) || application.allowedScopes.some((scope) => typeof scope !== 'string' || !PERMISSION_RE.test(scope)))) {
      throw new Error(`Application allowedScopes are invalid: ${clientId}`);
    }
    if (application.authorizationManifestFile !== undefined && (typeof application.authorizationManifestFile !== 'string' || !application.authorizationManifestFile.trim())) {
      throw new Error(`Application authorizationManifestFile is invalid: ${clientId}`);
    }
    if (application.defaultRole !== undefined && (typeof application.defaultRole !== 'string' || !ROLE_RE.test(application.defaultRole))) {
      throw new Error(`Application defaultRole is invalid: ${clientId}`);
    }
    if (application.initialRoleAssignments !== undefined && (!Array.isArray(application.initialRoleAssignments) || application.initialRoleAssignments.some((assignment) => typeof assignment?.username !== 'string' || !Array.isArray(assignment?.roles)))) {
      throw new Error(`Application initialRoleAssignments are invalid: ${clientId}`);
    }
    if (application.secret !== undefined) {
      throw new Error(`Do not put secrets in the application config; use ${DEFAULT_VAULTS_FILE}`);
    }
    return {
      clientId,
      name: application.name.trim(),
      description: application.description,
      clientType: application.clientType,
      grantTypes: [...application.grantTypes],
      ...(application.allowedScopes !== undefined ? { allowedScopes: [...new Set(application.allowedScopes)] } : {}),
      ...(application.redirectUris !== undefined ? { redirectUris: application.redirectUris } : {}),
      ...(application.authorizationManifestFile ? { authorizationManifestFile: application.authorizationManifestFile.trim() } : {}),
      ...(application.defaultRole !== undefined ? { defaultRole: application.defaultRole } : {}),
      ...(application.initialRoleAssignments ? { initialRoleAssignments: application.initialRoleAssignments } : {}),
    };
  });
}

function generateSecret() {
  return crypto.randomBytes(32).toString('base64url');
}

function writeVault(filePath, vault) {
  const parent = path.dirname(filePath);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const temporaryPath = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(vault, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  fs.chmodSync(temporaryPath, 0o600);
  fs.renameSync(temporaryPath, filePath);
  fs.chmodSync(filePath, 0o600);
}

/**
 * Register the applications declared in applications.json.
 *
 * This is a deployment/bootstrap path, not a public self-registration API.
 * Existing clients must have a matching secret in .vaults; a mismatch fails
 * startup rather than silently rotating a credential that an app may still use.
 */
export function bootstrapConfiguredApplications({
  configPath = process.env.IAM_APPLICATIONS_CONFIG || DEFAULT_APPLICATIONS_CONFIG,
  vaultPath = process.env.IAM_VAULTS_FILE || DEFAULT_VAULTS_FILE,
} = {}) {
  if (!configPath || !fs.existsSync(configPath)) return { applications: [], changed: false };

  const applications = validateApplications(readJson(configPath, { applications: [] }));
  if (fs.existsSync(vaultPath)) {
    const vaultStat = fs.lstatSync(vaultPath);
    if (vaultStat.isSymbolicLink()) throw new Error(`Vault file must not be a symbolic link: ${vaultPath}`);
    fs.chmodSync(vaultPath, 0o600);
  }
  const vault = readJson(vaultPath, { version: 1, clients: {} });
  if (!vault || typeof vault !== 'object' || !vault.clients || typeof vault.clients !== 'object') {
    throw new Error(`Invalid vault file: ${vaultPath}`);
  }

  let changed = false;
  const results = [];
  for (const application of applications) {
    const vaultEntry = vault.clients[application.clientId];
    const storedSecret = vaultEntry?.clientSecret;
    if (storedSecret !== undefined && (typeof storedSecret !== 'string' || storedSecret.length < 16)) {
      throw new Error(`Invalid secret entry in vault for ${application.clientId}`);
    }

    const existing = getClientByPublicId(application.clientId);
    let client;
    let secret = storedSecret;
    if (existing) {
      if (application.clientType !== 'public') {
        if (!secret) {
          throw new Error(`Vault secret is missing for existing client ${application.clientId}`);
        }
        if (!verifyClientSecret(application.clientId, secret)) {
          throw new Error(`Vault secret does not match existing client ${application.clientId}`);
        }
      } else {
        secret = null;
        if (existing.has_secret) clearClientSecret(existing.id);
      }
      client = updateClient(existing.id, {
        name: application.name,
        description: application.description,
        clientType: application.clientType,
        grantTypes: application.grantTypes,
        allowedScopes: application.allowedScopes,
        redirectUris: application.redirectUris,
        defaultRole: application.defaultRole,
      });
    } else {
      secret ??= generateSecret();
      client = createClient({
        clientId: application.clientId,
        name: application.name,
        description: application.description,
        secret: application.clientType === 'public' ? null : secret,
        clientType: application.clientType,
        grantTypes: application.grantTypes,
        allowedScopes: application.allowedScopes ?? [],
        redirectUris: application.redirectUris ?? [],
        defaultRole: application.defaultRole,
      });
      changed = true;
      recordAuditEvent({
        eventType: 'client_bootstrapped',
        clientId: client.id,
        metadata: { client_id: client.client_id, source: 'applications_config' },
      });
    }

    if (application.clientType === 'public' && vaultEntry) {
      delete vault.clients[application.clientId];
      changed = true;
    } else if (application.clientType !== 'public' && (!vaultEntry || vaultEntry.clientSecret !== secret)) {
      vault.clients[application.clientId] = { clientId: application.clientId, clientSecret: secret };
      changed = true;
    }

    if (application.authorizationManifestFile) {
      const manifest = readJson(application.authorizationManifestFile, null);
      if (!manifest) throw new Error(`Authorization manifest is missing: ${application.authorizationManifestFile}`);
      const result = reconcileAuthorizationManifest({ clientId: client.id, ...manifest });
      if (result?.error) throw new Error(`Authorization manifest failed for ${application.clientId}: ${result.error}`);
    }

    for (const assignment of application.initialRoleAssignments ?? []) {
      const user = getUserByUsername(assignment.username);
      if (!user) continue;
      setUserRolesForClient(user.id, client.id, assignment.roles);
    }
    // Never return bootstrap secrets to callers; they are persisted only in the
    // protected vault file and are not needed by the IAM process after startup.
    results.push({ clientId: client.client_id, created: !existing });
  }

  if (changed) writeVault(vaultPath, vault);
  return { applications: results, changed };
}
