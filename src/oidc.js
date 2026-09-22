import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const configuredPrivateKey = process.env.IAM_OIDC_PRIVATE_KEY_PEM?.replace(/\\n/g, '\n');
const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const keyFile = process.env.IAM_OIDC_KEY_FILE ?? path.join(moduleDir, '..', 'iam.oidc.key');
let keyPair;

function ensureKeyPair() {
  if (keyPair) return keyPair;
  if (configuredPrivateKey) {
    const privateKey = crypto.createPrivateKey(configuredPrivateKey);
    keyPair = { privateKey, publicKey: crypto.createPublicKey(privateKey) };
    return keyPair;
  }

  if (fs.existsSync(keyFile)) {
    const privateKey = crypto.createPrivateKey(fs.readFileSync(keyFile, 'utf8'));
    keyPair = { privateKey, publicKey: crypto.createPublicKey(privateKey) };
    return keyPair;
  }

  keyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  if (process.env.NODE_ENV === 'production') {
    throw new Error('IAM_OIDC_PRIVATE_KEY_PEM or IAM_OIDC_KEY_FILE must be configured in production');
  }
  const privatePem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  fs.writeFileSync(keyFile, privatePem, { encoding: 'utf8', mode: 0o600 });
  return keyPair;
}

export function initializeOidcKeys() {
  ensureKeyPair();
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

export function issuerFor(req) {
  return (process.env.IAM_ISSUER || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
}

export function oidcJwks() {
  const { publicKey } = ensureKeyPair();
  const jwk = publicKey.export({ format: 'jwk' });
  return {
    keys: [{
      ...jwk,
      kid: 'iam-rsa-1',
      alg: 'RS256',
      use: 'sig',
      key_ops: ['verify'],
    }],
  };
}

export function signIdToken({ issuer, clientId, user, nonce, authTime, scopes }) {
  const { privateKey } = ensureKeyPair();
  const header = { alg: 'RS256', typ: 'JWT', kid: 'iam-rsa-1' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer,
    sub: user.id,
    aud: clientId,
    iat: now,
    exp: now + 600,
    auth_time: authTime ?? now,
  };
  if (nonce) payload.nonce = nonce;
  if (scopes.includes('profile')) {
    payload.name = user.display_name;
    payload.preferred_username = user.username;
  }
  if (scopes.includes('email') && user.email) {
    payload.email = user.email;
    payload.email_verified = false;
  }

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}
