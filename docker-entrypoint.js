import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const keyFile = process.env.IAM_OIDC_KEY_FILE;
if (!keyFile) throw new Error('IAM_OIDC_KEY_FILE must be configured');

if (!fs.existsSync(keyFile)) {
  fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  fs.writeFileSync(keyFile, privatePem, { encoding: 'utf8', mode: 0o600 });
  fs.chmodSync(keyFile, 0o600);
  console.log(`[startup] Generated OIDC signing key at ${keyFile}`);
}

await import('./src/index.js');
