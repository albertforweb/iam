import path from 'node:path';
import { fileURLToPath } from 'node:url';
import './db.js';
import { createApp } from './app.js';
import { initializeOidcKeys } from './oidc.js';
import { bootstrapConfiguredApplications } from './application-bootstrap.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
if (!process.env.IAM_UI_DIR) process.env.IAM_UI_DIR = path.join(__dirname, '..', 'public');
const PORT = process.env.PORT ?? 3000;
initializeOidcKeys();
const app = createApp();

try {
  const bootstrap = bootstrapConfiguredApplications();
  for (const application of bootstrap.applications) {
    console.log(`[bootstrap] Application client ready: ${application.clientId}${application.created ? ' (created)' : ''}`);
  }
  app.listen(PORT, () => {
    console.log(`IAM service listening on http://localhost:${PORT}`);
  });
} catch (error) {
  console.error(`[bootstrap] ${error.message}`);
  process.exitCode = 1;
}
