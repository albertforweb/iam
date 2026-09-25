import express from 'express';
import cookieParser from 'cookie-parser';
import usersRouter from './routes/users.js';
import rolesRouter from './routes/roles.js';
import clientsRouter from './routes/clients.js';
import { default as oauthRouter, OAUTH_ENABLED } from './routes/oauth.js';
import auditRouter from './routes/audit.js';
import { metricsText, requestObservability } from './observability.js';

export function createApp() {
  const app = express();
  const allowedOrigins = new Set(
    (process.env.IAM_ALLOWED_ORIGINS ?? '')
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean),
  );

  app.disable('x-powered-by');
  app.use(requestObservability);
  app.use(express.json({ limit: '64kb' }));
  app.use(express.urlencoded({ extended: true, limit: '64kb' }));
  app.use(cookieParser());

  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.has(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
      res.set('Access-Control-Allow-Credentials', 'true');
    }
    res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Client-Id');
    if (req.method === 'OPTIONS') {
      if (origin && !allowedOrigins.has(origin)) return res.status(403).end();
      return res.status(204).end();
    }
    next();
  });

  app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
  });
  if (process.env.IAM_METRICS_ENABLED === 'true') {
    app.get('/metrics', (req, res) => {
      res.type('text/plain').send(metricsText());
    });
  }

  app.use('/api/auth', usersRouter);
  app.use('/api/auth', rolesRouter);
  app.use('/api/auth', clientsRouter);
  app.use('/api/auth', auditRouter);
  app.use('/v1', usersRouter);
  app.use('/v1', rolesRouter);
  app.use('/v1', clientsRouter);
  app.use('/v1', auditRouter);
  if (OAUTH_ENABLED) {
    // Keep the current prefix during migration while exposing standards-based
    // discovery and OIDC endpoints at their conventional root paths.
    app.use('/api/auth', oauthRouter);
    app.use('/', oauthRouter);
    app.use('/v1', oauthRouter);
  }

  const uiEnabled = (process.env.IAM_UI_ENABLED ?? 'true') === 'true';
  if (uiEnabled) {
    const path = process.env.IAM_UI_DIR;
    if (path) {
      // The UI is a single-page application. Keep index.html as an internal
      // asset name and expose route-level entry points for auth and console.
      app.get('/index.html', (req, res) => {
        const query = req.originalUrl.includes('?') ? req.originalUrl.slice(req.originalUrl.indexOf('?')) : '';
        res.redirect(301, `/${query}`);
      });
      app.get('/login', (req, res) => res.sendFile('index.html', { root: path }));
      app.use(express.static(path));
    }
  }

  app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Internal server error', request_id: req.id });
  });

  return app;
}
