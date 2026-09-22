import { Router } from 'express';
import { listAuditEvents } from '../db.js';
import { requireAuth, requireRole } from '../middleware.js';

const router = Router();

router.get('/audit-events', requireAuth, requireRole('admin'), (req, res) => {
  const limit = Math.min(Math.max(Number.parseInt(req.query.limit ?? '100', 10) || 100, 1), 500);
  const offset = Math.max(Number.parseInt(req.query.offset ?? '0', 10) || 0, 0);
  res.json({ events: listAuditEvents({ limit, offset }), limit, offset });
});

export default router;
