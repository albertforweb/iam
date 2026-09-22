import crypto from 'node:crypto';

const counters = new Map();

export function incrementMetric(name, value = 1) {
  counters.set(name, (counters.get(name) ?? 0) + value);
}

export function metricsText() {
  return [...counters.entries()]
    .map(([name, value]) => `iam_${name} ${value}`)
    .join('\n') + '\n';
}

export function requestObservability(req, res, next) {
  const requestId = req.get('X-Request-Id') || crypto.randomUUID();
  const started = process.hrtime.bigint();
  req.id = requestId;
  res.set('X-Request-Id', requestId);
  res.on('finish', () => {
    incrementMetric('http_requests_total');
    incrementMetric(`http_responses_total{status="${res.statusCode}"}`);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    if (elapsedMs > 1000) incrementMetric('slow_requests_total');
  });
  next();
}

