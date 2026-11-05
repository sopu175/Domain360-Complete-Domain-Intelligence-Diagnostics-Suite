/**
 * Sliding-window rate limiter keyed by client IP + route.
 * Fair-use protection for free-tier diagnostics.
 */

const buckets = new Map<string, number[]>();
let lastGc = Date.now();

function gc(): void {
  const now = Date.now();
  if (now - lastGc < 60_000) return;
  lastGc = now;
  for (const [k, hits] of buckets) {
    if (hits.length === 0 || now - hits[hits.length - 1] > 120_000) buckets.delete(k);
  }
}

export interface RateVerdict {
  allowed: boolean;
  remaining: number;
  retryAfterSec: number;
}

export function checkRate(key: string, limitPerMinute: number, windowMs = 60_000): RateVerdict {
  gc();
  const now = Date.now();
  const hits = (buckets.get(key) || []).filter((t) => now - t < windowMs);
  if (hits.length >= limitPerMinute) {
    const retryAfterSec = Math.ceil((windowMs - (now - hits[0])) / 1000);
    buckets.set(key, hits);
    return { allowed: false, remaining: 0, retryAfterSec };
  }
  hits.push(now);
  buckets.set(key, hits);
  return { allowed: true, remaining: limitPerMinute - hits.length, retryAfterSec: 0 };
}

export function clientIpFromHeaders(h: Headers): string {
  const xff = h.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  return h.get('x-real-ip') || 'anonymous';
}
