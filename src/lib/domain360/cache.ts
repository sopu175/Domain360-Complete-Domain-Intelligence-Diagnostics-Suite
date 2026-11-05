/**
 * In-memory TTL cache with in-flight request de-duplication.
 * Suitable for the single-instance deployment model of this app.
 */

interface Entry {
  value: unknown;
  expires: number;
}

const store = new Map<string, Entry>();
const inflight = new Map<string, Promise<unknown>>();

function gc(): void {
  const now = Date.now();
  if (store.size > 800) {
    for (const [k, v] of store) {
      if (v.expires < now) store.delete(k);
    }
  }
}

export function cacheGet<T>(key: string): T | undefined {
  const hit = store.get(key);
  if (!hit) return undefined;
  if (hit.expires < Date.now()) {
    store.delete(key);
    return undefined;
  }
  return hit.value as T;
}

export function cacheSet(key: string, value: unknown, ttlMs: number): void {
  store.set(key, { value, expires: Date.now() + ttlMs });
  gc();
}

export function cacheDelete(key: string): void {
  store.delete(key);
  inflight.delete(key);
}

/**
 * Get-or-compute with TTL + in-flight de-duplication so parallel
 * API calls for the same key share one computation.
 */
export async function cached<T>(
  key: string,
  ttlMs: number,
  compute: () => Promise<T>,
): Promise<T> {
  const hit = cacheGet<T>(key);
  if (hit !== undefined) return hit;
  const existing = inflight.get(key);
  if (existing) return existing as Promise<T>;
  const p = (async () => {
    try {
      const value = await compute();
      cacheSet(key, value, ttlMs);
      return value;
    } finally {
      inflight.delete(key);
    }
  })();
  inflight.set(key, p);
  return p;
}

export function cacheStats(): { size: number; inflight: number } {
  return { size: store.size, inflight: inflight.size };
}

/** Standard TTLs (ms) per data kind. */
export const TTL = {
  dnsLow: 60_000,
  dns: Math.min(300, 60) * 1000,
  dnsLong: 10 * 60_000,
  propagation: 60_000,
  nameservers: 5 * 60_000,
  ssl: 10 * 60_000,
  whois: 60 * 60_000,
  ipinfo: 60 * 60_000,
  http: 5 * 60_000,
  security: 5 * 60_000,
  subdomains: 6 * 60 * 60_000,
  dnssec: 10 * 60_000,
  overview: 2 * 60_000,
  crtsh: 6 * 60 * 60_000,
} as const;
