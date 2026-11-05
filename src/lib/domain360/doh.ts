import { TIMEOUTS } from './config';

/**
 * DNS-over-HTTPS JSON client (Google / Cloudflare / Quad9).
 * Used as automatic fallback when raw UDP is unavailable, and for the
 * DNSSEC AD (authenticated data) flag coming from validating resolvers.
 */

export type DohProvider = 'google' | 'cloudflare' | 'quad9';

const ENDPOINTS: Record<DohProvider, string> = {
  google: 'https://dns.google/resolve',
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  quad9: 'https://dns.quad9.net:5053/dns-query',
};

export interface DohAnswer {
  name: string;
  type: number;
  typeName: string;
  ttl: number;
  data: string;
}

export interface DohResult {
  status: number;
  statusName: string;
  ad: boolean;
  answers: DohAnswer[];
  authority: DohAnswer[];
  provider: DohProvider;
  responseTimeMs: number;
  comment?: string;
}

const TYPE_TO_NAME: Record<number, string> = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
  29: 'LOC', 33: 'SRV', 35: 'NAPTR', 37: 'CERT', 39: 'DNAME', 43: 'DS', 44: 'SSHFP',
  46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 50: 'NSEC3', 51: 'NSEC3PARAM', 52: 'TLSA',
  64: 'SVCB', 65: 'HTTPS', 99: 'SPF', 255: 'ANY', 256: 'URI', 257: 'CAA',
};

const RCODE_NAMES: Record<number, string> = {
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED',
};

export async function dohQuery(
  name: string,
  type: string | number,
  provider: DohProvider = 'google',
  timeoutMs = TIMEOUTS.doh,
): Promise<DohResult> {
  const started = Date.now();
  const url = new URL(ENDPOINTS[provider]);
  url.searchParams.set('name', name);
  url.searchParams.set('type', String(type));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url.toString(), {
      headers: { accept: 'application/dns-json' },
      signal: ctrl.signal,
      cache: 'no-store',
    });
    if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
    const json = (await res.json()) as {
      Status: number;
      AD?: boolean;
      Answer?: { name: string; type: number; TTL: number; data: string }[];
      Authority?: { name: string; type: number; TTL: number; data: string }[];
      Comment?: string;
    };
    const map = (arr?: { name: string; type: number; TTL: number; data: string }[]): DohAnswer[] =>
      (arr || []).map((a) => ({
        name: a.name,
        type: a.type,
        typeName: TYPE_TO_NAME[a.type] || `TYPE${a.type}`,
        ttl: a.TTL,
        data: a.data,
      }));
    return {
      status: json.Status,
      statusName: RCODE_NAMES[json.Status] || `RCODE${json.Status}`,
      ad: Boolean(json.AD),
      answers: map(json.Answer),
      authority: map(json.Authority),
      provider,
      responseTimeMs: Date.now() - started,
      comment: json.Comment,
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Try providers in order until one answers. */
export async function dohQueryAny(
  name: string,
  type: string | number,
  order: DohProvider[] = ['google', 'cloudflare', 'quad9'],
): Promise<DohResult> {
  let lastErr: unknown;
  for (const p of order) {
    try {
      return await dohQuery(name, type, p);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error('All DoH providers failed');
}
