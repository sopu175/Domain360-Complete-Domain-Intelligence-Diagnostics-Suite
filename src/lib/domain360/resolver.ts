import dns from 'node:dns';
import { isIP } from './validation';
import { assertPublicIp, SsrfError } from './ssrf';
import { DnsWireError, TYPE_NUMBERS, wireQuery, wireToRecords, WireResponse } from './dns-wire';
import { dohQueryAny, dohQuery, DohProvider } from './doh';
import { TIMEOUTS } from './config';
import type { DnsRecord } from './types';

/**
 * High-level resolution engine: raw UDP wire queries to the chosen resolver,
 * with automatic DNS-over-HTTPS fallback. Ensures custom resolver IPs are
 * public (SSRF protection).
 */

export interface ResolverChoice {
  key: string;
  label: string;
  kind: 'system' | 'public' | 'custom' | 'doh';
  server?: string;
  dohProvider?: DohProvider;
}

export const RESOLVER_CHOICES: ResolverChoice[] = [
  { key: 'system', label: 'System / default resolver', kind: 'system' },
  { key: 'google', label: 'Google Public DNS (8.8.8.8)', kind: 'public', server: '8.8.8.8', dohProvider: 'google' },
  { key: 'cloudflare', label: 'Cloudflare DNS (1.1.1.1)', kind: 'public', server: '1.1.1.1', dohProvider: 'cloudflare' },
  { key: 'quad9', label: 'Quad9 (9.9.9.9)', kind: 'public', server: '9.9.9.9', dohProvider: 'quad9' },
  { key: 'opendns', label: 'OpenDNS (208.67.222.222)', kind: 'public', server: '208.67.222.222' },
  { key: 'adguard', label: 'AdGuard DNS (94.140.14.14)', kind: 'public', server: '94.140.14.14' },
];

export function parseResolverChoice(value?: string): ResolverChoice {
  const v = (value || 'system').trim().toLowerCase();
  if (v === 'system' || v === '') return RESOLVER_CHOICES[0];
  const known = RESOLVER_CHOICES.find((r) => r.key === v);
  if (known) return known;
  if (v.startsWith('custom:')) {
    const ip = v.slice(7).trim();
    if (isIP(ip) !== 4) throw new SsrfError('Custom resolver must be a valid IPv4 address.');
    assertPublicIp(ip);
    return { key: v, label: `Custom resolver (${ip})`, kind: 'custom', server: ip };
  }
  if (isIP(v) === 4) {
    assertPublicIp(v);
    return { key: `custom:${v}`, label: `Custom resolver (${v})`, kind: 'custom', server: v };
  }
  return RESOLVER_CHOICES[0];
}

export function systemDnsServer(): string | null {
  try {
    const servers = dns.getServers();
    const v4 = servers.find((s) => isIP(s) === 4);
    return v4 || null;
  } catch {
    return null;
  }
}

export interface ResolveOutcome {
  records: DnsRecord[];
  authority: DnsRecord[];
  rcode: string;
  rcodeNum: number;
  aa: boolean | null;
  ad: boolean | null;
  responseTimeMs: number;
  source: 'wire' | 'doh';
  serverUsed: string | null;
  note?: string;
}

const RECORD_TYPES = new Set(Object.keys(TYPE_NUMBERS));

export function isKnownRecordType(t: string): boolean {
  return RECORD_TYPES.has(t.toUpperCase());
}

/**
 * Resolve `name`/`type` via the selected resolver (raw UDP first,
 * DoH fallback). Never throws for DNS-level failures: returns the
 * rcode/empty result so callers can present them.
 */
export async function smartResolve(
  name: string,
  type: string,
  choice: ResolverChoice = RESOLVER_CHOICES[0],
  opts: { timeoutMs?: number; dnssecDo?: boolean } = {},
): Promise<ResolveOutcome> {
  const t = type.toUpperCase();
  const typeNum = TYPE_NUMBERS[t];
  if (!typeNum) throw new DnsWireError('FORMERR', `Unsupported record type ${type}`);
  const timeoutMs = opts.timeoutMs ?? TIMEOUTS.wire;

  let server: string | undefined = choice.server;
  if (choice.kind === 'system') {
    server = systemDnsServer() ?? undefined;
  }
  if (server) {
    try {
      const resp: WireResponse = await wireQuery({
        name,
        type: typeNum,
        server,
        timeoutMs,
        dnssecDo: opts.dnssecDo,
      });
      // Truncated responses can't be parsed over UDP — fall through to DoH
      if (!resp.tc) {
        return {
          records: wireToRecords(resp.answers),
          authority: wireToRecords(resp.authority),
          rcode: resp.rcodeName,
          rcodeNum: resp.rcode,
          aa: resp.aa,
          ad: resp.ad,
          responseTimeMs: resp.responseTimeMs,
          source: 'wire',
          serverUsed: server,
        };
      }
      const doh = await dohQueryAny(name, t);
      return {
        records: doh.answers.map((a) => ({ type: a.typeName, name: a.name, value: a.data, ttl: a.ttl, class: 'IN' })),
        authority: doh.authority.map((a) => ({ type: a.typeName, name: a.name, value: a.data, ttl: a.ttl, class: 'IN' })),
        rcode: doh.statusName,
        rcodeNum: doh.status,
        aa: null,
        ad: doh.ad,
        responseTimeMs: doh.responseTimeMs,
        source: 'doh',
        serverUsed: `DoH:${doh.provider}`,
        note: 'UDP response was truncated; result via DNS-over-HTTPS.',
      };
    } catch (e) {
      const err = e as { code?: string };
      if (err.code === 'TIMEOUT' || err.code === 'NETWORK' || err.code === 'PARSE_ERROR') {
        // fall back to DoH transparently
        try {
          const doh = await dohQueryAny(
            name,
            t,
            choice.dohProvider ? [choice.dohProvider, 'google', 'cloudflare'] : ['google', 'cloudflare'],
          );
          return {
            records: doh.answers.map((a) => ({ type: a.typeName, name: a.name, value: a.data, ttl: a.ttl, class: 'IN' })),
            authority: doh.authority.map((a) => ({ type: a.typeName, name: a.name, value: a.data, ttl: a.ttl, class: 'IN' })),
            rcode: doh.statusName,
            rcodeNum: doh.status,
            aa: null,
            ad: doh.ad,
            responseTimeMs: doh.responseTimeMs,
            source: 'doh',
            serverUsed: `DoH:${doh.provider}`,
            note: `Resolver ${server} unreachable over UDP (${err.code}); answered via DNS-over-HTTPS.`,
          };
        } catch {
          throw new DnsWireError('TIMEOUT', `Resolver ${server} unreachable and DoH fallback failed`);
        }
      }
      // DNS-level answers (NXDOMAIN etc.) are real results — rethrow only real errors
      if (err.code === 'FORMERR' || err.code === 'PARSE_ERROR') throw e;
      throw e;
    }
  }
  // No usable UDP server (e.g. system has none) → DoH only
  const doh = await dohQueryAny(name, t);
  return {
    records: doh.answers.map((a) => ({ type: a.typeName, name: a.name, value: a.data, ttl: a.ttl, class: 'IN' })),
    authority: doh.authority.map((a) => ({ type: a.typeName, name: a.name, value: a.data, ttl: a.ttl, class: 'IN' })),
    rcode: doh.statusName,
    rcodeNum: doh.status,
    aa: null,
    ad: doh.ad,
    responseTimeMs: doh.responseTimeMs,
    source: 'doh',
    serverUsed: `DoH:${doh.provider}`,
    note: 'Answered via DNS-over-HTTPS.',
  };
}

/** Quick values extraction for policy checks (SPF, DMARC, CAA, …). */
export async function resolveTypeValues(
  name: string,
  type: string,
  choice?: ResolverChoice,
): Promise<{ values: string[]; ttl: number | null; rcode: string; ms: number }> {
  const outcome = await smartResolve(name, type, choice || RESOLVER_CHOICES[0]);
  return {
    values: outcome.records.map((r) => r.value),
    ttl: outcome.records[0]?.ttl ?? null,
    rcode: outcome.rcode,
    ms: outcome.responseTimeMs,
  };
}

export interface HostIps {
  v4: string[];
  v6: string[];
  rcode: string;
}

/** Resolve a hostname to its public IPv4/IPv6 addresses (SSRF-safe filtering). */
export async function resolveHostIps(host: string): Promise<HostIps> {
  const choice = RESOLVER_CHOICES[0];
  const [a, aaaa] = await Promise.allSettled([
    smartResolve(host, 'A', choice),
    smartResolve(host, 'AAAA', choice),
  ]);
  const v4: string[] = [];
  const v6: string[] = [];
  let rcode = 'NOERROR';
  if (a.status === 'fulfilled') {
    rcode = a.value.rcode;
    for (const r of a.value.records) {
      if (r.type === 'A' && isIP(r.value) === 4) v4.push(r.value);
    }
  }
  if (aaaa.status === 'fulfilled') {
    if (rcode === 'NOERROR' && aaaa.value.rcode !== 'NOERROR') rcode = aaaa.value.rcode;
    for (const r of aaaa.value.records) {
      if (r.type === 'AAAA' && isIP(r.value) === 6) v6.push(r.value);
    }
  }
  return { v4: [...new Set(v4)], v6: [...new Set(v6)], rcode };
}

/** Resolve a hostname keeping private IPs visible (for reporting, not connecting). */
export async function resolveHostIpsUnfiltered(host: string): Promise<HostIps> {
  return resolveHostIps(host);
}
