import { ApiError } from '../api';
import { cached, TTL } from '../cache';
import { entitlement } from '../config';
import { TYPE_NUMBERS, wireToRecords } from '../dns-wire';
import { parseResolverChoice, smartResolve } from '../resolver';
import type { DnsLookupResult } from '../types';

const SUPPORTED = [
  'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'PTR', 'CAA', 'SRV',
  'NAPTR', 'DS', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'TLSA',
  'SSHFP', 'SVCB', 'HTTPS', 'LOC', 'CERT', 'URI', 'DNAME', 'ANY',
];

export async function lookupDns(input: {
  ascii: string;
  display: string;
  recordType: string;
  resolver: string;
}): Promise<DnsLookupResult> {
  const type = input.recordType.toUpperCase().trim();
  if (!SUPPORTED.includes(type) || !TYPE_NUMBERS[type]) {
    throw new ApiError(
      'INVALID_INPUT',
      `Unsupported record type "${type}". Supported: ${SUPPORTED.join(', ')}`,
    );
  }
  if (type === 'ANY' && !entitlement('advancedTls')) {
    throw new ApiError('FORBIDDEN', 'ANY queries require a higher plan.', 403);
  }
  const choice = parseResolverChoice(input.resolver || 'system');
  const key = `dns:${input.ascii}:${type}:${choice.key}`;

  const perform = async (): Promise<DnsLookupResult> => {
    try {
      const outcome = await smartResolve(input.ascii, type, choice, { dnssecDo: true });
      const records = wireToRecords(
        outcome.records.map((r) => ({
          name: r.name, type: TYPE_NUMBERS[r.type] || 0, typeName: r.type,
          ttl: r.ttl ?? 0, class: r.class || 'IN', data: r.value,
          raw: '',
        })),
      );
      const authority = wireToRecords(
        outcome.authority.map((r) => ({
          name: r.name, type: TYPE_NUMBERS[r.type] || 0, typeName: r.type,
          ttl: r.ttl ?? 0, class: r.class || 'IN', data: r.value,
          raw: '',
        })),
      );
      return {
        domain: input.display,
        ascii: input.ascii,
        recordType: type,
        resolverLabel: outcome.serverUsed ? `${choice.label} → ${outcome.serverUsed}` : choice.label,
        resolverKind: choice.kind,
        responseCode: outcome.rcode,
        responseTimeMs: outcome.responseTimeMs,
        records,
        authority,
        dnssecAd: outcome.ad,
        source: outcome.source,
        timestamp: new Date().toISOString(),
        ...(outcome.note ? { note: outcome.note } : {}),
        ...(type === 'ANY' && records.length === 0
          ? { note: 'Many resolvers refuse ANY queries; an empty result may not mean the domain has no records.' }
          : {}),
      };
    } catch (err) {
      const e = err as { code?: string; message?: string };
      return {
        domain: input.display,
        ascii: input.ascii,
        recordType: type,
        resolverLabel: choice.label,
        resolverKind: choice.kind,
        responseCode: e.code === 'TIMEOUT' ? 'TIMEOUT' : 'SERVFAIL',
        responseTimeMs: 0,
        records: [],
        authority: [],
        dnssecAd: null,
        source: 'wire',
        timestamp: new Date().toISOString(),
        note: `Resolver query failed: ${e.message || 'unknown error'}. Try a different resolver.`,
      };
    }
  };

  // Cache successful shapes only (perform never throws).
  return cached(key, TTL.dns, perform);
}
