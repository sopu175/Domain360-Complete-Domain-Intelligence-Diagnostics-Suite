import { ApiError } from '../api';
import { cached, TTL } from '../cache';
import { entitlement, PUBLIC_RESOLVERS } from '../config';
import { TYPE_NUMBERS, wireQuery } from '../dns-wire';
import type { PropagationNode, PropagationResult, StatusLevel } from '../types';

const PROPAGATION_TYPES = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME'];

interface RawNode {
  resolver: string;
  ip: string;
  values: string[] | null;
  rcode: string;
  ms: number | null;
  failed: boolean;
}

const normalize = (answers: { data: string }[]): string[] =>
  answers.map((a) => a.data.replace(/\.$/, '')).sort();

export async function checkPropagation(input: {
  ascii: string;
  recordType: string;
  maxNodes?: number;
}): Promise<PropagationResult> {
  const type = input.recordType.toUpperCase().trim();
  if (!PROPAGATION_TYPES.includes(type)) {
    throw new ApiError('INVALID_INPUT', `Propagation check supports: ${PROPAGATION_TYPES.join(', ')}`);
  }
  const maxNodes = Math.min(input.maxNodes ?? entitlement('propagationResolvers'), PUBLIC_RESOLVERS.length);
  const resolvers = PUBLIC_RESOLVERS.slice(0, maxNodes);
  const typeNum = TYPE_NUMBERS[type];

  return cached(`prop:${input.ascii}:${type}`, TTL.propagation, async (): Promise<PropagationResult> => {
    const settled = await Promise.allSettled(
      resolvers.map((r) => wireQuery({ name: input.ascii, type: typeNum, server: r.ip, timeoutMs: 2500 })),
    );

    const raw: RawNode[] = settled.map((s, i) => {
      const r = resolvers[i];
      if (s.status === 'fulfilled') {
        const resp = s.value;
        const values = resp.rcodeName === 'NOERROR' && resp.answers.length ? normalize(resp.answers) : null;
        return { resolver: r.name, ip: r.ip, values, rcode: resp.rcodeName, ms: resp.responseTimeMs, failed: false };
      }
      return { resolver: r.name, ip: r.ip, values: null, rcode: 'TIMEOUT', ms: null, failed: true };
    });

    // expected = first successful non-empty NOERROR answer (Google is first)
    const firstOk = raw.find((n) => !n.failed && n.rcode === 'NOERROR' && n.values && n.values.length);
    const expected: string[] | null = firstOk?.values ?? null;
    const expectedSource = firstOk?.resolver ?? '';

    const nodes: PropagationNode[] = raw.map((n) => {
      let matchesExpected: boolean | null = null;
      let status: StatusLevel;
      if (n.failed) status = 'unknown';
      else if (n.rcode === 'NOERROR' && n.values && n.values.length) {
        matchesExpected = expected ? n.values.join('|') === expected.join('|') : null;
        status = matchesExpected ? 'healthy' : 'warning';
      } else if (n.rcode === 'NOERROR') status = 'not_configured';
      else if (n.rcode === 'NXDOMAIN') status = 'critical';
      else status = 'unknown';

      return {
        name: n.resolver,
        ip: n.ip,
        kind: 'public_resolver' as const,
        values: n.values,
        responseCode: n.rcode,
        responseTimeMs: n.ms,
        matchesExpected,
        status,
      };
    });

    const matched = nodes.filter((n) => n.status === 'healthy').length;
    const divergent = nodes.filter((n) => n.status === 'warning').length;
    const failed = nodes.filter((n) => n.status === 'unknown' || n.status === 'critical').length;
    const answered = nodes.length - nodes.filter((n) => n.status === 'unknown').length;
    const propagationScore = answered <= 0 ? 0 : Math.min(100, Math.round((100 * matched) / Math.max(1, answered)));

    return {
      domain: input.ascii,
      recordType: type,
      expectedSource,
      expected,
      nodes,
      summary: { total: nodes.length, matched, divergent, failed },
      propagationScore,
      timestamp: new Date().toISOString(),
      note:
        `Results come from ${nodes.length} independent public DNS resolvers operated by different companies ` +
        `(Google, Cloudflare, Quad9, Cisco OpenDNS, …). These are public resolvers, NOT geographic vantage points — ` +
        `worldwide coverage is not claimed. Observed values also depend on each resolver's cache TTL.`,
    };
  });
}
