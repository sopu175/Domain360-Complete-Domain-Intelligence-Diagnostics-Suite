import { createHash } from 'node:crypto';
import { cached, TTL } from '../cache';
import { dohQuery } from '../doh';
import { smartResolve } from '../resolver';
import type { DnsRecord, DnssecChainStep, DnssecResult, Finding } from '../types';

const ALG_NAMES: Record<number, string> = {
  5: 'RSA/SHA-1',
  7: 'RSA/SHA-1 (NSEC3)',
  8: 'RSA/SHA-256',
  10: 'RSA/SHA-512',
  13: 'ECDSA P-256/SHA-256',
  14: 'ECDSA P-384/SHA-384',
  15: 'Ed25519',
  16: 'Ed448',
};

function finding(id: string, title: string, severity: Finding['severity'], description: string, recommendation?: string, reference?: string): Finding {
  return { id, title, severity, category: 'dnssec', description, recommendation, reference };
}

/** RFC 4034 Appendix B key tag checksum. */
function keyTag(rdata: Buffer): number {
  let sum = 0;
  for (let i = 0; i < rdata.length; i++) {
    sum += i & 1 ? rdata[i] : rdata[i] << 8;
  }
  return ((sum + (sum >> 16)) & 0xffff) >>> 0;
}

/** DNSKEY wire rdata = flags(2) proto(1) alg(1) pubkey */
function parseDnskey(value: string): { flags: number; proto: number; alg: number; rdata: Buffer } | null {
  try {
    const parts = value.trim().split(/\s+/);
    const flags = parseInt(parts[0], 10);
    const proto = parseInt(parts[1], 10);
    const alg = parseInt(parts[2], 10);
    const pubkey = Buffer.from(parts[3], 'base64');
    if (!Number.isFinite(flags) || !pubkey.length) return null;
    const head = Buffer.alloc(4);
    head.writeUInt16BE(flags, 0);
    head[2] = proto;
    head[3] = alg;
    return { flags, proto, alg, rdata: Buffer.concat([head, pubkey]) };
  } catch {
    return null;
  }
}

function ownerWire(name: string): Buffer {
  const chunks: Buffer[] = [];
  for (const label of name.toLowerCase().replace(/\.$/, '').split('.')) {
    const b = Buffer.from(label, 'ascii');
    chunks.push(Buffer.from([b.length]), b);
  }
  chunks.push(Buffer.from([0]));
  return Buffer.concat(chunks);
}

function dsDigestMatch(domain: string, dnskeyRdata: Buffer, digestType: number, expectedHex: string): boolean {
  const algo = digestType === 1 ? 'sha1' : digestType === 2 ? 'sha256' : digestType === 4 ? 'sha384' : null;
  if (!algo) return false;
  const digest = createHash(algo).update(Buffer.concat([ownerWire(domain), dnskeyRdata])).digest('hex');
  return digest.toUpperCase() === expectedHex.toUpperCase();
}

function parseRrsigValue(value: string) {
  // "DNSKEY 13 2 3600 20250101120000 20241201120000 1234 example.com. sig..."
  const parts = value.trim().split(/\s+/);
  if (parts.length < 8) return null;
  const covered = parts[0].toUpperCase();
  const alg = parseInt(parts[1], 10);
  const expRaw = parts[4];
  const keytag = parseInt(parts[6], 10);
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(expRaw);
  if (!m || !Number.isFinite(alg)) return null;
  const expiration = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  return { covered, alg, keytag, expiration };
}

export async function analyzeDnssec(input: { ascii: string }): Promise<DnssecResult> {
  return cached(`dnssec:${input.ascii}`, TTL.dnssec, async (): Promise<DnssecResult> => {
    const [dsRes, keyRes, sigRes, adRes] = await Promise.allSettled([
      smartResolve(input.ascii, 'DS', undefined, { dnssecDo: true }),
      smartResolve(input.ascii, 'DNSKEY', undefined, { dnssecDo: true }),
      smartResolve(input.ascii, 'RRSIG', undefined, { dnssecDo: true }),
      dohQuery(input.ascii, 'DNSKEY', 'google').catch(() => null),
    ]);

    const ds: DnsRecord[] = dsRes.status === 'fulfilled' ? dsRes.value.records : [];
    const dnskey: DnsRecord[] = keyRes.status === 'fulfilled' ? keyRes.value.records : [];
    const rrsigRecords: DnsRecord[] = sigRes.status === 'fulfilled' ? sigRes.value.records : [];
    const adFlag = adRes.status === 'fulfilled' ? adRes.value : null;

    const keytagRdata = dnskey
      .map((k) => parseDnskey(k.value))
      .filter((k): k is NonNullable<typeof k> => k !== null);
    const ksks = keytagRdata.filter((k) => k.flags & 0x0001); // flags 257 = KSK

    const digestVerified = (() => {
      if (!ds.length || !ksks.length) return null;
      for (const d of ds) {
        const parts = d.value.trim().split(/\s+/);
        if (parts.length < 4) continue;
        const digestType = parseInt(parts[2], 10);
        const expected = parts[3];
        for (const k of ksks) {
          if (dsDigestMatch(input.ascii, k.rdata, digestType, expected)) return true;
        }
      }
      return false;
    })();

    const dnskeySig = rrsigRecords
      .map((r) => parseRrsigValue(r.value))
      .filter((s): s is NonNullable<typeof s> => s !== null && s.covered === 'DNSKEY');
    const sig = dnskeySig[0] ?? null;
    const expired = sig ? sig.expiration.getTime() < Date.now() : null;

    const validatedByResolver = adFlag ? adFlag.ad : null;
    const enabled =
      ds.length > 0 || dnskey.length > 0 || validatedByResolver === true;

    const chain: DnssecChainStep[] = [
      {
        step: 'DS record present at parent zone',
        status: ds.length > 0 ? 'pass' : enabled ? 'fail' : 'unknown',
        detail: ds.length
          ? `${ds.length} DS record(s) link this zone to the parent.`
          : 'No DS record found at the parent — the chain of trust cannot be established.',
      },
      {
        step: 'DNSKEY RRset present at zone apex',
        status: dnskey.length > 0 ? 'pass' : 'fail',
        detail: dnskey.length
          ? `${dnskey.length} DNSKEY record(s) (${ksks.length} KSK, ${dnskey.length - ksks.length} ZSK).`
          : 'No DNSKEY records published.',
      },
      {
        step: 'KSK ↔ DS digest verification (SHA-1/256/384)',
        status: digestVerified === null ? 'unknown' : digestVerified ? 'pass' : 'fail',
        detail:
          digestVerified === null
            ? 'Not enough data to verify the digest.'
            : digestVerified
              ? 'The DS digest cryptographically matches a KSK in the DNSKEY RRset.'
              : 'The DS digest does NOT match any DNSKEY KSK — the zone is likely broken (bofya/misconfiguration).',
      },
      {
        step: 'RRSIG covering DNSKEY RRset',
        status: sig ? 'pass' : dnskey.length ? 'fail' : 'unknown',
        detail: sig
          ? `Signed with algorithm ${sig.alg}${ALG_NAMES[sig.alg] ? ` (${ALG_NAMES[sig.alg]})` : ''}, key tag ${sig.keytag}.`
          : 'No RRSIG for the DNSKEY RRset was returned.',
      },
      {
        step: 'Validated by public validating resolver (AD flag)',
        status: validatedByResolver === null ? 'unknown' : validatedByResolver ? 'pass' : 'fail',
        detail:
          validatedByResolver === null
            ? 'Could not reach a validating resolver.'
            : validatedByResolver
              ? 'Google Public DNS (DoH) reports the Authenticated Data flag — full validation succeeded.'
              : 'A validating resolver did NOT set the AD flag — validation is failing somewhere.',
      },
      {
        step: 'Signature validity window',
        status: expired === null ? 'unknown' : expired ? 'fail' : 'pass',
        detail: sig ? `RRSIG expires ${sig.expiration.toISOString()}` : 'No signature to evaluate.',
      },
    ];

    const issues: Finding[] = [];
    if (!enabled) {
      issues.push(
        finding(
          'dnssec-off',
          'DNSSEC is not enabled',
          'info',
          'This domain has no DS, DNSKEY or signed answers. DNS responses can be spoofed by on-path attackers (cache poisoning).',
          'Enable DNSSEC at your registrar and DNS provider, then publish the DS record.',
          'https://icann.org/dnssec',
        ),
      );
    } else {
      if (digestVerified === false) {
        issues.push(
          finding('dnssec-broken-chain', 'DNSSEC chain of trust is broken', 'critical', 'The DS digest at the parent does not match any KSK in the DNSKEY RRset. Resolvers treating the zone as Bogus will fail validation.', 'Re-publish the correct DS record from your current KSK at the registrar.', 'https://datatracker.ietf.org/doc/html/rfc4035'),
        );
      }
      if (expired === true) {
        issues.push(finding('dnssec-expired', 'DNSSEC signature expired', 'high', `The DNSKEY RRSIG expired ${sig?.expiration.toISOString()}. Validating resolvers will treat answers as Bogus.`, 'Re-sign the zone and check your signer\'s automation (e.g. OpenDNSSEC / BIND inline-signing).'));
      }
      if (sig && (sig.alg === 5 || sig.alg === 7)) {
        issues.push(finding('dnssec-weak-alg', 'Legacy SHA-1 DNSSEC algorithm', 'medium', `Zone is signed with algorithm ${sig.alg} (RSA/SHA-1), which is deprecated (RFC 8624).`, 'Re-sign with algorithm 13 (ECDSA P-256/SHA-256), 15 (Ed25519) or 8 (RSA/SHA-256).'));
      }
      if (ds.length && digestVerified === true && validatedByResolver === false) {
        issues.push(finding('dnssec-validation-fail', 'Public resolvers fail to validate', 'high', 'Records exist and the DS digest matches, but a validating resolver did not return the AD flag. The zone may be signed inconsistently (e.g. RRSIG missing for some RRsets).', 'Run a full zone audit with a signer/validator (e.g. dnssec-checkzone, dnsviz.net).'));
      }
    }

    const algorithmsInfo: string[] = [];
    const algs = new Set<number>([...keytagRdata.map((k) => k.alg), ...(sig ? [sig.alg] : [])]);
    for (const a of algs) {
      const n = ALG_NAMES[a] || `Algorithm ${a}`;
      const note = a === 8 || a === 13 || a === 15 ? `${n} — modern, recommended` : a === 5 || a === 7 ? `${n} — deprecated (SHA-1)` : n;
      algorithmsInfo.push(note);
    }

    return {
      domain: input.ascii,
      enabled,
      ds,
      dnskey,
      rrsig: {
        present: sig !== null,
        records: rrsigRecords.slice(0, 10),
        algorithm: sig?.alg ?? null,
        algorithmName: sig ? ALG_NAMES[sig.alg] || `Algorithm ${sig.alg}` : null,
        expiration: sig ? sig.expiration.toISOString() : null,
        expired,
      },
      validatedByResolver,
      chain,
      algorithmsInfo,
      issues,
      timestamp: new Date().toISOString(),
    };
  });
}
