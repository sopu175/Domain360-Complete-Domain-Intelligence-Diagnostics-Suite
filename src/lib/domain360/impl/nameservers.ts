import { cached, TTL } from '../cache';
import { wireQuery } from '../dns-wire';
import { resolveHostIps, smartResolve } from '../resolver';
import { enrichIp } from './ipinfo';
import type { Finding, NameserverResult, NsServerInfo } from '../types';

const clean = (s: string): string => s.replace(/\.$/, '').toLowerCase();

function finding(id: string, title: string, severity: Finding['severity'], description: string, recommendation?: string): Finding {
  return { id, title, severity, category: 'nameservers', description, recommendation };
}

async function queryNsOnServer(server: string, name: string, type: 'NS' | 'SOA' | 'A' | 'AAAA') {
  const resp = await wireQuery({ name, type, server, timeoutMs: 3000, rd: false });
  return resp;
}

export async function analyzeNameservers(input: { ascii: string }): Promise<NameserverResult> {
  return cached(`ns:${input.ascii}`, TTL.nameservers, async (): Promise<NameserverResult> => {
    const issues: Finding[] = [];
    const labels = input.ascii.split('.');
    const parentZone = labels.length >= 2 ? labels.slice(1).join('.') : '';

    // --- 1. delegation from parent zone
    let parentNsUsed: string[] = [];
    let parentDelegationNs: string[] = [];
    let glueA: string[] = [];
    let parentNsIp: string | null = null;

    if (parentZone) {
      try {
        const parentNsResp = await smartResolve(parentZone, 'NS');
        parentNsUsed = parentNsResp.records
          .filter((r) => r.type === 'NS')
          .map((r) => clean(r.value))
          .slice(0, 4);
        if (parentNsUsed.length) {
          const parentIps = await resolveHostIps(parentNsUsed[0]);
          parentNsIp = parentIps.v4[0] ?? parentIps.v6[0] ?? null;
        }
        if (parentNsIp) {
          const [nsDel, aDel] = await Promise.allSettled([
            queryNsOnServer(parentNsIp, input.ascii, 'NS'),
            queryNsOnServer(parentNsIp, input.ascii, 'A'),
          ]);
          if (nsDel.status === 'fulfilled') {
            // delegation NS records for a child zone come from the AUTHORITY section
            parentDelegationNs = [...new Set(
              [...nsDel.value.answers, ...nsDel.value.authority]
                .filter((a) => a.typeName === 'NS')
                .map((a) => clean(a.data)),
            )].filter(Boolean);
          }
          if (aDel.status === 'fulfilled') {
            // glue A records arrive in the ADDITIONAL section
            glueA = [...new Set(
              [...aDel.value.answers, ...aDel.value.additional]
                .filter((a) => a.typeName === 'A')
                .map((a) => a.data),
            )];
          }
        }
      } catch {
        issues.push(
          finding(
            'parent-delegation-unknown',
            'Parent-zone delegation could not be verified',
            'info',
            `The authoritative servers of "${parentZone}" could not be queried directly, so delegation and glue records could not be inspected at the parent side.`,
            'This is often caused by resolver restrictions and does not necessarily indicate a problem.',
          ),
        );
      }
    }

    // --- 2. child NS set
    let childNs: string[] = [];
    try {
      const resp = await smartResolve(input.ascii, 'NS');
      childNs = [...new Set(resp.records.filter((r) => r.type === 'NS').map((r) => clean(r.value)))].slice(0, 8);
    } catch {
      /* handled below */
    }

    const union = [...new Set([...parentDelegationNs, ...childNs])].filter(Boolean).slice(0, 8);

    // --- 3. probe each authoritative server
    const authoritative: NsServerInfo[] = await Promise.all(
      union.map(async (ns): Promise<NsServerInfo> => {
        let ips: string[] = [];
        try {
          const hostIps = await resolveHostIps(ns);
          ips = [...hostIps.v4.slice(0, 2), ...hostIps.v6.slice(0, 1)];
        } catch {
          ips = [];
        }
        let responded = false;
        let responseTimeMs: number | null = null;
        let soaSerial: number | null = null;
        let nsRecords: string[] | null = null;

        for (const ip of ips.slice(0, 2)) {
          try {
            const soa = await queryNsOnServer(ip, input.ascii, 'SOA');
            responded = soa.rcodeName === 'NOERROR';
            responseTimeMs = soa.responseTimeMs;
            const soaVal = soa.answers.find((a) => a.typeName === 'SOA')?.data;
            if (soaVal) {
              const parts = soaVal.trim().split(/\s+/);
              const serial = parseInt(parts[2], 10);
              soaSerial = Number.isFinite(serial) ? serial : null;
            }
            try {
              const nsResp = await queryNsOnServer(ip, input.ascii, 'NS');
              nsRecords = nsResp.answers.map((a) => clean(a.data)).filter(Boolean);
            } catch {
              nsRecords = null;
            }
            break;
          } catch {
            continue;
          }
        }
        let country: string | null = null;
        let countryCode: string | null = null;
        let city: string | null = null;
        let asnOrg: string | null = null;

        if (ips.length > 0) {
          try {
            const geo = await enrichIp(ips[0]);
            country = geo.country;
            countryCode = geo.countryCode;
            city = geo.city;
            asnOrg = geo.asnOrg || geo.org;
          } catch {
            /* best effort */
          }
        }

        const isLame = ips.length === 0 || !responded;
        return { nameserver: ns, ips, responded, responseTimeMs, soaSerial, nsRecords, isLame, country, countryCode, city, asnOrg };
      }),
    );

    // --- 4. consistency
    const responded = authoritative.filter((a) => a.responded && a.nsRecords);
    let setsMatch = true;
    if (responded.length >= 2) {
      const first = [...responded[0].nsRecords!].sort().join('|');
      setsMatch = responded.every((a) => [...a.nsRecords!].sort().join('|') === first);
      if (parentDelegationNs.length && responded[0].nsRecords) {
        const childSet = [...responded[0].nsRecords].sort().join('|');
        const parentSet = [...new Set(parentDelegationNs)].sort().join('|');
        if (childSet !== parentSet) setsMatch = false;
      }
    }
    const serials = authoritative.map((a) => ({ nameserver: a.nameserver, serial: a.soaSerial }));
    const realSerials = serials.map((s) => s.serial).filter((s): s is number => s !== null);
    const serialsMatch = realSerials.length >= 2 ? new Set(realSerials).size === 1 : true;

    // --- 5. issues
    if (authoritative.length === 0) {
      issues.push(finding('ns-none', 'No nameservers found', 'critical', 'No NS records could be resolved for this domain.', 'Add at least two nameservers at your registrar.'));
    } else if (authoritative.length === 1) {
      issues.push(finding('ns-single', 'Only a single nameserver', 'medium', `"${authoritative[0].nameserver}" is the only nameserver. If it fails, the domain becomes unresolvable.`, 'Configure at least two nameservers on distinct networks for redundancy.'));
    }
    for (const a of authoritative) {
      if (a.isLame) {
        issues.push(finding(`ns-lame:${a.nameserver}`, `Unreachable nameserver: ${a.nameserver}`, 'medium', a.ips.length === 0 ? 'No public IP could be resolved for this nameserver — it may be lame-delegated.' : 'This nameserver did not answer an authoritative query for the domain.', 'Fix the nameserver configuration at your DNS provider or remove it from the delegation.'));
      }
    }
    if (!setsMatch && responded.length >= 2) {
      issues.push(finding('ns-set-mismatch', 'Nameserver sets are inconsistent', 'medium', 'Different authoritative servers report different NS sets for this zone, which can cause intermittent resolution problems.', 'Synchronize the NS set at your registrar and on every nameserver.'));
    }
    if (!serialsMatch) {
      issues.push(finding('ns-serial-mismatch', 'SOA serial numbers differ between nameservers', 'medium', `Serials: ${serials.map((s) => `${s.nameserver}=${s.serial ?? 'n/a'}`).join(', ')}. A zone transfer (AXFR/IXFR) may be stuck or misconfigured.`, 'Ensure zone transfers complete successfully to all secondaries.'));
    }
    if (parentDelegationNs.length) {
      for (const ns of parentDelegationNs) {
        if (ns.endsWith(`.${input.ascii}`) && glueA.length === 0) {
          issues.push(finding(`ns-no-glue:${ns}`, `Missing glue record for ${ns}`, 'low', `The parent zone delegates to "${ns}" which is inside the domain itself, but no glue A record was returned. In-bailiwick nameservers need glue to avoid bootstrapping loops.`, 'Add glue A/AAAA records for this nameserver at your registrar.'));
        }
      }
    }

    return {
      domain: input.ascii,
      delegation: {
        parentZone,
        parentNsUsed,
        parentDelegationNs,
        glueA,
        gluePresent: parentDelegationNs.length > 0 ? glueA.length > 0 : glueA.length > 0,
      },
      authoritative,
      consistency: { setsMatch, serialsMatch, serials },
      issues,
      timestamp: new Date().toISOString(),
    };
  });
}
