import net from 'node:net';
import dns from 'node:dns';
import { cached, TTL } from '../cache';
import { COMMON_DKIM_SELECTORS, MAIL_PROVIDERS, TIMEOUTS } from '../config';
import { resolveHostIps, smartResolve } from '../resolver';
import type { EmailMx, EmailResult, Finding } from '../types';

function finding(id: string, title: string, severity: Finding['severity'], description: string, recommendation?: string, reference?: string): Finding {
  return { id, title, severity, category: 'email', description, recommendation, reference };
}

const cleanTxt = (v: string): string => {
  // join chunked TXT strings & strip surrounding quotes
  let s = v.trim();
  if (s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);
  return s;
};

function extractTag(record: string, tag: string): string | null {
  const m = new RegExp(`(?:^|;)\\s*${tag}=([^;]+)`, 'i').exec(record);
  return m ? m[1].trim() : null;
}

function smtpProbe(host: string): Promise<{ reachable: boolean | null; banner: string | null }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port: 25 });
    let settled = false;
    let banner: string | null = null;
    const done = (reachable: boolean | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({ reachable, banner });
    };
    const timer = setTimeout(() => done(null), TIMEOUTS.smtp);
    socket.setTimeout(TIMEOUTS.smtp, () => done(null));
    socket.on('connect', () => {
      /* wait for banner */
    });
    socket.on('data', (d) => {
      banner = d.toString('utf8').split('\r\n')[0]?.slice(0, 120) || null;
      done(true);
    });
    socket.on('error', (e) => {
      const code = (e as { code?: string }).code || '';
      done(code === 'ECONNREFUSED' ? false : null);
    });
  });
}

function grade(score: number): string {
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export async function analyzeEmail(input: { ascii: string; selectors?: string[] }): Promise<EmailResult> {
  const cacheKey = `email:${input.ascii}:${(input.selectors || []).join(',')}`;
  return cached(cacheKey, TTL.dnsLong, async (): Promise<EmailResult> => {
    const findings: Finding[] = [];

    // ---------------- MX
    const mxRecords: EmailMx[] = [];
    try {
      const resp = await smartResolve(input.ascii, 'MX');
      const parsed = resp.records
        .filter((r) => r.type === 'MX')
        .map((r) => {
          const [p, host] = r.value.trim().split(/\s+/);
          return { priority: parseInt(p, 10) || 0, exchange: host.replace(/\.$/, '') };
        })
        .sort((a, b) => a.priority - b.priority)
        .slice(0, 8);
      await Promise.all(
        parsed.map(async (m) => {
          const ips: { ip: string; version: 4 | 6 }[] = [];
          try {
            const r = await resolveHostIps(m.exchange);
            r.v4.slice(0, 2).forEach((ip) => ips.push({ ip, version: 4 }));
            r.v6.slice(0, 1).forEach((ip) => ips.push({ ip, version: 6 }));
          } catch { /* keep empty */ }
          let ptr: string | null = null;
          if (ips[0]) {
            try {
              ptr = (await dns.promises.reverse(ips[0].ip))[0] || null;
            } catch { /* none */ }
          }
          const hay = `${m.exchange} ${ptr || ''}`.toLowerCase();
          const provider = MAIL_PROVIDERS.find((mp) => mp.patterns.some((p) => hay.includes(p)));
          const smtp = ips[0] ? await smtpProbe(ips[0].ip).catch(() => ({ reachable: null, banner: null })) : { reachable: null, banner: null };
          mxRecords.push({
            exchange: m.exchange,
            priority: m.priority,
            ips,
            ptr,
            providerGuess: provider?.name || null,
            reachable: smtp.reachable,
            banner: smtp.banner,
          });
        }),
      );
      mxRecords.sort((a, b) => a.priority - b.priority);
    } catch { /* no MX */ }

    if (!mxRecords.length) {
      findings.push(finding('email-no-mx', 'No MX records', 'info', 'This domain does not announce mail exchangers — it likely does not receive email at @' + input.ascii + '.', 'If you intend to receive email, add MX records; otherwise publish a null MX ("0 .") to signal intent (RFC 7505).'));
    } else if (mxRecords.length === 1) {
      findings.push(finding('email-mx-single', 'Single mail exchanger', 'low', 'Only one MX host is published; mail bounces if it is down.', 'Add a secondary MX for redundancy.'));
    }

    // ---------------- SPF
    let spf: EmailResult['spf'] = null;
    try {
      const resp = await smartResolve(input.ascii, 'TXT');
      const txts = resp.records.filter((r) => r.type === 'TXT').map((r) => cleanTxt(r.value));
      const spfRecords = txts.filter((t) => /^v=spf1/i.test(t));
      if (spfRecords.length === 1) {
        const record = spfRecords[0];
        const mechanisms = record.split(/\s+/).slice(1);
        const lookupMechs = mechanisms.filter((m) => /^(include:|a\b|mx\b|ptr\b|exists:|redirect=)/i.test(m)).length;
        const allM = mechanisms.find((m) => /^[-~?+]?all$/i.test(m));
        const policy: EmailResult['spf'] extends null ? never : 'none' | 'neutral' | 'softfail' | 'fail' | 'pass' =
          allM === '-all' ? 'fail' : allM === '~all' ? 'softfail' : allM === '?all' ? 'neutral' : 'pass';
        const issues: string[] = [];
        if (lookupMechs > 10) issues.push(`SPF requires ${lookupMechs} DNS lookups — the RFC 7208 limit is 10; recipients may return PermError.`);
        if (!allM) issues.push('SPF record has no "all" mechanism — default is +all (anyone can spoof this domain).');
        if (allM === '+all') issues.push('SPF ends with +all — this authorizes the entire internet to send as your domain.');
        spf = { record, valid: issues.length === 0, policy, dnsLookups: lookupMechs, mechanisms, issues };
        if (!record || issues.some((i) => i.includes('+all') || i.includes('no "all"'))) {
          findings.push(finding('spf-permissive', 'SPF policy is permissive or broken', 'high', issues.join(' '), 'End the SPF record with -all (strict) or ~all (softfail).', 'https://datatracker.ietf.org/doc/html/rfc7208'));
        } else if (lookupMechs > 10) {
          findings.push(finding('spf-lookups', 'SPF lookup limit exceeded', 'medium', issues[0], 'Flatten includes or remove unused mechanisms.', 'https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4'));
        }
      } else if (spfRecords.length > 1) {
        spf = { record: spfRecords.join(' | '), valid: false, policy: 'pass', dnsLookups: 0, mechanisms: [], issues: ['Multiple SPF records found — this is invalid; recipients must treat it as PermError.'] };
        findings.push(finding('spf-multi', 'Multiple SPF records', 'high', 'More than one v=spf1 record exists at the apex. This is a configuration error.', 'Merge the records into a single v=spf1 record.'));
      } else if (mxRecords.length) {
        findings.push(finding('spf-missing', 'No SPF record', 'high', 'The domain sends/receives mail but publishes no SPF policy, making sender spoofing trivial.', 'Publish e.g. "v=spf1 include:_spf.google.com -all" matching your provider.', 'https://datatracker.ietf.org/doc/html/rfc7208'));
      }
    } catch { /* TXT lookup failed */ }

    // ---------------- DMARC
    let dmarc: EmailResult['dmarc'] = null;
    try {
      const resp = await smartResolve(`_dmarc.${input.ascii}`, 'TXT');
      const rec = resp.records.find((r) => /^v\s*=\s*DMARC1/i.test(cleanTxt(r.value)));
      if (rec) {
        const record = cleanTxt(rec.value);
        const p = extractTag(record, 'p');
        const sp = extractTag(record, 'sp');
        const pctRaw = extractTag(record, 'pct');
        const rua = extractTag(record, 'rua');
        const valid = !!p && ['none', 'quarantine', 'reject'].includes(p);
        dmarc = {
          record, policy: p || null, subdomainPolicy: sp || null,
          pct: pctRaw ? parseInt(pctRaw, 10) || null : null,
          rua: rua || null, valid,
          issues: valid ? [] : ['DMARC record present but p= tag is missing/invalid.'],
        };
        if (p === 'none') {
          findings.push(finding('dmarc-none', 'DMARC policy is p=none', 'medium', 'Reports are collected but nothing enforces the policy — spoofed mail is still delivered.', 'After monitoring reports, move to p=quarantine then p=reject.', 'https://datatracker.ietf.org/doc/html/rfc7489'));
        }
        if (!rua) {
          findings.push(finding('dmarc-no-rua', 'DMARC has no aggregate reporting (rua)', 'low', 'Without rua= you never see authentication reports.', 'Add rua=mailto:dmarc@yourdomain.'));
        }
      }
    } catch { /* none */ }
    if (!dmarc && mxRecords.length) {
      findings.push(finding('dmarc-missing', 'No DMARC record', 'high', 'Without DMARC, receivers have no policy for unauthenticated mail claiming to be from this domain, and you get no visibility.', 'Publish _dmarc TXT: "v=DMARC1; p=quarantine; rua=mailto:dmarc@' + input.ascii + '"', 'https://datatracker.ietf.org/doc/html/rfc7489'));
    }

    // ---------------- DKIM
    const dkim: EmailResult['dkim'] = [];
    const selectors = [...new Set([...(input.selectors || []), ...COMMON_DKIM_SELECTORS])]
      .map((s) => s.trim().toLowerCase())
      .filter((s) => /^[a-z0-9._-]{1,63}$/i.test(s))
      .slice(0, 30);
    const dkimResults = await Promise.allSettled(
      selectors.map(async (sel) => {
        const resp = await smartResolve(`${sel}._domainkey.${input.ascii}`, 'TXT');
        const rec = resp.records.find((r) => /(^|[\s;"])p\s*=/i.test(cleanTxt(r.value)) && /v\s*=\s*DKIM1|p\s*=/i.test(cleanTxt(r.value)));
        if (!rec) return null;
        const record = cleanTxt(rec.value);
        const pTag = extractTag(record, 'p') || '';
        const kTag = extractTag(record, 'k');
        const keyBits = kTag?.toLowerCase() === 'ed25519' ? 256 : pTag ? Math.round((pTag.length * 3) / 4 * 8) : null;
        return { selector: sel, record: record.slice(0, 400), valid: true, keyBits, algorithm: kTag || 'rsa' };
      }),
    );
    for (const r of dkimResults) {
      if (r.status === 'fulfilled' && r.value) dkim.push(r.value);
      if (dkim.length >= 8) break;
    }
    if (mxRecords.length && dkim.length === 0) {
      findings.push(finding('dkim-missing', 'No DKIM key found (common selectors)', 'medium', `None of ${selectors.length} common selectors published a key. If you sign mail with an unusual selector it was not discovered — enter it manually.`, 'Configure DKIM signing in your mail provider and publish the public key.', 'https://datatracker.ietf.org/doc/html/rfc6376'));
    }

    // ---------------- BIMI / MTA-STS / TLS-RPT
    let bimi: EmailResult['bimi'] = null;
    try {
      const resp = await smartResolve(`default._bimi.${input.ascii}`, 'TXT');
      const rec = resp.records.find((r) => /^v\s*=\s*BIMI1/i.test(cleanTxt(r.value)));
      bimi = rec ? { record: cleanTxt(rec.value), valid: true } : { record: null, valid: false };
    } catch {
      bimi = { record: null, valid: false };
    }

    let mtaSts: EmailResult['mtaSts'] = null;
    try {
      const resp = await smartResolve(`_mta-sts.${input.ascii}`, 'TXT');
      const rec = resp.records.find((r) => /^v\s*=\s*STSv1/i.test(cleanTxt(r.value)));
      const policyUrl = `https://mta-sts.${input.ascii}/.well-known/mta-sts.txt`;
      let policy: string | null = null;
      if (rec) {
        try {
          const r = await fetch(policyUrl, { signal: AbortSignal.timeout(6000), cache: 'no-store' });
          if (r.ok) policy = (await r.text()).slice(0, 4000);
        } catch { /* policy unreachable */ }
      }
      mtaSts = { dnsRecord: rec ? cleanTxt(rec.value) : null, policy, policyUrl };
      if (rec && !policy) {
        findings.push(finding('mtasts-policy-missing', 'MTA-STS DNS record exists but policy is unreachable', 'low', `The HTTPS policy at ${policyUrl} could not be fetched.`, 'Host the policy file over HTTPS as required by RFC 8461.'));
      }
    } catch {
      mtaSts = { dnsRecord: null, policy: null, policyUrl: `https://mta-sts.${input.ascii}/.well-known/mta-sts.txt` };
    }

    let tlsRpt: EmailResult['tlsRpt'] = null;
    try {
      const resp = await smartResolve(`_smtp._tls.${input.ascii}`, 'TXT');
      const rec = resp.records.find((r) => /^v\s*=\s*TLSRPTv1/i.test(cleanTxt(r.value)));
      tlsRpt = rec ? { record: cleanTxt(rec.value), rua: extractTag(cleanTxt(rec.value), 'rua'), valid: true } : { record: null, rua: null, valid: false };
    } catch {
      tlsRpt = { record: null, rua: null, valid: false };
    }

    // ---------------- score
    let score = 0;
    if (mxRecords.length) score += 15;
    if (mxRecords.length >= 2) score += 5;
    if (spf) {
      score += 10;
      if (spf.valid) score += 5;
      if (spf.policy === 'fail') score += 10;
      else if (spf.policy === 'softfail') score += 7;
      else if (spf.policy === 'neutral') score += 3;
    }
    if (dmarc?.valid) {
      score += 10;
      if (dmarc.policy === 'reject') score += 12;
      else if (dmarc.policy === 'quarantine') score += 8;
      else if (dmarc.policy === 'none') score += 3;
      if (dmarc.rua) score += 3;
    }
    if (dkim.length) score += 15;
    if (dkim.length >= 2) score += 5;
    if (mtaSts?.dnsRecord) score += 8;
    if (tlsRpt?.valid) score += 7;
    score = Math.min(100, score);

    const noMail = !mxRecords.length && !spf && !dmarc;
    if (noMail) {
      score = 0;
      findings.push(finding('email-none', 'No email configuration detected', 'info', 'No MX, SPF or DMARC records — this domain apparently does not use email. Score is informational.', undefined));
    }

    return {
      domain: input.ascii,
      mx: mxRecords,
      spf,
      dmarc,
      dkim,
      bimi,
      mtaSts,
      tlsRpt,
      score,
      grade: noMail ? 'N/A' : grade(score),
      findings,
      timestamp: new Date().toISOString(),
    };
  });
}
