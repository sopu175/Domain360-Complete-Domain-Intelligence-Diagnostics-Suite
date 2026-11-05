import net from 'node:net';
import { randomInt } from 'node:crypto';
import { cached, TTL } from '../cache';
import { entitlement, USER_AGENT } from '../config';
import { buildQuery, TYPE_NUMBERS } from '../dns-wire';
import { resolveHostIps, smartResolve } from '../resolver';
import { diagnoseHttp } from './http';
import { inspectSsl } from './ssl';
import { analyzeDnssec } from './dnssec';
import type { Finding, SecurityResult, Severity } from '../types';

function finding(id: string, title: string, severity: Severity, description: string, recommendation?: string, reference?: string): Finding {
  return { id, title, severity, category: 'security', description, recommendation, reference };
}

const HEADER_CHECKS: {
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
}[] = [
  { name: 'strict-transport-security', severity: 'medium', description: 'HSTS forces browsers to use HTTPS, preventing downgrade and cookie-hijacking attacks.', recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains' },
  { name: 'content-security-policy', severity: 'medium', description: 'CSP restricts which scripts/resources the page may load, mitigating XSS.', recommendation: 'Add a Content-Security-Policy header (start in report-only mode).' },
  { name: 'x-frame-options', severity: 'low', description: 'Prevents clickjacking by controlling who may frame the page.', recommendation: 'Add: X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors).' },
  { name: 'x-content-type-options', severity: 'low', description: 'Stops browsers from MIME-sniffing responses away from the declared type.', recommendation: 'Add: X-Content-Type-Options: nosniff.' },
  { name: 'referrer-policy', severity: 'low', description: 'Controls how much referrer data leaks to other sites.', recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin.' },
  { name: 'permissions-policy', severity: 'info', description: 'Restricts powerful browser features (camera, geolocation…) to chosen origins.', recommendation: 'Add a Permissions-Policy header limiting unused features.' },
];

interface TcpDnsResult { rcode: number; anCount: number }

/** Minimal AXFR probe over TCP (only used with explicit user authorization). */
function tcpDnsQuery(server: string, name: string, type: number, timeoutMs = 6000): Promise<TcpDnsResult> {
  return new Promise((resolve, reject) => {
    const q = buildQuery({ name, type, rd: false, edns: false });
    const len = Buffer.alloc(2);
    len.writeUInt16BE(q.length, 0);
    const socket = net.createConnection({ host: server, port: 53 });
    let buf = Buffer.alloc(0);
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      fn();
    };
    const timer = setTimeout(() => done(() => reject(new Error('timeout'))), timeoutMs);
    socket.on('connect', () => socket.write(Buffer.concat([len, q])));
    socket.on('data', (d) => {
      buf = Buffer.concat([buf, Buffer.isBuffer(d) ? d : Buffer.from(String(d))]);
      if (buf.length >= 2) {
        const need = buf.readUInt16BE(0);
        if (buf.length >= need + 2) {
          const msg = buf.subarray(2, need + 2);
          if (msg.length >= 12) {
            const rcode = msg[3] & 0x0f;
            const anCount = msg.readUInt16BE(6);
            done(() => resolve({ rcode, anCount }));
          } else {
            done(() => reject(new Error('short response')));
          }
        }
      }
    });
    socket.on('error', (e) => done(() => reject(e)));
    socket.on('close', () => done(() => reject(new Error('closed early'))));
  });
}

export async function scanSecurity(input: { ascii: string; authorizeAxfr?: boolean }): Promise<SecurityResult> {
  const cacheKey = `security:${input.ascii}:${input.authorizeAxfr ? 'axfr' : 'no'}`;
  return cached(cacheKey, TTL.security, async (): Promise<SecurityResult> => {
    const findings: Finding[] = [];

    const [httpRes, sslRes, dnssecRes, caaRes] = await Promise.allSettled([
      diagnoseHttp({ ascii: input.ascii }),
      inspectSsl({ ascii: input.ascii }),
      analyzeDnssec({ ascii: input.ascii }),
      smartResolve(input.ascii, 'CAA'),
    ]);

    const http = httpRes.status === 'fulfilled' ? httpRes.value : null;
    const ssl = sslRes.status === 'fulfilled' ? sslRes.value : null;
    const dnssec = dnssecRes.status === 'fulfilled' ? dnssecRes.value : null;
    const caaRecords = caaRes.status === 'fulfilled' ? caaRes.value.records.filter((r) => r.type === 'CAA').map((r) => r.value) : [];

    const headerMap = new Map<string, string>();
    if (http) for (const h of http.headers) headerMap.set(h.name.toLowerCase(), h.value);

    // ---- HTTPS enforcement
    let httpsEnforced: boolean | null = null;
    if (http) httpsEnforced = http.httpsRedirect;
    if (httpsEnforced === false) {
      findings.push(finding('https-not-enforced', 'HTTP traffic is not redirected to HTTPS', 'medium', 'Plain HTTP requests are answered without upgrading to HTTPS — visitors on http:// remain unencrypted.', 'Redirect all HTTP traffic (301) to HTTPS and enable HSTS.', 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security'));
    }

    // ---- TLS
    if (ssl) {
      if (ssl.status === 'expired') findings.push(finding('tls-expired', 'TLS certificate has expired', 'critical', `The certificate expired on ${ssl.cert?.validTo}. Browsers show a full-page warning.`, 'Renew the certificate immediately (Let\'s Encrypt supports automated renewal).'));
      if (ssl.status === 'self_signed') findings.push(finding('tls-self-signed', 'Self-signed certificate', 'high', 'The certificate is not issued by a trusted CA; visitors see warnings.', 'Install a certificate from a public CA (e.g. Let\'s Encrypt).'));
      if (ssl.status === 'invalid') findings.push(finding('tls-invalid', 'Certificate validation failed', 'high', ssl.errors.join(' ') || 'The certificate could not be validated for this hostname.', 'Reissue the certificate for the correct hostname.'));
      if (ssl.status === 'expiring_soon') findings.push(finding('tls-expiring', 'Certificate expiring soon', 'medium', `Only ${ssl.daysRemaining} days remain until expiry.`, 'Confirm your auto-renewal is working.'));
      if (ssl.status === 'not_installed') findings.push(finding('tls-none', 'No TLS/HTTPS available', 'high', 'Port 443 did not answer a TLS handshake — the site is served without encryption.', 'Install a TLS certificate and serve the site over HTTPS.'));
      const legacy = ssl.protocols.filter((p) => p.supported && (p.version === 'TLSv1' || p.version === 'TLSv1.1'));
      if (legacy.length) {
        findings.push(finding('tls-legacy', `Legacy protocol enabled: ${legacy.map((p) => p.version).join(', ')}`, 'medium', 'TLS 1.0/1.1 are deprecated (RFC 8996) and vulnerable to downgrade attacks.', 'Disable TLS 1.0/1.1; keep TLS 1.2+ only.', 'https://datatracker.ietf.org/doc/html/rfc8996'));
      }
    }

    // ---- DNSSEC
    if (dnssec && dnssec.enabled === false) {
      findings.push(finding('dnssec-off', 'DNSSEC not enabled', 'medium', 'DNS answers are unsigned and can be spoofed (cache poisoning).', 'Enable DNSSEC at your registrar/DNS provider and publish the DS record.', 'https://icann.org/dnssec'));
    }
    if (dnssec) {
      findings.push(...dnssec.issues.filter((i) => i.severity !== 'info'));
    }

    // ---- CAA
    const caa = {
      records: caaRecords,
      allowsLetsEncrypt: caaRecords.length
        ? caaRecords.some((r) => /letsencrypt/i.test(r))
        : null,
    };
    if (!caaRecords.length) {
      findings.push(finding('caa-missing', 'No CAA policy', 'low', 'Any certificate authority may issue certificates for this domain.', 'Publish CAA records (e.g. 0 issue "letsencrypt.org") to restrict issuance.', 'https://datatracker.ietf.org/doc/html/rfc8659'));
    }

    // ---- security headers
    const headersChecked = HEADER_CHECKS.map((c) => {
      const value = headerMap.get(c.name) || null;
      return { name: c.name, present: !!value, value, severity: c.severity, description: c.description, recommendation: c.recommendation };
    });
    for (const h of headersChecked) {
      if (!h.present && h.severity !== 'info') {
        findings.push(finding(`header-missing:${h.name}`, `Missing security header: ${h.name}`, h.severity, h.description, h.recommendation));
      }
    }
    const hstsValue = headerMap.get('strict-transport-security');
    const hsts = {
      present: !!hstsValue,
      maxAge: hstsValue ? parseInt(/max-age=(\d+)/i.exec(hstsValue)?.[1] || '', 10) || null : null,
      includeSubdomains: !!hstsValue && /includeSubDomains/i.test(hstsValue),
      preload: !!hstsValue && /preload/i.test(hstsValue),
    };
    if (hsts.present && hsts.maxAge !== null && hsts.maxAge < 15768000) {
      findings.push(finding('hsts-short', 'HSTS max-age is short', 'low', `max-age is ${hsts.maxAge}s — recommend at least 18 weeks (15768000s).`, 'Increase max-age to 31536000.'));
    }
    const cspValue = headerMap.get('content-security-policy');
    const cspOnlyReport = headerMap.get('content-security-policy-report-only');
    const csp = {
      present: !!(cspValue || cspOnlyReport),
      reportOnly: !cspValue && !!cspOnlyReport,
      value: cspValue || cspOnlyReport || null,
    };
    if (csp.reportOnly) {
      findings.push(finding('csp-report-only', 'CSP is report-only', 'info', 'Content-Security-Policy-Report-Only does not enforce anything yet.', 'Review violation reports, then switch to enforcing mode.'));
    }
    const serverHeader = headerMap.get('server');
    if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
      findings.push(finding('server-version', 'Server header discloses version', 'info', `"Server: ${serverHeader}" reveals software version, helping attackers target known CVEs.`, 'Remove the version from the Server header.'));
    }

    // ---- exposed sensitive files (existence only; content is never returned)
    const exposedFiles: SecurityResult['exposedFiles'] = [];
    const probes = ['/.env', '/.git/HEAD', '/config.php.bak', '/.DS_Store'];
    const origin = http?.finalUrl ? new URL(http.finalUrl).origin : `https://${input.ascii}`;
    await Promise.all(
      probes.map(async (path) => {
        try {
          const res = await fetch(origin + path, {
            signal: AbortSignal.timeout(6000),
            redirect: 'manual',
            headers: { 'user-agent': USER_AGENT },
          });
          let exposed = res.status === 200;
          if (exposed && path === '/.git/HEAD') {
            const text = (await res.text()).slice(0, 200);
            exposed = /^ref:\s*refs\//.test(text);
          } else if (exposed && path === '/.env') {
            const text = (await res.text()).slice(0, 400);
            // only flag if it truly looks like an env file
            exposed = /^[A-Z0-9_]+=/m.test(text);
          } else if (res.status !== 200) {
            exposed = false;
          }
          try {
            res.body?.cancel().catch(() => {});
          } catch { /* already closed */ }
          exposedFiles.push({ path, status: res.status, exposed });
        } catch {
          exposedFiles.push({ path, status: null, exposed: false });
        }
      }),
    );
    for (const f of exposedFiles) {
      if (f.exposed) {
        findings.push(finding(`exposed:${f.path}`, `Sensitive file publicly readable: ${f.path}`, 'critical', `${origin}${f.path} returns HTTP 200 with content that looks like a real ${f.path === '/.git/HEAD' ? 'Git repository' : 'configuration file'}.`, 'Restrict access to this path immediately (deny in web server config) and rotate any secrets it may contain.'));
      }
    }

    // ---- zone transfer (authorization-gated)
    let zoneTransfer: SecurityResult['zoneTransfer'] | null = null;
    if (input.authorizeAxfr && entitlement('zoneTransferCheck')) {
      const servers: string[] = [];
      try {
        const ns = await smartResolve(input.ascii, 'NS');
        const names = ns.records.filter((r) => r.type === 'NS').map((r) => r.value.replace(/\.$/, '')).slice(0, 3);
        const ips = await Promise.all(names.map((n) => resolveHostIps(n).then((r) => r.v4[0]).catch(() => null)));
        ips.forEach((ip) => ip && servers.push(ip));
      } catch { /* none */ }
      let vulnerable: boolean | null = null;
      for (const server of servers.slice(0, 2)) {
        try {
          const res = await tcpDnsQuery(server, input.ascii, TYPE_NUMBERS.AXFR || 252);
          if (res.rcode === 0 && res.anCount > 1) {
            vulnerable = true;
            break;
          }
          vulnerable = false;
        } catch {
          /* server refused/timed out */
        }
      }
      zoneTransfer = { tested: true, authorized: true, vulnerable, servers };
      if (vulnerable) {
        findings.push(finding('axfr-open', 'DNS zone transfer (AXFR) is open', 'critical', `Nameserver ${servers.join(', ')} transferred the whole zone — attackers can enumerate every host.`, 'Restrict AXFR to approved secondary IPs (allow-transfer).', 'https://datatracker.ietf.org/doc/html/rfc5936'));
      }
    } else {
      zoneTransfer = { tested: false, authorized: !!input.authorizeAxfr, vulnerable: null, servers: [] };
    }

    // ---- email (light presence checks)
    try {
      const [txt, dmarcTxt] = await Promise.allSettled([
        smartResolve(input.ascii, 'TXT'),
        smartResolve(`_dmarc.${input.ascii}`, 'TXT'),
      ]);
      const hasSpf = txt.status === 'fulfilled' && txt.value.records.some((r) => /^v=spf1/i.test(r.value));
      const hasDmarc = dmarcTxt.status === 'fulfilled' && dmarcTxt.value.records.some((r) => /^v\s*=\s*DMARC1/i.test(r.value));
      if (!hasSpf) findings.push(finding('email-no-spf', 'No SPF record', 'medium', 'Sender spoofing of this domain is trivially possible.', 'Publish an SPF record.', 'https://datatracker.ietf.org/doc/html/rfc7208'));
      if (!hasDmarc) findings.push(finding('email-no-dmarc', 'No DMARC record', 'medium', 'Receivers have no domain-owner policy for unauthenticated mail.', 'Publish a DMARC record.', 'https://datatracker.ietf.org/doc/html/rfc7489'));
    } catch { /* ignore */ }

    // ---- score
    const weight: Record<Severity, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0, pass: 0 };
    const penalty = findings.reduce((acc, f) => acc + (weight[f.severity] || 0), 0);
    const score = Math.max(0, 100 - penalty);
    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

    return {
      domain: input.ascii,
      score,
      grade,
      httpsEnforced,
      dnssecEnabled: dnssec?.enabled ?? null,
      caa,
      hsts,
      csp,
      headersChecked,
      exposedFiles,
      zoneTransfer,
      findings,
      timestamp: new Date().toISOString(),
    };
  });
}

export { randomInt };
