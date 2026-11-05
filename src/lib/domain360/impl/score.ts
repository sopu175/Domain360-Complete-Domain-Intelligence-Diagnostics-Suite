import type {
  DnssecResult, EmailResult, Finding, HttpResult, NameserverResult,
  ScoreCategory, ScoreResult, SslResult, StatusLevel, WhoisResult,
} from '../types';

export interface ScoreInputs {
  dnsQuick?: { a: boolean; aaaa: boolean; nsCount: number; caa: boolean; mxCount: number } | null;
  nameservers?: NameserverResult | null;
  ssl?: SslResult | null;
  email?: EmailResult | null;
  http?: HttpResult | null;
  whois?: WhoisResult | null;
  dnssec?: DnssecResult | null;
}

function cat(key: string, label: string, max: number, score: number, notes: string[]): ScoreCategory {
  const ratio = max > 0 ? score / max : 0;
  const status: StatusLevel = ratio >= 0.8 ? 'healthy' : ratio >= 0.5 ? 'warning' : max === 0 ? 'unknown' : 'critical';
  return { key, label, max, score: Math.max(0, Math.min(max, Math.round(score * 10) / 10)), status, notes };
}

function f(id: string, title: string, severity: Finding['severity'], category: string, description: string, recommendation?: string, reference?: string): Finding {
  return { id, title, severity, category, description, recommendation, reference };
}

const gradeFor = (total: number): string =>
  total >= 90 ? 'A' : total >= 75 ? 'B' : total >= 60 ? 'C' : total >= 40 ? 'D' : 'F';

export function computeScore(inputs: ScoreInputs): ScoreResult {
  const findings: Finding[] = [];
  const categories: ScoreCategory[] = [];

  // ---------------- DNS (20)
  const dq = inputs.dnsQuick;
  if (dq) {
    let s = 0;
    const notes: string[] = [];
    if (dq.a) { s += 5; } else {
      notes.push('No IPv4 A record — the domain may not resolve for many users.');
      findings.push(f('dns-no-a', 'No IPv4 (A) record', 'critical', 'dns', 'The domain does not resolve to an IPv4 address.', 'Add an A record pointing at your hosting.'));
    }
    if (dq.aaaa) { s += 2; notes.push('IPv6 available'); } else notes.push('No IPv6 (AAAA) record — IPv6-only visitors depend on NAT64 gateways.');
    if (dq.nsCount >= 2) { s += 4; } else if (dq.nsCount === 1) { s += 2; notes.push('Only one nameserver.'); findings.push(f('dns-ns1', 'Single nameserver', 'medium', 'dns', 'Only one nameserver is published; DNS fails entirely if it goes down.', 'Add at least a second nameserver.')); } else {
      notes.push('No nameservers found.');
    }
    if (dq.caa) { s += 3; } else notes.push('No CAA policy (any CA may issue certificates).');
    if (inputs.nameservers) {
      const lame = inputs.nameservers.authoritative.filter((a) => a.isLame).length;
      const total = inputs.nameservers.authoritative.length;
      if (total > 0 && lame === 0) { s += 3; } else if (total > 0) { s += 1; notes.push(`${lame}/${total} nameservers unreachable.`); }
      if (inputs.nameservers.consistency.serialsMatch) { s += 3; } else notes.push('SOA serials differ between nameservers.');
    } else {
      s += 3; // unknown → neutral
      notes.push('Nameserver analysis unavailable — neutral credit.');
    }
    categories.push(cat('dns', 'DNS health', 20, s, notes));
  } else {
    categories.push(cat('dns', 'DNS health', 20, 10, ['DNS data unavailable — neutral credit.']));
  }

  // ---------------- SSL/TLS (20)
  if (inputs.ssl) {
    const ssl = inputs.ssl;
    let s = 0;
    const notes: string[] = [];
    const base: Record<SslResult['status'], number> = {
      valid: 13, expiring_soon: 11, unverifiable: 8, expired: 2, invalid: 2, self_signed: 2, not_installed: 0,
    };
    s += base[ssl.status];
    if (ssl.status === 'valid') notes.push('Certificate valid');
    if (ssl.daysRemaining !== null) notes.push(`${ssl.daysRemaining} days remaining`);
    if (ssl.hostnameMatch) { s += 3; } else if (ssl.hostnameMatch === false) {
      notes.push('Hostname mismatch.');
      findings.push(f('ssl-hostname', 'Certificate hostname mismatch', 'high', 'ssl', 'The certificate presented is not valid for this hostname.', 'Reissue the certificate with the correct SANs.'));
    }
    if (ssl.chainComplete) { s += 2; } else if (ssl.chain.length > 0) { s += 1; notes.push('Chain may be incomplete (only leaf served).'); }
    const modern = ssl.protocols.find((p) => p.version === 'TLSv1.3' && p.supported);
    if (modern) { s += 2; notes.push('TLS 1.3 supported'); }
    if (ssl.status === 'expired') findings.push(f('ssl-expired', 'TLS certificate expired', 'critical', 'ssl', `Certificate expired ${ssl.cert?.validTo}.`, 'Renew immediately.'));
    if (ssl.status === 'self_signed') findings.push(f('ssl-selfsigned', 'Self-signed certificate', 'high', 'ssl', 'Visitors see certificate warnings.', 'Install a CA-issued certificate.'));
    if (ssl.status === 'not_installed') findings.push(f('ssl-none', 'HTTPS not available', 'high', 'ssl', 'No TLS service answered on port 443.', 'Install a TLS certificate.'));
    if (ssl.status === 'expiring_soon') findings.push(f('ssl-expiring', 'Certificate expiring soon', 'medium', 'ssl', `Only ${ssl.daysRemaining} days remain.`, 'Check auto-renewal.'));
    categories.push(cat('ssl', 'SSL / TLS', 20, s, notes));
  } else {
    categories.push(cat('ssl', 'SSL / TLS', 20, 10, ['SSL data unavailable — neutral credit.']));
  }

  // ---------------- Email (20)
  if (inputs.email) {
    const em = inputs.email;
    if (em.grade === 'N/A') {
      categories.push(cat('email', 'Email security', 20, 10, ['No mail configuration detected (no MX, SPF or DMARC) — email checks not applicable; neutral credit.']));
    } else {
      categories.push(cat('email', 'Email security', 20, em.score / 5, [
        `Email security score ${em.score}/100 (grade ${em.grade})`,
        em.dmarc?.policy ? `DMARC policy: ${em.dmarc.policy}` : 'No DMARC policy',
        em.spf ? `SPF policy: ${em.spf.policy}` : 'No SPF',
        em.dkim.length ? `${em.dkim.length} DKIM selector(s) found` : 'No DKIM key discovered',
      ]));
    }
    findings.push(...em.findings);
  } else {
    categories.push(cat('email', 'Email security', 20, 10, ['Email data unavailable — neutral credit.']));
  }

  // ---------------- HTTP security (15)
  if (inputs.http && inputs.http.statusCode !== null) {
    const http = inputs.http;
    const h = new Map(http.headers.map((x) => [x.name.toLowerCase(), x.value]));
    let s = 0;
    const notes: string[] = [];
    const add = (name: string, pts: number, label: string) => {
      if (h.has(name)) { s += pts; notes.push(`${label} present`); }
      else {
        notes.push(`${label} missing`);
        const refs: Record<string, string> = {
          'strict-transport-security': 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security',
          'content-security-policy': 'https://developer.mozilla.org/docs/Web/HTTP/CSP',
          'x-frame-options': 'https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options',
          'x-content-type-options': 'https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options',
          'referrer-policy': 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy',
          'permissions-policy': 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy',
        };
        const sev: Finding['severity'] = name === 'strict-transport-security' || name === 'content-security-policy' ? 'medium' : name === 'permissions-policy' ? 'info' : 'low';
        findings.push(f(`http-header:${name}`, `Missing security header: ${name}`, sev, 'http', `The response does not include ${name}.`, `Add the ${name} header to your web server configuration.`, refs[name]));
      }
    };
    add('strict-transport-security', 4, 'HSTS');
    add('content-security-policy', 3, 'CSP');
    add('x-frame-options', 2, 'X-Frame-Options');
    add('x-content-type-options', 2, 'X-Content-Type-Options');
    add('referrer-policy', 2, 'Referrer-Policy');
    add('permissions-policy', 1, 'Permissions-Policy');
    if (http.httpsRedirect) { s += 1; notes.push('HTTP → HTTPS redirect'); }
    categories.push(cat('http', 'HTTP security', 15, s, notes));
  } else {
    categories.push(cat('http', 'HTTP security', 15, 7, ['Website did not answer — neutral credit.']));
  }

  // ---------------- Nameservers & delegation (15)
  if (inputs.nameservers) {
    const ns = inputs.nameservers;
    let s = 0;
    const notes: string[] = [];
    const mediumIssues = ns.issues.filter((i) => i.severity === 'medium' || i.severity === 'high' || i.severity === 'critical');
    const lowIssues = ns.issues.filter((i) => i.severity === 'low');
    if (mediumIssues.length === 0) { s += 8; } else if (mediumIssues.length <= 2) { s += 4; notes.push(`${mediumIssues.length} delegation issue(s)`); }
    else { notes.push(`${mediumIssues.length} delegation issues`); }
    if (lowIssues.length === 0) s += 2; else s += 1;
    if (ns.consistency.serialsMatch) s += 3; else notes.push('SOA serial mismatch.');
    if (ns.consistency.setsMatch) s += 2; else notes.push('NS set mismatch between servers.');
    if (ns.delegation.parentDelegationNs.length) s += 1;
    else notes.push('Parent-zone delegation not directly verified.');
    categories.push(cat('ns', 'Nameservers & delegation', 15, s, notes));
    findings.push(...ns.issues);
  } else {
    categories.push(cat('ns', 'Nameservers & delegation', 15, 8, ['Nameserver data unavailable — neutral credit.']));
  }

  // ---------------- Registration (10)
  if (inputs.whois && (inputs.whois.daysToExpiry !== null || inputs.whois.registrar)) {
    const w = inputs.whois;
    let s = 0;
    const notes: string[] = [];
    const dte = w.daysToExpiry;
    if (dte !== null) {
      if (dte < 0) { notes.push('Domain is EXPIRED.'); findings.push(f('reg-expired', 'Domain registration has expired', 'critical', 'registration', 'The registration lapse means the domain can be lost entirely.', 'Renew at your registrar immediately.')); }
      else if (dte > 180) s += 6;
      else if (dte > 90) s += 5;
      else if (dte > 30) s += 3;
      else if (dte > 7) s += 1;
      else notes.push('Expiring within days!');
      if (dte <= 30 && dte >= 0) {
        findings.push(f('reg-expiring', 'Domain expiring soon', 'high', 'registration', `Domain expires in ${dte} days.`, 'Renew now; consider multi-year registration.'));
      }
      notes.push(`Expires in ${dte} days`);
    } else {
      s += 3; // unknown expiry → partial neutral
      notes.push('Expiry date unavailable.');
    }
    if (w.transferLocked) s += 2; else { notes.push('No clientTransferProhibited lock.'); findings.push(f('reg-unlocked', 'Transfer lock not set', 'low', 'registration', 'Domain status codes do not include a transfer lock — domain hijacking via unauthorized transfer is easier.', 'Enable clientTransferProhibited at your registrar.')); }
    if (w.ageDays !== null && w.ageDays > 365) { s += 2; notes.push(`Registered ${Math.floor(w.ageDays / 365)}+ years ago`); }
    categories.push(cat('reg', 'Registration health', 10, s, notes));
  } else {
    categories.push(cat('reg', 'Registration health', 10, 5, ['Registration data unavailable — neutral credit.']));
  }

  // ---------------- DNSSEC bonus/penalty folded into DNS notes
  if (inputs.dnssec) {
    const dnsCat = categories.find((c) => c.key === 'dns');
    if (dnsCat) {
      if (inputs.dnssec.enabled === true) {
        dnsCat.notes.push('DNSSEC enabled');
        if (inputs.dnssec.validatedByResolver === true) dnsCat.score = Math.min(20, dnsCat.score + 1);
      } else {
        dnsCat.notes.push('DNSSEC not enabled (informational)');
      }
      dnsCat.score = Math.min(dnsCat.max, dnsCat.score);
    }
    findings.push(...inputs.dnssec.issues);
  }

  const total = Math.round(categories.reduce((a, c) => a + c.score, 0));
  const clamped = Math.max(0, Math.min(100, total));
  const severityOrder: Finding['severity'][] = ['critical', 'high', 'medium', 'low', 'info', 'pass'];
  findings.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));

  return {
    total: clamped,
    grade: gradeFor(clamped),
    categories,
    findings: findings.slice(0, 40),
    methodology:
      'Score = DNS health (20) + SSL/TLS (20) + Email security (20) + HTTP security headers (15) + Nameserver & delegation health (15) + Registration health (10). ' +
      'When a module cannot be measured, it receives neutral partial credit and is marked Unknown instead of failing. ' +
      'Each category note explains which checks contributed or lost points.',
    disclaimer:
      'This score is an informational technical-configuration summary generated by automated passive checks. It is NOT a certified security assessment or audit.',
  };
}
