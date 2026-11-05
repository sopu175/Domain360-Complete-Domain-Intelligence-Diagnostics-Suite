import { db } from '@/lib/db';
import { cached, TTL } from '../cache';
import { smartResolve } from '../resolver';
import { diagnoseHttp } from './http';
import { inspectSsl } from './ssl';
import { lookupRegistration } from './rdap';
import { lookupIpInfo } from './ipinfo';
import { analyzeEmail } from './email';
import { analyzeNameservers } from './nameservers';
import { analyzeDnssec } from './dnssec';
import { computeScore } from './score';
import type { OverviewResult, StatusLevel } from '../types';

const HOSTING_PROVIDER_KEYS = ['org', 'isp'] as const;

function guessDnsProvider(ns: string[]): string | null {
  const joined = ns.join(' ').toLowerCase();
  const map: [string, string][] = [
    ['cloudflare', 'Cloudflare DNS'],
    ['googledomains', 'Google Cloud DNS'],
    ['google', 'Google Cloud DNS'],
    ['awsdns', 'AWS Route 53'],
    ['azure', 'Azure DNS'],
    ['dnsmadeeasy', 'DNS Made Easy'],
    ['nsone', 'NS1'],
    ['ultradns', 'Neustar UltraDNS'],
    ['dynect', 'Oracle Dyn'],
    ['digitalocean', 'DigitalOcean DNS'],
    ['linode', 'Linode DNS'],
    ['namecheap', 'Namecheap'],
    ['domaincontrol', 'GoDaddy'],
    ['godaddy', 'GoDaddy'],
    ['gandi', 'Gandi'],
    ['dnsimple', 'DNSimple'],
    ['hover', 'Hover'],
    ['wixdns', 'Wix'],
    ['squarespace', 'Squarespace'],
    ['vercel', 'Vercel'],
    ['netlify', 'Netlify'],
    ['hostinger', 'Hostinger'],
    ['siteground', 'SiteGround'],
    ['rackner', 'RackNerd'],
    ['hetzner', 'Hetzner'],
    ['ovh', 'OVHcloud'],
    ['transip', 'TransIP'],
    ['infomaniak', 'Infomaniak'],
    ['porkbun', 'Porkbun'],
    ['dnsowl', 'NameSilo'],
    ['registrar-servers', 'Namecheap'],
  ];
  for (const [needle, label] of map) {
    if (joined.includes(needle)) return label;
  }
  return null;
}

function guessMailProvider(mx: string[]): string | null {
  const joined = mx.join(' ').toLowerCase();
  const map: [string, string][] = [
    ['google', 'Google Workspace'], ['googlemail', 'Google Workspace'],
    ['outlook', 'Microsoft 365'], ['protection.outlook', 'Microsoft 365'],
    ['zoho', 'Zoho Mail'], ['proton', 'Proton Mail'], ['yahoodns', 'Yahoo'],
    ['icloud', 'Apple iCloud Mail'], ['mimecast', 'Mimecast'],
    ['pphosted', 'Proofpoint'], ['proofpoint', 'Proofpoint'],
    ['barracuda', 'Barracuda'], ['mailgun', 'Mailgun'], ['sendgrid', 'SendGrid'],
    ['amazonaws', 'Amazon WorkMail/SES'], ['messagingengine', 'Fastmail'],
    ['mxroute', 'MXroute'], ['privateemail', 'PrivateEmail'],
  ];
  for (const [needle, label] of map) {
    if (joined.includes(needle)) return label;
  }
  return null;
}

export async function buildOverview(input: { ascii: string; display: string }): Promise<OverviewResult> {
  return cached(`overview:${input.ascii}`, TTL.overview, async (): Promise<OverviewResult> => {
    const [aRes, aaaaRes, mxRes, txtRes, nsRes, caaRes] = await Promise.allSettled([
      smartResolve(input.ascii, 'A'),
      smartResolve(input.ascii, 'AAAA'),
      smartResolve(input.ascii, 'MX'),
      smartResolve(input.ascii, 'TXT'),
      smartResolve(input.ascii, 'NS'),
      smartResolve(input.ascii, 'CAA'),
    ]);

    const values = (r: PromiseSettledResult<Awaited<ReturnType<typeof smartResolve>>>) =>
      r.status === 'fulfilled' ? r.value.records : [];
    const rcodeOf = (r: PromiseSettledResult<Awaited<ReturnType<typeof smartResolve>>>) =>
      r.status === 'fulfilled' ? r.value.rcode : 'FAILED';

    const aRecords = values(aRes).filter((r) => r.type === 'A');
    const aaaaRecords = values(aaaaRes).filter((r) => r.type === 'AAAA');
    const mxRecords = values(mxRes).filter((r) => r.type === 'MX');
    const nsRecords = values(nsRes).filter((r) => r.type === 'NS');
    const caaRecords = values(caaRes).filter((r) => r.type === 'CAA');
    const txtRecords = values(txtRes).filter((r) => r.type === 'TXT');

    const nx = rcodeOf(aRes) === 'NXDOMAIN';

    const [whoisRes, sslRes, httpRes, ipRes, emailRes, nsAnalysisRes, dnssecRes] = await Promise.allSettled([
      lookupRegistration({ ascii: input.ascii, display: input.display }),
      inspectSsl({ ascii: input.ascii }),
      diagnoseHttp({ ascii: input.ascii }),
      lookupIpInfo({ query: input.ascii, isIp: 0 }),
      analyzeEmail({ ascii: input.ascii }),
      analyzeNameservers({ ascii: input.ascii }),
      analyzeDnssec({ ascii: input.ascii }),
    ]);

    const whois = whoisRes.status === 'fulfilled' ? whoisRes.value : null;
    const ssl = sslRes.status === 'fulfilled' ? sslRes.value : null;
    const http = httpRes.status === 'fulfilled' ? httpRes.value : null;
    const ip = ipRes.status === 'fulfilled' ? ipRes.value : null;
    const email = emailRes.status === 'fulfilled' ? emailRes.value : null;
    const nameservers = nsAnalysisRes.status === 'fulfilled' ? nsAnalysisRes.value : null;
    const dnssec = dnssecRes.status === 'fulfilled' ? dnssecRes.value : null;

    const hasSpf = txtRecords.some((r) => /^v=spf1/i.test(r.value));
    let hasDmarc = false;
    try {
      const dmarc = await smartResolve(`_dmarc.${input.ascii}`, 'TXT');
      hasDmarc = dmarc.records.some((r) => /^v\s*=\s*DMARC1/i.test(r.value));
    } catch { /* none */ }

    const score = computeScore({
      dnsQuick: {
        a: aRecords.length > 0,
        aaaa: aaaaRecords.length > 0,
        nsCount: nsRecords.length,
        caa: caaRecords.length > 0,
        mxCount: mxRecords.length,
      },
      nameservers,
      ssl,
      email,
      http,
      whois,
      dnssec,
    });

    const nsNames = nsRecords.map((r) => r.value.replace(/\.$/, ''));
    const firstHosting = ip?.ipv4[0] || ip?.ipv6[0] || null;
    const hosting = firstHosting
      ? {
          org: (firstHosting[HOSTING_PROVIDER_KEYS[0]] as string | null) || null,
          country: firstHosting.country,
          asn: firstHosting.asn,
        }
      : null;

    const websiteUp = http ? (http.statusCode !== null && http.statusCode < 500) : null;
    const daysToExpiry = whois?.daysToExpiry ?? null;
    const sslStatus = ssl?.httpsAvailable ? ssl.status : ssl ? 'not_installed' : null;

    let overall: StatusLevel = 'healthy';
    if (nx) overall = 'critical';
    else if (score.total >= 75) overall = 'healthy';
    else if (score.total >= 50) overall = 'warning';
    else overall = 'critical';
    if (score.categories.every((c) => c.max === 0)) overall = 'unknown';

    const moduleStatus: OverviewResult['moduleStatus'] = [
      { module: 'DNS', status: aRecords.length ? 'healthy' : 'warning', summary: `${aRecords.length} A, ${aaaaRecords.length} AAAA, ${nsRecords.length} NS records` },
      { module: 'Nameservers', status: nameservers ? (nameservers.issues.some((i) => i.severity === 'critical') ? 'critical' : nameservers.issues.length ? 'warning' : 'healthy') : 'unknown', summary: nameservers ? `${nameservers.authoritative.length} servers probed` : 'unavailable' },
      { module: 'SSL/TLS', status: ssl ? (ssl.status === 'valid' ? 'healthy' : ssl.status === 'expiring_soon' ? 'warning' : ssl.status === 'not_installed' || ssl.status === 'unverifiable' ? 'unknown' : 'critical') : 'unknown', summary: ssl ? `${ssl.status}${ssl.daysRemaining !== null ? `, ${ssl.daysRemaining}d left` : ''}` : 'unavailable' },
      { module: 'WHOIS', status: whois ? 'healthy' : 'unknown', summary: whois?.registrar || 'unavailable' },
      { module: 'IP & Hosting', status: ip ? 'healthy' : 'unknown', summary: ip ? `${ip.ipv4.length + ip.ipv6.length} address(es)${ip.cdn ? `, ${ip.cdn.name}` : ''}` : 'unavailable' },
      { module: 'Email', status: email ? (email.grade === 'N/A' ? 'not_configured' : email.score >= 70 ? 'healthy' : email.score >= 40 ? 'warning' : 'critical') : 'unknown', summary: email ? `score ${email.score}/100` : 'unavailable' },
      { module: 'HTTP', status: http ? (http.statusCode && http.statusCode < 400 ? 'healthy' : 'warning') : 'unknown', summary: http?.statusCode ? `HTTP ${http.statusCode}${http.h2Supported ? ', H2' : ''}` : 'unavailable' },
      { module: 'DNSSEC', status: dnssec ? (dnssec.enabled === false ? 'not_configured' : dnssec.validatedByResolver === true ? 'healthy' : dnssec.validatedByResolver === false ? 'critical' : 'warning') : 'unknown', summary: dnssec ? (dnssec.enabled ? `enabled, alg ${dnssec.rrsig.algorithm ?? '?'}` : 'not enabled') : 'unavailable' },
    ];

    // persist scan history (non-blocking best-effort)
    try {
      await db.scanHistory.create({
        data: {
          domain: input.display,
          score: score.total,
          grade: score.grade,
          summaryJson: JSON.stringify(moduleStatus),
          findingsJson: JSON.stringify(score.findings.slice(0, 12)),
        },
      });
    } catch { /* history is best-effort */ }

    return {
      domain: input.display,
      ascii: input.ascii,
      checkedAt: new Date().toISOString(),
      score,
      cards: {
        status: overall,
        registrar: whois?.registrar ?? null,
        createdDate: whois?.creationDate ?? null,
        expirationDate: whois?.expirationDate ?? null,
        daysToExpiry,
        nameServers: nsNames.length ? nsNames : whois?.nameServers || [],
        dnsProvider: guessDnsProvider(nsNames.length ? nsNames : whois?.nameServers || []),
        ip4: aRecords.map((r) => r.value),
        ip6: aaaaRecords.map((r) => r.value),
        hosting,
        httpStatus: http?.statusCode ?? null,
        websiteUp,
        sslStatus,
        sslDaysRemaining: ssl?.httpsAvailable ? ssl.daysRemaining : null,
        sslIssuer: ssl?.cert?.issuerCn ?? null,
        mxCount: mxRecords.length,
        mailProvider: guessMailProvider(mxRecords.map((r) => r.value)),
        spf: hasSpf,
        dmarc: hasDmarc,
        dnssec: dnssec?.enabled ?? null,
        caa: caaRecords.length > 0,
        httpRedirectsToHttps: http?.httpsRedirect ?? null,
      },
      moduleStatus,
      timestamp: new Date().toISOString(),
    };
  });
}
