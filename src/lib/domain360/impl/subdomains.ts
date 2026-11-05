import tls from 'node:tls';
import { randomBytes } from 'node:crypto';
import { cached, TTL } from '../cache';
import { entitlement, USER_AGENT } from '../config';
import { smartResolve } from '../resolver';
import type { SubdomainEntry, SubdomainResult } from '../types';

const WORDLIST = [
  'www', 'www2', 'www3', 'mail', 'webmail', 'smtp', 'pop', 'pop3', 'imap', 'mx',
  'mx1', 'mx2', 'email', 'api', 'apis', 'app', 'apps', 'dev', 'development',
  'test', 'testing', 'stage', 'staging', 'stg', 'beta', 'demo', 'uat', 'qa',
  'prod', 'production', 'sandbox', 'blog', 'shop', 'store', 'cdn', 'static',
  'assets', 'img', 'images', 'media', 'video', 'docs', 'doc', 'wiki', 'help',
  'support', 'status', 'portal', 'admin', 'dashboard', 'intranet', 'vpn',
  'remote', 'gateway', 'auth', 'sso', 'login', 'id', 'identity', 'git',
  'gitlab', 'jenkins', 'ci', 'cd', 'build', 'deploy', 'docker', 'k8s',
  'kubernetes', 'vault', 'consul', 'db', 'sql', 'mysql', 'postgres', 'redis',
  'mongo', 'cache', 'elastic', 'kibana', 'grafana', 'prometheus', 'monitor',
  'monitoring', 'logs', 'syslog', 'files', 'ftp', 'sftp', 'ssh', 'backup',
  'backups', 'old', 'new', 'secure', 'ssl', 'proxy', 'lb', 'ns1', 'ns2', 'ns3',
  'dns', 'cloud', 's3', 'storage', 'bucket', 'partner', 'partners', 'crm',
  'erp', 'hr', 'billing', 'pay', 'payment', 'checkout', 'cart', 'account',
  'accounts', 'my', 'client', 'clients', 'ir', 'press', 'careers', 'jobs',
  'go', 'link', 'redirect', 'm', 'mobile', 'wap', 'node', 'node1', 'node2',
  'server', 'server1', 'server2', 'host', 'vps', 'internal', 'corp', 'office',
  'relay', 'autodiscover', 'autoconfig', 'cpanel', 'whm', 'plesk', 'exchange',
  'sip', 'jira', 'confluence', 'bitbucket', 'sonarqube', 'nexus', 'artifactory',
  'registry', 'npm', 'analytics', 'ads', 'track', 'tracking', 'chat', 'xmpp',
  'voip', 'pbx', 'waf', 'firewall', 'router', 'gw', 'edge', 'cdn2', 'img2',
  'static2', 'alpha', 'rc', 'release', 'hotfix', 'experiment', 'lp', 'promo',
  'marketing', 'sales', 'onboarding', 'signup', 'register', 'signin', 'oauth',
  'token', 'config', 'setup', 'install', 'update', 'upgrade', 'restore',
  'archive', 'temp', 'tmp', 'queue', 'worker', 'workers', 'cron', 'job',
  'scheduler', 'data', 'db1', 'db2', 'mail2', 'mxbackup', 'smtp2', 'public',
  'private', 'secure2', 'ssl2', 'api2', 'beta2', 'dev1', 'dev2', 'test1', 'test2',
];

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let idx = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = idx++;
      if (i >= items.length) break;
      try {
        results[i] = await fn(items[i]);
      } catch {
        results[i] = undefined as unknown as R;
      }
    }
  });
  await Promise.all(workers);
  return results;
}

async function resolveA(host: string): Promise<string[]> {
  try {
    const r = await smartResolve(host, 'A');
    if (r.rcode !== 'NOERROR') return [];
    return r.records.filter((x) => x.type === 'A').map((x) => x.value);
  } catch {
    return [];
  }
}

async function httpStatus(host: string): Promise<number | null> {
  try {
    const res = await fetch(`https://${host}/`, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(4000),
      headers: { 'user-agent': USER_AGENT },
    });
    return res.status;
  } catch {
    return null;
  }
}

async function sslOk(host: string): Promise<boolean | null> {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: true, timeout: 4000 });
    let settled = false;
    const done = (v: boolean | null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(v);
    };
    socket.setTimeout(4000, () => done(null));
    socket.once('secureConnect', () => done(socket.authorized));
    socket.once('error', () => done(false));
  });
}

export async function discoverSubdomains(input: {
  ascii: string;
  source: 'all' | 'ct' | 'dns';
  maxResults?: number;
}): Promise<SubdomainResult> {
  const cacheKey = `sub:${input.ascii}:${input.source}`;
  return cached(cacheKey, TTL.crtsh, async (): Promise<SubdomainResult> => {
    const maxResults = input.maxResults ?? entitlement('subdomainMaxResults');
    const sourcesUsed: string[] = [];
    const entries = new Map<string, SubdomainEntry>();
    let ctAvailable = false;
    let ctError: string | null = null;

    // wildcard detection
    const rnd = randomBytes(8).toString('hex');
    const wildcardIps = await resolveA(`${rnd}.${input.ascii}`);
    const wildcard = wildcardIps.length > 0;

    // ---- Certificate Transparency
    if (input.source === 'all' || input.source === 'ct') {
      try {
        const url = `https://crt.sh/?q=${encodeURIComponent('%.')}${input.ascii}&output=json`;
        let res: Response | null = null;
        for (let attempt = 0; attempt < 2; attempt++) {
          try {
            res = await fetch(url, { signal: AbortSignal.timeout(25000), headers: { 'user-agent': USER_AGENT }, cache: 'no-store' });
            if (res.ok) break;
          } catch { /* retry */ }
          await new Promise((r) => setTimeout(r, 2000));
        }
        if (res && res.ok) {
          const json = (await res.json()) as { name_value?: string; common_name?: string; not_before?: string }[];
          ctAvailable = true;
          sourcesUsed.push('ct');
          let count = 0;
          for (const cert of json) {
            if (count++ > 800) break;
            const names = `${cert.name_value || ''}\n${cert.common_name || ''}`.split('\n');
            for (let raw of names) {
              raw = raw.trim().toLowerCase().replace(/^\*\./, '');
              if (!raw.endsWith(`.${input.ascii}`)) continue;
              if (raw === rnd || raw === `${rnd}.${input.ascii}`) continue;
              const existing = entries.get(raw);
              const lastSeen = cert.not_before || null;
              if (existing) {
                if (!existing.source.includes('ct')) existing.source.push('ct');
                if (lastSeen && (!existing.lastSeen || lastSeen > existing.lastSeen)) existing.lastSeen = lastSeen;
              } else {
                entries.set(raw, {
                  subdomain: raw,
                  ips: [],
                  source: ['ct'],
                  verified: 'historical',
                  httpStatus: null,
                  sslValid: null,
                  lastSeen,
                  wildcard,
                });
              }
            }
          }
        } else {
          ctError = `crt.sh returned ${res ? res.status : 'no response'} (service is often overloaded)`;
        }
      } catch (e) {
        ctError = `Certificate Transparency unavailable: ${(e as Error).message}`;
      }
    }

    // ---- DNS wordlist
    if (input.source === 'all' || input.source === 'dns') {
      sourcesUsed.push('dns-brute');
      const hosts = WORDLIST.map((w) => `${w}.${input.ascii}`);
      const resolved = await mapLimit(hosts, 12, (h) => resolveA(h));
      hosts.forEach((h, i) => {
        const ips = (resolved[i] || []).filter(Boolean);
        if (!ips.length) return;
        if (wildcard && ips.sort().join(',') === [...wildcardIps].sort().join(',')) return;
        const existing = entries.get(h);
        if (existing) {
          existing.ips = ips;
          existing.verified = 'live';
          if (!existing.source.includes('dns-brute')) existing.source.push('dns-brute');
        } else {
          entries.set(h, {
            subdomain: h,
            ips,
            source: ['dns-brute'],
            verified: 'live',
            httpStatus: null,
            sslValid: null,
            lastSeen: null,
            wildcard,
          });
        }
      });
    }

    // ---- enrich first live entries
    const all = [...entries.values()];
    const live = all.filter((e) => e.verified === 'live');
    const toEnrich = live.slice(0, 25);
    await mapLimit(toEnrich, 5, async (e) => {
      e.httpStatus = await httpStatus(e.subdomain);
      e.sslValid = e.httpStatus !== null ? await sslOk(e.subdomain) : null;
    });

    const sorted = all
      .sort((a, b) => {
        if (a.verified !== b.verified) return a.verified === 'live' ? -1 : 1;
        return a.subdomain.localeCompare(b.subdomain);
      })
      .slice(0, maxResults);

    return {
      domain: input.ascii,
      sourcesUsed,
      ctAvailable,
      ctError,
      entries: sorted,
      counts: {
        total: sorted.length,
        live: sorted.filter((e) => e.verified === 'live').length,
        historical: sorted.filter((e) => e.verified === 'historical').length,
      },
      truncated: all.length > maxResults,
      note:
        'Passive discovery only: hosts are collected from Certificate Transparency logs (historical certificates) and by resolving a built-in list of common names via DNS. ' +
        (wildcard ? 'A DNS wildcard was detected — entries matching the wildcard IP were filtered.' : '') +
        ' Results are NOT exhaustive.',
      timestamp: new Date().toISOString(),
    };
  });
}
