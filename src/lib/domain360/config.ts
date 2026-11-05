/**
 * Domain360 — central configuration: timeouts, resolvers, selectors, plans.
 * Plan entitlements are config-driven (never hardcode plan checks in code paths).
 */

export const TIMEOUTS = {
  wire: 4_000, // raw UDP DNS query
  wireRetry: 2_500,
  doh: 6_000,
  tls: 10_000,
  http: 12_000,
  smallFetch: 6_000,
  whois: 8_000,
  smtp: 3_500,
  crtsh: 25_000,
  ipinfo: 6_000,
  rdap: 10_000,
} as const;

export const USER_AGENT =
  'Mozilla/5.0 (compatible; Domain360/1.0; +domain-diagnostics)';

export const MAX_HTTP_BYTES = 768 * 1024; // response size cap for HTML scans

// ---------------------------------------------------------- Resolvers

export interface PublicResolver {
  name: string;
  org: string;
  ip: string;
  ip2?: string;
  ipv6?: string;
  privacy: 'logging' | 'no-log' | 'unknown';
}

/** Public UDP resolvers used for propagation / custom resolver lookups. */
export const PUBLIC_RESOLVERS: PublicResolver[] = [
  { name: 'Google Public DNS', org: 'Google', ip: '8.8.8.8', ip2: '8.8.4.4', privacy: 'logging' },
  { name: 'Cloudflare DNS', org: 'Cloudflare', ip: '1.1.1.1', ip2: '1.0.0.1', privacy: 'no-log' },
  { name: 'Quad9 (filtered)', org: 'Quad9 Foundation', ip: '9.9.9.9', ip2: '149.112.112.112', privacy: 'no-log' },
  { name: 'Quad9 (unfiltered)', org: 'Quad9 Foundation', ip: '9.9.9.10', privacy: 'no-log' },
  { name: 'OpenDNS', org: 'Cisco', ip: '208.67.222.222', ip2: '208.67.220.220', privacy: 'logging' },
  { name: 'AdGuard DNS', org: 'AdGuard', ip: '94.140.14.14', ip2: '94.140.15.15', privacy: 'no-log' },
  { name: 'CleanBrowsing (security)', org: 'CleanBrowsing', ip: '185.228.168.9', privacy: 'no-log' },
  { name: 'DNS.WATCH', org: 'DNS.WATCH', ip: '84.200.69.80', ip2: '84.200.70.40', privacy: 'unknown' },
  { name: 'Yandex DNS', org: 'Yandex', ip: '77.88.8.8', privacy: 'logging' },
  { name: 'Neustar UltraDNS', org: 'Neustar', ip: '64.6.64.6', privacy: 'unknown' },
  { name: 'Level3 DNS', org: 'Level3/Lumen', ip: '209.244.0.3', privacy: 'unknown' },
  { name: 'Comodo Secure DNS', org: 'Comodo', ip: '8.26.56.26', privacy: 'unknown' },
  { name: 'Norton ConnectSafe', org: 'NortonLifeLock', ip: '199.85.126.10', privacy: 'unknown' },
  { name: 'CIRA Canadian Shield', org: 'CIRA', ip: '149.112.121.10', privacy: 'no-log' },
];

export const DNS_PROVIDERS: Record<string, string> = {
  'cloudflare.com': 'Cloudflare',
  'google.com': 'Google Cloud',
  'amazonaws.com': 'AWS',
  'azure.com': 'Microsoft Azure',
  'microsoft.com': 'Microsoft',
  'digitalocean.com': 'DigitalOcean',
  'hetzner.com': 'Hetzner',
  'hetzner.de': 'Hetzner',
  'ovh.net': 'OVHcloud',
  'linode.com': 'Akamai (Linode)',
  'vultr.com': 'Vultr',
  'gcore.com': 'Gcore',
  'akamai.com': 'Akamai',
  'akamai.net': 'Akamai',
  'fastly.net': 'Fastly',
  'edgekey.net': 'Akamai',
  'edgesuite.net': 'Akamai',
  'cloudfront.net': 'AWS CloudFront',
  'vercel-dns.com': 'Vercel',
  'vercel.app': 'Vercel',
  'wpengine.com': 'WP Engine',
  'godaddy.com': 'GoDaddy',
  'namecheaphosting.com': 'Namecheap',
  'hostgator.com': 'HostGator',
  'bluehost.com': 'Bluehost',
  'siteground.net': 'SiteGround',
  'hostinger.com': 'Hostinger',
  'contabo.net': 'Contabo',
  'scaleway.com': 'Scaleway',
  'oraclecloud.net': 'Oracle Cloud',
  'stackpathdns.com': 'StackPath',
  'bunny.net': 'BunnyCDN',
  'cdn77.org': 'CDN77',
  'keycdn.com': 'KeyCDN',
};

export const CDN_SIGNATURES: { name: string; patterns: string[] }[] = [
  { name: 'Cloudflare', patterns: ['cloudflare'] },
  { name: 'Akamai', patterns: ['akamai', 'edgekey', 'edgesuite', 'akamaiedge'] },
  { name: 'Fastly', patterns: ['fastly'] },
  { name: 'AWS CloudFront', patterns: ['cloudfront'] },
  { name: 'Google Cloud CDN', patterns: ['google', 'gcache', 'googleusercontent'] },
  { name: 'Azure CDN / Front Door', patterns: ['azureedge', 'azurefd', 'microsoft'] },
  { name: 'BunnyCDN', patterns: ['bunny', 'b-cdn'] },
  { name: 'CDN77', patterns: ['cdn77'] },
  { name: 'KeyCDN', patterns: ['keycdn'] },
  { name: 'StackPath', patterns: ['stackpath'] },
  { name: 'Gcore', patterns: ['gcore'] },
  { name: 'Vercel Edge', patterns: ['vercel'] },
  { name: 'Imperva', patterns: ['imperva', 'sucuri'] },
];

export const MAIL_PROVIDERS: { name: string; patterns: string[] }[] = [
  { name: 'Google Workspace', patterns: ['google.com', 'googlemail.com'] },
  { name: 'Microsoft 365', patterns: ['outlook.com', 'protection.outlook', 'office365.com'] },
  { name: 'Zoho Mail', patterns: ['zoho'] },
  { name: 'Proton Mail', patterns: ['protonmail', 'proton.me'] },
  { name: 'Yahoo Mail', patterns: ['yahoodns'] },
  { name: 'Apple iCloud Mail', patterns: ['icloud', 'apple'] },
  { name: 'Mimecast', patterns: ['mimecast'] },
  { name: 'Proofpoint', patterns: ['pphosted', 'proofpoint'] },
  { name: 'Barracuda', patterns: ['barracuda', 'cudamail'] },
  { name: 'Mailgun', patterns: ['mailgun'] },
  { name: 'SendGrid', patterns: ['sendgrid'] },
  { name: 'Amazon SES / WorkMail', patterns: ['amazonaws', 'awsapps'] },
  { name: 'Yandex Mail', patterns: ['yandex'] },
  { name: 'Fastmail', patterns: ['messagingengine', 'fastmail'] },
  { name: 'MXroute', patterns: ['mxroute'] },
  { name: 'PrivateEmail', patterns: ['privateemail'] },
  { name: 'IceWarp', patterns: ['icewarp'] },
];

/** Common DKIM selectors tried during discovery (ordered by likelihood). */
export const COMMON_DKIM_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 's1', 's2', 'k1', 'dkim',
  'mail', 'smtp', 'mandrill', 'zoho', 'fm1', 'fm2', 'fm3', 'protonmail',
  'pm1', 'pm2', 'mta-sts', 'mailgun', 'sendgrid', 'everlytickey1',
  'everlytickey2', 'eversrv', 'dkim1024', 'dkim2048', 'bronto', 'ctct',
  'zendesk1', 'zendesk2', 'sim1', 'sim2', 'cisco', 'ciscoselect1',
];

// ------------------------------------------------------------- Plans

export type PlanId = 'free' | 'pro' | 'business';

export interface PlanLimits {
  label: string;
  active: boolean; // whether the plan can actually be granted (billing backend required)
  dnsPerMinute: number;
  perModulePerMinute: number;
  propagationPerMinute: number;
  overviewPerMinute: number;
  securityPerMinute: number;
  subdomainsPerMinute: number;
  propagationResolvers: number;
  subdomainMaxResults: number;
  subdomainCtLogs: boolean;
  dnssecAnalyzer: boolean;
  advancedTls: boolean;
  zoneTransferCheck: boolean;
  historyDays: number;
  savedDomains: number;
  pdfExport: boolean;
  apiAccess: boolean;
  bulkAnalysis: number;
}

export const PLANS: Record<PlanId, PlanLimits> = {
  free: {
    label: 'Free',
    active: true,
    dnsPerMinute: 60,
    perModulePerMinute: 20,
    propagationPerMinute: 8,
    overviewPerMinute: 8,
    securityPerMinute: 8,
    subdomainsPerMinute: 4,
    propagationResolvers: 14,
    subdomainMaxResults: 300,
    subdomainCtLogs: true,
    dnssecAnalyzer: true,
    advancedTls: true,
    zoneTransferCheck: true, // gated behind explicit user authorization in UI
    historyDays: 7,
    savedDomains: 10,
    pdfExport: true,
    apiAccess: false,
    bulkAnalysis: 0,
  },
  pro: {
    label: 'Pro',
    active: false, // requires subscription/billing backend — honestly disabled
    dnsPerMinute: 240,
    perModulePerMinute: 60,
    propagationPerMinute: 30,
    overviewPerMinute: 30,
    securityPerMinute: 30,
    subdomainsPerMinute: 20,
    propagationResolvers: 14,
    subdomainMaxResults: 1000,
    subdomainCtLogs: true,
    dnssecAnalyzer: true,
    advancedTls: true,
    zoneTransferCheck: true,
    historyDays: 365,
    savedDomains: 100,
    pdfExport: true,
    apiAccess: true,
    bulkAnalysis: 0,
  },
  business: {
    label: 'Business',
    active: false,
    dnsPerMinute: 600,
    perModulePerMinute: 120,
    propagationPerMinute: 60,
    overviewPerMinute: 60,
    securityPerMinute: 60,
    subdomainsPerMinute: 40,
    propagationResolvers: 14,
    subdomainMaxResults: 5000,
    subdomainCtLogs: true,
    dnssecAnalyzer: true,
    advancedTls: true,
    zoneTransferCheck: true,
    historyDays: 730,
    savedDomains: 1000,
    pdfExport: true,
    apiAccess: true,
    bulkAnalysis: 50,
  },
};

/** The plan currently granted to anonymous users. Controlled by env override. */
export function currentPlan(): PlanId {
  const p = (process.env.DOMAIN360_PLAN || 'free').toLowerCase() as PlanId;
  if ((p === 'pro' || p === 'business') && PLANS[p].active) return p;
  return 'free';
}

/** Resolve an entitlement for the active plan. */
export function entitlement<K extends keyof PlanLimits>(key: K): PlanLimits[K] {
  return PLANS[currentPlan()][key];
}
