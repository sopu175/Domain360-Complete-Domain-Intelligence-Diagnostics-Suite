/**
 * Domain360 — shared type contracts.
 * Every backend module and frontend tab codes against these types.
 */

export type StatusLevel =
  | 'healthy'
  | 'warning'
  | 'critical'
  | 'unknown'
  | 'not_configured'
  | 'info';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'pass';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  recommendation?: string;
  reference?: string;
}

// ---------------------------------------------------------------- DNS

export interface DnsRecord {
  type: string;
  name: string;
  value: string;
  ttl: number | null;
  priority?: number | null;
  class?: string;
}

export interface DnsLookupResult {
  domain: string;
  ascii: string;
  recordType: string;
  resolverLabel: string;
  resolverKind: 'system' | 'public' | 'custom' | 'doh';
  responseCode: string;
  responseTimeMs: number;
  records: DnsRecord[];
  authority: DnsRecord[];
  dnssecAd: boolean | null;
  source: 'wire' | 'doh';
  timestamp: string;
  note?: string;
}

// ------------------------------------------------------- Propagation

export interface PropagationNode {
  name: string;
  ip: string;
  kind: 'public_resolver';
  values: string[] | null;
  responseCode: string;
  responseTimeMs: number | null;
  matchesExpected: boolean | null;
  status: StatusLevel;
}

export interface PropagationResult {
  domain: string;
  recordType: string;
  expectedSource: string;
  expected: string[] | null;
  nodes: PropagationNode[];
  summary: { total: number; matched: number; divergent: number; failed: number };
  propagationScore: number;
  timestamp: string;
  note: string;
}

// ------------------------------------------------------- Nameservers

export interface NsServerInfo {
  nameserver: string;
  ips: string[];
  responded: boolean;
  responseTimeMs: number | null;
  soaSerial: number | null;
  nsRecords: string[] | null;
  isLame: boolean;
}

export interface NameserverResult {
  domain: string;
  delegation: {
    parentZone: string;
    parentNsUsed: string[];
    parentDelegationNs: string[];
    glueA: string[];
    gluePresent: boolean;
  };
  authoritative: NsServerInfo[];
  consistency: {
    setsMatch: boolean;
    serialsMatch: boolean;
    serials: { nameserver: string; serial: number | null }[];
  };
  issues: Finding[];
  timestamp: string;
}

// ---------------------------------------------------------------- SSL

export interface SslChainCert {
  subjectCn: string;
  subject: Record<string, string>;
  issuerCn: string;
  issuer: Record<string, string>;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint256: string;
  sans: string[];
  keyAlgorithm: string;
  keyBits: number | null;
  signatureAlgorithm: string;
  selfIssued: boolean;
}

export interface SslResult {
  host: string;
  ip: string | null;
  httpsAvailable: boolean;
  status:
    | 'valid'
    | 'expiring_soon'
    | 'expired'
    | 'invalid'
    | 'self_signed'
    | 'not_installed'
    | 'unverifiable';
  hostnameMatch: boolean | null;
  cert: SslChainCert | null;
  chain: SslChainCert[];
  chainComplete: boolean | null;
  daysRemaining: number | null;
  protocols: { version: string; supported: boolean }[];
  negotiatedProtocol: string | null;
  cipher: { name: string; version: string | null; bits: number | null } | null;
  ocspUrls: string[];
  crlUrls: string[];
  ctLogsSeen: number | null;
  errors: string[];
  timestamp: string;
}

// -------------------------------------------------------------- WHOIS

export interface WhoisResult {
  domain: string;
  source: 'rdap' | 'whois' | 'rdap+whois';
  registrar: string | null;
  registrarUrl: string | null;
  registrarIanaId: string | null;
  abuseContact: string | null;
  registry: string | null;
  creationDate: string | null;
  expirationDate: string | null;
  updatedDate: string | null;
  ageDays: number | null;
  daysToExpiry: number | null;
  statusCodes: string[];
  nameServers: string[];
  dnssec: boolean | null;
  transferLocked: boolean | null;
  registrant: {
    organization: string | null;
    country: string | null;
    state: string | null;
    privacyProtected: boolean;
  };
  whoisServerQueried: string | null;
  rawRdap?: unknown;
  timestamp: string;
}

// ----------------------------------------------------------------- IP

export interface IpDetail {
  ip: string;
  version: 4 | 6;
  ptr: string | null;
  asn: string | null;
  asnOrg: string | null;
  isp: string | null;
  org: string | null;
  providerDomain: string | null;
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  postal: string | null;
  timezone: string | null;
  ipType: 'datacenter' | 'hosting' | 'business' | 'residential' | 'education' | 'unknown';
  source: string;
}

export interface IpResult {
  query: string;
  isDomain: boolean;
  ipv4: IpDetail[];
  ipv6: IpDetail[];
  cdn: { name: string; confidence: 'high' | 'medium' | 'low' } | null;
  cloudProvider: string | null;
  ipTypeNote: string;
  timestamp: string;
}

// -------------------------------------------------------------- Email

export interface EmailMx {
  exchange: string;
  priority: number;
  ips: { ip: string; version: 4 | 6 }[];
  ptr: string | null;
  providerGuess: string | null;
  reachable: boolean | null;
  banner: string | null;
}

export interface EmailResult {
  domain: string;
  mx: EmailMx[];
  spf: {
    record: string | null;
    valid: boolean;
    policy: 'none' | 'neutral' | 'softfail' | 'fail' | 'pass';
    dnsLookups: number;
    mechanisms: string[];
    issues: string[];
  } | null;
  dmarc: {
    record: string | null;
    policy: string | null;
    subdomainPolicy: string | null;
    pct: number | null;
    rua: string | null;
    valid: boolean;
    issues: string[];
  } | null;
  dkim: {
    selector: string;
    record: string | null;
    valid: boolean;
    keyBits: number | null;
    algorithm: string | null;
  }[];
  bimi: { record: string | null; valid: boolean } | null;
  mtaSts: { dnsRecord: string | null; policy: string | null; policyUrl: string } | null;
  tlsRpt: { record: string | null; rua: string | null; valid: boolean } | null;
  score: number;
  grade: string;
  findings: Finding[];
  timestamp: string;
}

// ---------------------------------------------------------------- HTTP

export interface HttpRedirectHop {
  url: string;
  status: number;
  location: string | null;
  ms: number;
}

export interface HttpResult {
  target: string;
  finalUrl: string;
  schemeUsed: 'http' | 'https';
  statusCode: number | null;
  statusText: string;
  httpVersion: string | null;
  h2Supported: boolean | null;
  h3Supported: boolean | 'unknown';
  ttfbMs: number | null;
  totalMs: number | null;
  redirects: HttpRedirectHop[];
  redirectLoop: boolean;
  httpsRedirect: boolean | null;
  server: string | null;
  poweredBy: string | null;
  contentType: string | null;
  contentLengthBytes: number | null;
  compression: { enabled: boolean; encoding: string | null };
  headers: { name: string; value: string }[];
  robots: { url: string; status: number | null; sitemaps: string[]; exists: boolean | null };
  sitemap: { url: string; status: number | null; exists: boolean | null };
  favicon: { url: string; status: number | null; exists: boolean | null };
  canonical: string | null;
  title: string | null;
  mixedContent: { detected: boolean; samples: string[] };
  error: string | null;
  timestamp: string;
}

// ------------------------------------------------------------ Security

export interface SecurityResult {
  domain: string;
  score: number;
  grade: string;
  httpsEnforced: boolean | null;
  dnssecEnabled: boolean | null;
  caa: { records: string[]; allowsLetsEncrypt: boolean | null } | null;
  hsts: {
    present: boolean;
    maxAge: number | null;
    includeSubdomains: boolean;
    preload: boolean;
  } | null;
  csp: { present: boolean; reportOnly: boolean; value: string | null } | null;
  headersChecked: {
    name: string;
    present: boolean;
    value: string | null;
    severity: Severity;
    description: string;
    recommendation: string;
  }[];
  exposedFiles: { path: string; status: number | null; exposed: boolean }[];
  zoneTransfer: {
    tested: boolean;
    authorized: boolean;
    vulnerable: boolean | null;
    servers: string[];
  } | null;
  findings: Finding[];
  timestamp: string;
}

// ---------------------------------------------------------- Subdomains

export interface SubdomainEntry {
  subdomain: string;
  ips: string[];
  source: ('ct' | 'dns-brute' | 'user')[];
  verified: 'live' | 'historical';
  httpStatus: number | null;
  sslValid: boolean | null;
  lastSeen: string | null;
  wildcard: boolean;
}

export interface SubdomainResult {
  domain: string;
  sourcesUsed: string[];
  ctAvailable: boolean;
  ctError: string | null;
  entries: SubdomainEntry[];
  counts: { total: number; live: number; historical: number };
  truncated: boolean;
  note: string;
  timestamp: string;
}

// ------------------------------------------------------------- DNSSEC

export interface DnssecChainStep {
  step: string;
  status: 'pass' | 'fail' | 'unknown';
  detail: string;
}

export interface DnssecResult {
  domain: string;
  enabled: boolean | null;
  ds: DnsRecord[];
  dnskey: DnsRecord[];
  rrsig: {
    present: boolean;
    records: DnsRecord[];
    algorithm: number | null;
    algorithmName: string | null;
    expiration: string | null;
    expired: boolean | null;
  };
  validatedByResolver: boolean | null;
  chain: DnssecChainStep[];
  algorithmsInfo: string[];
  issues: Finding[];
  timestamp: string;
}

// --------------------------------------------------------------- Score

export interface ScoreCategory {
  key: string;
  label: string;
  max: number;
  score: number;
  status: StatusLevel;
  notes: string[];
}

export interface ScoreResult {
  total: number;
  grade: string;
  categories: ScoreCategory[];
  findings: Finding[];
  methodology: string;
  disclaimer: string;
}

// ------------------------------------------------------------ Overview

export interface OverviewResult {
  domain: string;
  ascii: string;
  checkedAt: string;
  score: ScoreResult;
  cards: {
    status: StatusLevel;
    registrar: string | null;
    createdDate: string | null;
    expirationDate: string | null;
    daysToExpiry: number | null;
    nameServers: string[];
    dnsProvider: string | null;
    ip4: string[];
    ip6: string[];
    hosting: { org: string | null; country: string | null; asn: string | null } | null;
    httpStatus: number | null;
    websiteUp: boolean | null;
    sslStatus: SslResult['status'] | null;
    sslDaysRemaining: number | null;
    sslIssuer: string | null;
    mxCount: number;
    mailProvider: string | null;
    spf: boolean;
    dmarc: boolean;
    dnssec: boolean | null;
    caa: boolean;
    httpRedirectsToHttps: boolean | null;
  };
  moduleStatus: { module: string; status: StatusLevel; summary: string }[];
  timestamp: string;
}

// ------------------------------------------------------------- History

export interface HistoryItem {
  id: string;
  domain: string;
  score: number | null;
  grade: string | null;
  createdAt: string;
  summary: string | null;
}

// -------------------------------------------------- API envelopes

export interface ApiResponse<T> {
  ok: true;
  data: T;
}

export interface ApiErrorResponse {
  ok: false;
  error: { code: string; message: string };
}

export type ApiResult<T> = ApiResponse<T> | ApiErrorResponse;
