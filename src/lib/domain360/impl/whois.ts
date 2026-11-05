import net from 'node:net';
import type { WhoisResult } from '../types';

/**
 * Raw WHOIS client (TCP port 43) + plain-text response parser.
 * Used as fallback/enrichment when RDAP is unavailable or incomplete.
 */

/** Query a WHOIS server over TCP port 43. Rejects on error/timeout. */
export function whoisQuery(server: string, query: string, timeoutMs = 8000): Promise<string> {
  return new Promise((resolve, reject) => {
    let text = '';
    let settled = false;
    const socket = net.createConnection({ host: server, port: 43 });

    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      fn();
    };

    const timer = setTimeout(
      () => finish(() => {
        if (text.length > 0) resolve(text);
        else reject(new Error(`WHOIS query to ${server} timed out after ${timeoutMs}ms`));
      }),
      timeoutMs,
    );

    socket.setEncoding('utf8');

    socket.on('connect', () => {
      socket.write(`${query}\r\n`);
    });

    socket.on('data', (chunk: string) => {
      text += chunk;
      // hard safety cap: some servers stream endlessly
      if (text.length > 512_000) finish(() => resolve(text));
    });

    socket.on('end', () => finish(() => {
      if (text.trim().length > 0) resolve(text);
      else reject(new Error(`WHOIS server ${server} closed the connection without data`));
    }));

    socket.on('close', () => finish(() => {
      if (text.trim().length > 0) resolve(text);
      else reject(new Error(`WHOIS server ${server} closed without a response`));
    }));

    socket.on('error', (err: Error) => finish(() => {
      if (text.trim().length > 0) resolve(text);
      else reject(new Error(`WHOIS connection to ${server} failed: ${err.message}`));
    }));
  });
}

/** Well-known registry WHOIS endpoints per TLD. */
const WHOIS_SERVERS: Record<string, string> = {
  com: 'whois.verisign-grs.com',
  net: 'whois.verisign-grs.com',
  org: 'whois.publicinterestregistry.net',
  io: 'whois.nic.io',
  dev: 'whois.nic.google',
  app: 'whois.nic.google',
  page: 'whois.nic.google',
  soy: 'whois.nic.google',
  how: 'whois.nic.google',
  esq: 'whois.nic.google',
  ing: 'whois.nic.google',
  ai: 'whois.nic.ai',
  xyz: 'whois.nic.xyz',
  uk: 'whois.nic.uk',
  de: 'whois.denic.de',
  fr: 'whois.nic.fr',
  au: 'whois.auda.org.au',
  ca: 'whois.cira.ca',
  br: 'whois.registro.br',
  in: 'whois.registry.in',
  nl: 'whois.domain-registry.nl',
  eu: 'whois.eu',
  info: 'whois.identitydigital.services',
  us: 'whois.nic.us',
  me: 'whois.nic.me',
  tv: 'whois.nic.tv',
  co: 'whois.nic.co',
  biz: 'whois.nic.biz',
  cloud: 'whois.nic.cloud',
  shop: 'whois.nic.shop',
  ru: 'whois.tcinet.ru',
  su: 'whois.tcinet.ru',
  jp: 'whois.jprs.jp',
  cn: 'whois.cnnic.cn',
  kr: 'whois.kr',
  ch: 'whois.nic.ch',
  li: 'whois.nic.ch',
  se: 'whois.iis.se',
  nu: 'whois.iis.se',
  no: 'whois.norid.no',
  nz: 'whois.nic.net.nz',
  za: 'whois.zarc.net',
  mx: 'whois.mx',
  es: 'whois.nic.es',
  it: 'whois.nic.it',
  pl: 'whois.dns.pl',
  pt: 'whois.dns.pt',
  be: 'whois.dns.be',
  at: 'whois.nic.at',
  dk: 'whois.dk-hostmaster.dk',
  fi: 'whois.fi',
  ie: 'whois.weare.ie',
  cz: 'whois.nic.cz',
  il: 'whois.isoc.org.il',
  nz2: 'whois.nic.net.nz',
  ae: 'whois.aeda.net.ae',
  sa: 'whois.nic.net.sa',
  tr: 'whois.trabis.gov.tr',
  id: 'whois.idnic.net.id',
  sg: 'whois.sgnic.sg',
  hk: 'whois.hkirc.hk',
  tw: 'whois.twnic.net.tw',
  vn: 'whois.vnnic.vn',
  th: 'whois.thnic.co',
  my: 'whois.mynic.my',
  ph: 'whois.dot.ph',
  sk: 'whois.sk-nic.sk',
  si: 'whois.register.si',
  gr: 'whois.gr',
  ro: 'whois.rotld.ro',
  ua: 'whois.ua',
  rs: 'whois.rnids.rs',
  bg: 'whois.register.bg',
  hu: 'whois.nic.hu',
  ee: 'whois.tld.ee',
  lv: 'whois.nic.lv',
  lt: 'whois.domreg.lt',
  is: 'whois.isnic.is',
};

/** TLDs that follow the whois.nic.<tld> convention (registry-run gTLDs). */
const NIC_CONVENTION_TLDS = new Set([
  'online', 'site', 'store', 'tech', 'website', 'space', 'fun', 'click', 'link',
  'icu', 'cyou', 'top', 'quest', 'beauty', 'hair', 'skin', 'makeup', 'fit',
  'life', 'live', 'world', 'today', 'zone', 'team', 'guru', 'expert', 'pro',
  'digital', 'network', 'systems', 'solutions', 'services', 'company', 'agency',
  'studio', 'design', 'media', 'news', 'blog', 'wiki', 'data', 'labs', 'works',
  'tools', 'tips', 'group', 'club', 'fun', 'games', 'gg', 'ooo', 'casa', 'baby',
]);

/** Look up the likely registry WHOIS server for a TLD. */
export function findWhoisServer(tld: string): string | null {
  const t = (tld || '').toLowerCase().replace(/^\./, '');
  if (!t) return null;
  const known = WHOIS_SERVERS[t];
  if (known) return known;
  if (NIC_CONVENTION_TLDS.has(t)) return `whois.nic.${t}`;
  return null;
}

// ---------------------------------------------------------------- parser

function firstMatch(text: string, keys: string[]): string | null {
  for (const key of keys) {
    const re = new RegExp(`^[ \\t]*${key}[ \\t]*:[ \\t]*(.+?)[ \\t]*$`, 'im');
    const m = re.exec(text);
    if (m && m[1]) return m[1];
  }
  return null;
}

function allMatches(text: string, key: string): string[] {
  const re = new RegExp(`^[ \\t]*${key}[ \\t]*:[ \\t]*(.+?)[ \\t]*$`, 'img');
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (m[1]) out.push(m[1]);
    if (out.length > 64) break; // safety cap
  }
  return out;
}

function isoOrNull(raw: string | null): string | null {
  if (!raw) return null;
  const cleaned = raw.replace(/\(.*?\)/g, '').trim();
  const d = new Date(cleaned);
  if (!Number.isNaN(d.getTime())) return d.toISOString();
  return null;
}

const PRIVACY_MARKERS = ['redacted', 'privacy', 'data protected', 'not disclosed', 'whoisguard', 'withheld', 'protected'];

function looksPrivate(value: string): boolean {
  const v = value.toLowerCase();
  return PRIVACY_MARKERS.some((p) => v.includes(p));
}

/**
 * Extract registration fields from a plain-text WHOIS response.
 * Handles the common thin-registry (Verisign-style) line format.
 */
export function parseWhoisText(text: string): Partial<WhoisResult> {
  if (!text) return {};
  const out: Partial<WhoisResult> = {};

  const registrar =
    firstMatch(text, ['Registrar']) ??
    firstMatch(text, ['Sponsoring Registrar', 'Registrar Name']);
  if (registrar) out.registrar = registrar;

  const registrarUrl = firstMatch(text, ['Registrar URL', 'URL']);
  if (registrarUrl && /^https?:\/\//i.test(registrarUrl)) out.registrarUrl = registrarUrl;

  const ianaId = firstMatch(text, ['Registrar IANA ID', 'IANA ID']);
  if (ianaId) out.registrarIanaId = ianaId;

  const abuse =
    firstMatch(text, ['Abuse contact email', 'Registrar Abuse Contact Email']) ??
    firstMatch(text, ['Abuse Contact Email']);
  if (abuse) out.abuseContact = abuse;

  const creation = firstMatch(text, ['Creation Date', 'Created On', 'Created Date', 'Registered on', 'Domain Registration Date', 'created']);
  out.creationDate = isoOrNull(creation);

  const expiry = firstMatch(text, [
    'Registry Expiry Date', 'Expiry Date', 'Expiration Date', 'Expiration Time',
    'paid-till', 'Expires on', 'Renewal Date', 'expires',
  ]);
  out.expirationDate = isoOrNull(expiry);

  const updated = firstMatch(text, ['Updated Date', 'Last Updated On', 'Last Update', 'changed', 'Modified Date', 'Last modified']);
  out.updatedDate = isoOrNull(updated);

  const statuses = allMatches(text, 'Domain Status')
    .map((s) => s.split(/\s+/)[0])
    .filter((s) => /^[a-zA-Z]/.test(s));
  if (statuses.length) out.statusCodes = [...new Set(statuses)];

  const ns = allMatches(text, 'Name Server')
    .map((s) => s.toLowerCase().split(/\s+/)[0].replace(/\.$/, ''))
    .filter((s) => s.includes('.'));
  if (ns.length) out.nameServers = [...new Set(ns)];

  const dnssec = firstMatch(text, ['DNSSEC']);
  if (dnssec) out.dnssec = /^signedDelegation|^yes$/i.test(dnssec.trim());

  const org = firstMatch(text, ['Registrant Organization', 'Registrant Organisation', 'Organization', 'Owner Organization']);
  const country = firstMatch(text, ['Registrant Country']);
  const state = firstMatch(text, ['Registrant State/Province', 'Registrant State']);

  const registrant: WhoisResult['registrant'] = {
    organization: org || null,
    country: country || null,
    state: state || null,
    privacyProtected: false,
  };
  if (org && looksPrivate(org)) registrant.privacyProtected = true;
  if (!org && looksPrivate(text.slice(0, 40_000)) && /Registrant/i.test(text)) {
    // some registries print REDACTED FOR PRIVACY without an Org line match
    registrant.privacyProtected = true;
  }
  out.registrant = registrant;

  return out;
}

/** True when a parsed WHOIS/RDAP result carries no meaningful data at all. */
export function isEmptyWhoisData(r: Partial<WhoisResult>): boolean {
  return (
    !r.registrar &&
    !r.creationDate &&
    !r.expirationDate &&
    !(r.nameServers && r.nameServers.length > 0) &&
    !(r.statusCodes && r.statusCodes.length > 0)
  );
}
