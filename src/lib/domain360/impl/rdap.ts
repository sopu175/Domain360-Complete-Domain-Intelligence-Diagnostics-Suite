import net from 'node:net';
import { TIMEOUTS, USER_AGENT } from '../config';
import { cached, TTL } from '../cache';
import type { WhoisResult } from '../types';

const WHOIS_SERVERS: Record<string, string> = {
  com: 'whois.verisign-grs.com', net: 'whois.verisign-grs.com',
  org: 'whois.publicinterestregistry.net', io: 'whois.nic.io',
  dev: 'whois.nic.google', app: 'whois.nic.google', page: 'whois.nic.google',
  ai: 'whois.nic.ai', xyz: 'whois.nic.xyz', uk: 'whois.nic.uk',
  de: 'whois.denic.de', fr: 'whois.nic.fr', au: 'whois.auda.org.au',
  ca: 'whois.cira.ca', ru: 'whois.tcinet.ru', su: 'whois.tcinet.ru',
  br: 'whois.registro.br', in: 'whois.registry.in', nl: 'whois.domain-registry.nl',
  eu: 'whois.eu', info: 'whois.identitydigital.services', us: 'whois.nic.us',
  me: 'whois.nic.me', tv: 'whois.nic.tv', co: 'whois.nic.co',
  biz: 'whois.nic.biz', online: 'whois.nic.online', site: 'whois.nic.site',
  store: 'whois.nic.store', tech: 'whois.nic.tech', cloud: 'whois.nic.cloud',
  shop: 'whois.nic.shop', jp: 'whois.jprs.jp', cn: 'whois.cnnic.cn',
  kr: 'whois.kr', ch: 'whois.nic.ch', li: 'whois.nic.ch', se: 'whois.iis.se',
  nu: 'whois.iis.se', no: 'whois.norid.no', nz: 'whois.nic.net.nz',
  mx: 'whois.mx', es: 'whois.nic.es', it: 'whois.nic.it', pl: 'whois.dns.pl',
  pt: 'whois.dns.pt', ie: 'whois.weare.ie', be: 'whois.dns.be',
  at: 'whois.nic.at', dk: 'whois.dk-hostmaster.dk', fi: 'whois.fi',
  cz: 'whois.nic.cz', sk: 'whois.sk-nic.sk', tr: 'whois.trabis.gov.tr',
  za: 'whois.zarc.net', il: 'whois.isoc.org.il', ae: 'whois.aeda.net.ae',
  sg: 'whois.sgnic.sg', my: 'whois.mynic.my', id: 'whois.idweb.id',
  th: 'whois.thnic.co', vn: 'whois.vnnic.vn', ph: 'whois.phDomains.com',
  uy: 'whois.nic.uy', pe: 'kwhois.rcp.net.pe', cl: 'whois.nic.cl',
  ar: 'whois.nic.ar', ua: 'whois.ua', ee: 'whois.tld.ee', lv: 'whois.nic.lv',
  lt: 'whois.domreg.lt', ro: 'whois.rotld.ro', bg: 'whois.register.bg',
  hr: 'whois.dns.hr', rs: 'whois.rnids.rs', si: 'whois.arnes.si',
};

export async function whoisQuery(server: string, query: string, timeoutMs = TIMEOUTS.whois): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: server, port: 43 });
    let data = '';
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      fn();
    };
    const timer = setTimeout(() => done(() => reject(new Error(`WHOIS query to ${server} timed out`))), timeoutMs);
    socket.setEncoding('utf8');
    socket.on('connect', () => socket.write(`${query}\r\n`));
    socket.on('data', (chunk) => {
      data += chunk;
      if (data.length > 256_000) done(() => resolve(data));
    });
    socket.on('end', () => done(() => resolve(data)));
    socket.on('close', () => done(() => resolve(data)));
    socket.on('error', (e) => done(() => reject(new Error(`WHOIS error: ${e.message}`))));
  });
}

export function findWhoisServer(tld: string): string | null {
  return WHOIS_SERVERS[tld.toLowerCase()] || null;
}

const pick = (re: RegExp, text: string): string | null => {
  const m = re.exec(text);
  return m ? m[1].trim() : null;
};

function isoOrNull(raw: string | null): string | null {
  if (!raw) return null;
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

export function parseWhoisText(text: string): Partial<WhoisResult> {
  const statuses = [...text.matchAll(/^\s*Domain Status:\s*(.+)$/gim)].map((m) => m[1].trim());
  const nameServers = [...new Set([...text.matchAll(/^\s*Name Server:\s*(.+)$/gim)].map((m) => m[1].trim().toLowerCase()))];
  const dnssecRaw = pick(/^\s*DNSSEC:\s*(.+)$/gim, text);
  const org = pick(/^\s*Registrant Organization:\s*(.+)$/gim, text);
  const privacy =
    !!org && /redacted|privacy|protected|not disclosed|data protected|REDACTED/i.test(org);
  return {
    registrar: pick(/^\s*Registrar:\s*(.+)$/gim, text),
    registrarUrl: pick(/^\s*Registrar URL:\s*(.+)$/gim, text),
    registrarIanaId: pick(/^\s*Registrar IANA ID:\s*(.+)$/gim, text),
    abuseContact: pick(/^\s*Abuse contact email:\s*(.+)$/gim, text) || pick(/^\s*Registrant Abuse Contact Email:\s*(.+)$/gim, text),
    creationDate: isoOrNull(pick(/^\s*Creation Date:\s*(.+)$/gim, text)),
    expirationDate: isoOrNull(pick(/^\s*(?:Registry Expiry Date|Expiry Date|Expiration Date|Expire Date|Expiration Time):\s*(.+)$/gim, text)),
    updatedDate: isoOrNull(pick(/^\s*(?:Updated Date|Last Updated On|Modified Date):\s*(.+)$/gim, text)),
    statusCodes: statuses,
    nameServers,
    dnssec: dnssecRaw ? /yes|signed/i.test(dnssecRaw) : null,
    registrant: {
      organization: org,
      country: pick(/^\s*Registrant Country:\s*(.+)$/gim, text),
      state: pick(/^\s*Registrant State\/Province:\s*(.+)$/gim, text),
      privacyProtected: privacy || !org,
    },
    whoisServerQueried: pick(/^\s*Registrar WHOIS Server:\s*(.+)$/gim, text),
  };
}

interface RdapEvent { eventAction?: string; eventDate?: string }
interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, [string, Record<string, unknown>, string, unknown][]];
  entities?: RdapEntity[];
}
interface RdapNs { ldhName?: string; unicodeName?: string }

function vcardValue(entity: RdapEntity | undefined, key: string): string | null {
  const cards = entity?.vcardArray?.[1];
  if (!Array.isArray(cards)) return null;
  for (const entry of cards) {
    if (entry?.[0] === key) {
      const v = entry[3];
      if (typeof v === 'string') return v;
      if (key === 'adr' && Array.isArray(v)) return (v[6] as string) || (v[3] as string) || null;
    }
  }
  return null;
}

function findEntity(entities: RdapEntity[] | undefined, role: string): RdapEntity | undefined {
  return entities?.find((e) => e.roles?.includes(role));
}

export function parseRdap(json: {
  events?: RdapEvent[];
  entities?: RdapEntity[];
  status?: string[];
  nameservers?: RdapNs[];
  secureDNS?: { delegationSigned?: boolean };
  links?: { rel?: string; href?: string }[];
}): Partial<WhoisResult> {
  const ev = (action: string): string | null =>
    json.events?.find((e) => e.eventAction === action)?.eventDate || null;
  const registrar = findEntity(json.entities, 'registrar');
  const registrant = findEntity(json.entities, 'registrant');
  const abuse = findEntity(json.entities, 'abuse');
  const registrarName = vcardValue(registrar, 'fn');
  const regOrg = vcardValue(registrant, 'org') || vcardValue(registrant, 'fn');
  return {
    registrar: registrarName,
    registrarUrl: (json.links?.find((l) => l.rel === 'related')?.href) || null,
    registrarIanaId: (registrar?.vcardArray && vcardValue(registrar, 'org')) || null,
    abuseContact: vcardValue(abuse, 'email'),
    creationDate: ev('registration'),
    expirationDate: ev('expiration'),
    updatedDate: ev('last changed') || ev('last update of RDAP database'),
    statusCodes: json.status || [],
    nameServers: (json.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean),
    dnssec: json.secureDNS ? Boolean(json.secureDNS.delegationSigned) : null,
    registrant: {
      organization: regOrg,
      country: vcardValue(registrant, 'adr'),
      state: null,
      privacyProtected: !registrant || (!!regOrg && /redacted|privacy|protected|not disclosed/i.test(regOrg)),
    },
    registry: json.links?.[0]?.href ? new URL(json.links[0].href).hostname : null,
  };
}

function mergeWhois(base: Partial<WhoisResult>, extra: Partial<WhoisResult>): Partial<WhoisResult> {
  const merged: Partial<WhoisResult> = { ...base };
  for (const [k, v] of Object.entries(extra)) {
    if (v === null || v === undefined) continue;
    const cur = (merged as Record<string, unknown>)[k];
    if (cur === null || cur === undefined || cur === '' || (Array.isArray(cur) && cur.length === 0)) {
      (merged as Record<string, unknown>)[k] = v;
    } else if (k === 'statusCodes' && Array.isArray(v) && Array.isArray(cur) && cur.length === 0) {
      (merged as Record<string, unknown>)[k] = v;
    }
  }
  return merged;
}

export async function lookupRegistration(input: { ascii: string; display: string }): Promise<WhoisResult> {
  return cached(`whois:${input.ascii}`, TTL.whois, async (): Promise<WhoisResult> => {
    let source: WhoisResult['source'] = 'rdap';
    let parsed: Partial<WhoisResult> = {};
    let rawRdap: unknown = undefined;
    let whoisServerQueried: string | null = null;

    // ---- RDAP primary
    try {
      const res = await fetch(`https://rdap.org/domain/${input.ascii}`, {
        headers: { accept: 'application/rdap+json', 'user-agent': USER_AGENT },
        signal: AbortSignal.timeout(TIMEOUTS.rdap),
        redirect: 'follow',
        cache: 'no-store',
      });
      if (res.status === 404) {
        throw new Error('NOT_FOUND_RDAP');
      }
      if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
      const json = (await res.json()) as Parameters<typeof parseRdap>[0];
      parsed = parseRdap(json);
      if (JSON.stringify(json).length < 400_000) rawRdap = json;
    } catch {
      parsed = {};
    }

    // ---- WHOIS fallback / enrichment
    const tld = input.ascii.split('.').pop() || '';
    const directServer = findWhoisServer(tld);
    const attempts: string[] = [];
    if (directServer) attempts.push(directServer);
    if (parsed.whoisServerQueried) attempts.push(parsed.whoisServerQueried);

    let whoisText = '';
    for (const server of attempts.slice(0, 2)) {
      try {
        whoisText = await whoisQuery(server, input.ascii);
        whoisServerQueried = server;
        if (whoisText && /Domain Name|domain name/i.test(whoisText)) break;
      } catch {
        continue;
      }
    }
    if (whoisText) {
      const parsedText = parseWhoisText(whoisText);
      if (!parsed.registrar && !parsed.creationDate) source = 'whois';
      else source = 'rdap+whois';
      parsed = mergeWhois(parsed, parsedText);
    }

    if (!parsed.registrar && !parsed.creationDate && !parsed.expirationDate) {
      throw new Error(`No registration data found for ${input.display} (RDAP and WHOIS both unavailable).`);
    }

    const created = parsed.creationDate ? new Date(parsed.creationDate) : null;
    const expires = parsed.expirationDate ? new Date(parsed.expirationDate) : null;
    const ageDays = created ? Math.floor((Date.now() - created.getTime()) / 86400000) : null;
    const daysToExpiry = expires ? Math.floor((expires.getTime() - Date.now()) / 86400000) : null;

    const statusCodes = parsed.statusCodes || [];
    return {
      domain: input.display,
      source,
      registrar: parsed.registrar ?? null,
      registrarUrl: parsed.registrarUrl ?? null,
      registrarIanaId: parsed.registrarIanaId ?? null,
      abuseContact: parsed.abuseContact ?? null,
      registry: parsed.registry ?? null,
      creationDate: parsed.creationDate ?? null,
      expirationDate: parsed.expirationDate ?? null,
      updatedDate: parsed.updatedDate ?? null,
      ageDays,
      daysToExpiry,
      statusCodes,
      nameServers: parsed.nameServers || [],
      dnssec: parsed.dnssec ?? null,
      transferLocked: statusCodes.some((s) => /transferProhibited/i.test(s)),
      registrant: parsed.registrant || { organization: null, country: null, state: null, privacyProtected: true },
      whoisServerQueried,
      ...(rawRdap !== undefined ? { rawRdap } : {}),
      timestamp: new Date().toISOString(),
    };
  });
}
