import dns from 'node:dns';
import { cached, TTL } from '../cache';
import { CDN_SIGNATURES, DNS_PROVIDERS, TIMEOUTS } from '../config';
import { isIP } from '../validation';
import { assertPublicIp, SsrfError } from '../ssrf';
import { resolveHostIps } from '../resolver';
import { ApiError } from '../api';
import type { IpDetail, IpResult } from '../types';

interface IpwhoResponse {
  success?: boolean;
  ip?: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  postal?: string;
  timezone?: { id?: string } | string;
  connection?: { asn?: number; org?: string; isp?: string; domain?: string };
}

interface IpApiResponse {
  status?: string;
  country?: string;
  countryCode?: string;
  regionName?: string;
  city?: string;
  zip?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isp?: string;
  org?: string;
  as?: string;
  hosting?: boolean;
  reverse?: string;
}

const DATACENTER_KW = /hosting|datacenter|data center|dedicated|server|cloud|vps|colo|dc\b|networks|communications|internet|host|telecom/i;
const RESIDENTIAL_KW = /mobile|broadband|fiber|fibre|cable|residential|telefon|telecom|wifi|wireless|comms|cellular|ltda|jio|airtel|vodafone|t-mobile|verizon|at&t|orange|telefonica|movistar|claro/i;
const EDUCATION_KW = /university|univ\.|edu|college|academy|school|institute/i;

function classifyIpType(org: string | null, isp: string | null, hostingFlag?: boolean): IpDetail['ipType'] {
  const hay = `${org || ''} ${isp || ''}`;
  if (EDUCATION_KW.test(hay)) return 'education';
  if (hostingFlag === true || DATACENTER_KW.test(hay)) return 'datacenter';
  if (RESIDENTIAL_KW.test(hay)) return 'residential';
  return 'unknown';
}

function detectCdn(haystacks: { org?: string | null; ptr?: string | null }): IpResult['cdn'] {
  const org = (haystacks.org || '').toLowerCase();
  const ptr = (haystacks.ptr || '').toLowerCase();
  for (const sig of CDN_SIGNATURES) {
    for (const p of sig.patterns) {
      if (org.includes(p)) return { name: sig.name, confidence: 'high' };
    }
  }
  for (const sig of CDN_SIGNATURES) {
    for (const p of sig.patterns) {
      if (ptr.includes(p)) return { name: sig.name, confidence: 'medium' };
    }
  }
  return null;
}

function detectCloud(haystack: string): string | null {
  const hay = haystack.toLowerCase();
  for (const [domain, name] of Object.entries(DNS_PROVIDERS)) {
    if (hay.includes(domain.replace(/\.(com|net|org|de|app)$/, '')) && hay.length > 3) {
      // require the provider token, not just any substring of 3 letters
      const token = domain.split('.')[0];
      if (token.length >= 4 && hay.includes(token)) return name;
      if (token.length < 4 && hay.includes(domain)) return name;
    }
  }
  return null;
}

async function ptrFor(ip: string): Promise<string | null> {
  try {
    const names = await dns.promises.reverse(ip);
    return names[0] || null;
  } catch {
    return null;
  }
}

export async function enrichIp(ip: string): Promise<IpDetail> {
  return cached(`ipenrich:${ip}`, TTL.ipinfo, async (): Promise<IpDetail> => {
    const version = isIP(ip) === 6 ? 6 : 4;
    const ptr = await ptrFor(ip);

    let detail: IpDetail = {
      ip, version, ptr,
      asn: null, asnOrg: null, isp: null, org: null, providerDomain: null,
      country: null, countryCode: null, region: null, city: null,
      latitude: null, longitude: null, postal: null, timezone: null,
      ipType: 'unknown', source: 'unavailable',
    };

    try {
      const res = await fetch(`https://ipwho.is/${ip}`, {
        signal: AbortSignal.timeout(TIMEOUTS.ipinfo),
        cache: 'no-store',
      });
      const j = (await res.json()) as IpwhoResponse;
      if (j.success !== false) {
        const org = j.connection?.org || j.connection?.isp || null;
        detail = {
          ...detail,
          asn: j.connection?.asn ? `AS${j.connection.asn}` : null,
          asnOrg: j.connection?.org || null,
          isp: j.connection?.isp || null,
          org,
          providerDomain: j.connection?.domain || null,
          country: j.country || null,
          countryCode: j.country_code || null,
          region: j.region || null,
          city: j.city || null,
          latitude: j.latitude ?? null,
          longitude: j.longitude ?? null,
          postal: j.postal || null,
          timezone: typeof j.timezone === 'string' ? j.timezone : j.timezone?.id || null,
          ipType: classifyIpType(org, j.connection?.isp || null),
          source: 'ipwho.is',
        };
      }
    } catch {
      /* fall through to ip-api */
    }

    if (detail.source === 'unavailable') {
      try {
        const res = await fetch(
          `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,hosting,reverse`,
          { signal: AbortSignal.timeout(TIMEOUTS.ipinfo), cache: 'no-store' },
        );
        const j = (await res.json()) as IpApiResponse;
        if (j.status === 'success') {
          const org = j.org || j.isp || null;
          detail = {
            ...detail,
            asn: j.as ? j.as.split(' ')[0] : null,
            asnOrg: j.as || null,
            isp: j.isp || null,
            org,
            country: j.country || null,
            countryCode: j.countryCode || null,
            region: j.regionName || null,
            city: j.city || null,
            latitude: j.lat ?? null,
            longitude: j.lon ?? null,
            postal: j.zip || null,
            timezone: j.timezone || null,
            ipType: j.hosting ? 'hosting' : classifyIpType(org, j.isp || null),
            source: 'ip-api.com',
          };
        }
      } catch {
        /* leave unavailable */
      }
    }
    return detail;
  });
}

export async function lookupIpInfo(input: { query: string; isIp: 0 | 4 | 6 }): Promise<IpResult> {
  const cacheKey = `ip:${input.query}:${input.isIp}`;
  return cached(cacheKey, TTL.ipinfo, async (): Promise<IpResult> => {
    let ips: { ip: string; version: 4 | 6 }[] = [];
    if (input.isIp) {
      assertPublicIp(input.query);
      ips = [{ ip: input.query, version: input.isIp === 6 ? 6 : 4 }];
    } else {
      const resolved = await resolveHostIps(input.query);
      ips = [
        ...resolved.v4.slice(0, 4).map((ip) => ({ ip, version: 4 as const })),
        ...resolved.v6.slice(0, 2).map((ip) => ({ ip, version: 6 as const })),
      ];
      if (!ips.length) {
        throw new ApiError('NOT_FOUND', 'Domain does not resolve to any public IP address.', 404);
      }
    }

    const details = await Promise.all(ips.map((i) => enrichIp(i.ip)));
    const v4 = details.filter((d) => d.version === 4);
    const v6 = details.filter((d) => d.version === 6);

    const first = details[0];
    const cdn = detectCdn({ org: first.org || first.isp, ptr: first.ptr });
    const cloudHay = `${first.org || ''} ${first.isp || ''} ${first.ptr || ''} ${first.providerDomain || ''}`;
    const cloudProvider = detectCloud(cloudHay);

    return {
      query: input.query,
      isDomain: input.isIp === 0,
      ipv4: v4,
      ipv6: v6,
      cdn,
      cloudProvider,
      ipTypeNote:
        'Geolocation is approximate (derived from registry data). IP type classification is heuristic. Whether an IP is shared or dedicated cannot be reliably determined from outside.',
      timestamp: new Date().toISOString(),
    };
  });
}

export { SsrfError };
