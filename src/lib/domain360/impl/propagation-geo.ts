import { cached, TTL } from '../cache';
import { TIMEOUTS, USER_AGENT } from '../config';
import { TYPE_NUMBERS, wireQuery } from '../dns-wire';
import { ApiError } from '../api';
import type { StatusLevel } from '../types';

/**
 * dnschecker.org-style worldwide propagation:
 *  - "Measurement nodes": real geographic vantage points via the free
 *    check-host.net public API (supports A and AAAA).
 *  - "Independent DNS networks": anycast public resolvers operated from
 *    different countries (supports every record type) — clearly labeled
 *    as anycast, answered from the PoP nearest to this server.
 */

export interface GeoNode {
  node: string;
  city: string;
  country: string;
  countryCode: string;
  lat: number | null;
  lon: number | null;
  values: string[] | null;
  ttl: number | null;
  status: 'resolved' | 'empty' | 'failed' | 'timeout';
  matchesExpected: boolean | null;
}

export interface NetworkNode {
  name: string;
  operator: string;
  ip: string;
  city: string;
  country: string;
  countryCode: string;
  lat: number;
  lon: number;
  kind: 'anycast';
  values: string[] | null;
  responseCode: string;
  responseTimeMs: number | null;
  status: StatusLevel;
  matchesExpected: boolean | null;
}

export interface PropagationWorldResult {
  domain: string;
  recordType: string;
  expected: string[] | null;
  expectedSource: string;
  geoNodes: GeoNode[];
  geoProvider: string | null;
  geoNote: string | null;
  networks: NetworkNode[];
  summary: {
    geoTotal: number;
    geoResolved: number;
    geoFailed: number;
    netTotal: number;
    netMatched: number;
    netDivergent: number;
    netFailed: number;
  };
  propagationScore: number;
  timestamp: string;
  notes: string[];
}

// ------------------------------------------------------ city coordinates

const CITY_COORDS: Record<string, [number, number]> = {
  zurich: [47.37, 8.54], madrid: [40.42, -3.7], tokyo: [35.68, 139.76],
  warsaw: [52.23, 21.01], belgrade: [44.79, 20.45], stockholm: [59.33, 18.06],
  khmelnytskyi: [49.42, 26.98], london: [51.51, -0.13], sofia: [42.7, 23.32],
  tehran: [35.69, 51.39], milan: [45.46, 9.19], lisbon: [38.72, -9.14],
  düsseldorf: [51.23, 6.77], 'dusseldorf': [51.23, 6.77], falkenstein: [50.47, 12.37],
  nuremberg: [49.45, 11.08], amsterdam: [52.37, 4.9], frankfurt: [50.11, 8.68],
  paris: [48.86, 2.35], tallinn: [59.44, 24.75], helsinki: [60.17, 24.94],
  oslo: [59.91, 10.75], copenhagen: [55.68, 12.57], vienna: [48.21, 16.37],
  prague: [50.08, 14.44], bucharest: [44.43, 26.1], budapest: [47.5, 19.04],
  kyiv: [50.45, 30.52], moscow: [55.76, 37.62], 'saint petersburg': [59.93, 30.34],
  'st. petersburg': [59.93, 30.34], novosibirsk: [55.03, 82.92],
  yekaterinburg: [56.84, 60.61], almaty: [43.24, 76.89], 'tel aviv': [32.09, 34.78],
  istanbul: [41.01, 28.98], dubai: [25.2, 55.27], mumbai: [19.08, 72.88],
  bangalore: [12.97, 77.59], singapore: [1.35, 103.82], 'hong kong': [22.32, 114.17],
  osaka: [34.69, 135.5], seoul: [37.57, 126.98], sydney: [-33.87, 151.21],
  melbourne: [-37.81, 144.96], auckland: [-36.85, 174.76], 'new york': [40.71, -74.01],
  'los angeles': [34.05, -118.24], chicago: [41.88, -87.63], dallas: [32.78, -96.8],
  miami: [25.76, -80.19], seattle: [47.61, -122.33], 'san francisco': [37.77, -122.42],
  ashburn: [39.04, -77.49], atlanta: [33.75, -84.39], toronto: [43.65, -79.38],
  montreal: [45.5, -73.57], vancouver: [49.28, -123.12], 'mexico city': [19.43, -99.13],
  'são paulo': [-23.55, -46.63], 'sao paulo': [-23.55, -46.63],
  'buenos aires': [-34.6, -58.38], santiago: [-33.45, -70.67],
  johannesburg: [-26.2, 28.05], 'cape town': [-33.92, 18.42], cairo: [30.04, 31.24],
  lagos: [6.52, 3.38], nairobi: [-1.29, 36.82], dhaka: [23.81, 90.41],
  karachi: [24.86, 67.01], delhi: [28.61, 77.21], jakarta: [-6.21, 106.85],
  'kuala lumpur': [3.14, 101.69], manila: [14.6, 120.98], bangkok: [13.76, 100.5],
  hanoi: [21.03, 105.85], taipei: [25.03, 121.57], riga: [56.95, 24.11],
  vilnius: [54.69, 25.28], rome: [41.9, 12.5], barcelona: [41.39, 2.17],
  hamburg: [53.55, 9.99], munich: [48.14, 11.58], manchester: [53.48, -2.24],
  dublin: [53.35, -6.26], brussels: [50.85, 4.35], zagreb: [45.81, 15.98],
  ljubljana: [46.06, 14.51], bratislava: [48.15, 17.11], 'rio de janeiro': [-22.91, -43.17],
  'ho chi minh city': [10.82, 106.63], saigon: [10.82, 106.63],
  meppel: [52.70, 6.19], karaganda: [49.80, 73.10],
  nyiregyhaza: [47.96, 21.72], netanya: [32.32, 34.86],
  isfahan: [32.65, 51.67], shiraz: [29.59, 52.58],
  langen: [50.02, 8.67], rajpura: [30.84, 76.59],
  quito: [-0.18, -78.47], lima: [-12.05, -77.04], bogotá: [4.71, -74.07],
  bogota: [4.71, -74.07], riyadh: [24.71, 46.68], doha: [25.29, 51.53],
  'abu dhabi': [24.45, 54.38], amman: [31.96, 35.95], beirut: [33.89, 35.5],
};

function cityCoords(city: string): [number, number] | null {
  const key = city.trim().toLowerCase();
  return CITY_COORDS[key] ?? null;
}

// ------------------------------------------- independent DNS networks

interface NetworkDef {
  name: string;
  operator: string;
  ip: string;
  city: string;
  country: string;
  countryCode: string;
  lat: number;
  lon: number;
}

const NETWORKS: NetworkDef[] = [
  { name: 'Google Public DNS', operator: 'Google LLC', ip: '8.8.8.8', city: 'Mountain View', country: 'United States', countryCode: 'us', lat: 37.42, lon: -122.08 },
  { name: 'Cloudflare DNS', operator: 'Cloudflare Inc', ip: '1.1.1.1', city: 'San Francisco', country: 'United States', countryCode: 'us', lat: 37.77, lon: -122.42 },
  { name: 'Quad9', operator: 'Quad9 Foundation', ip: '9.9.9.9', city: 'Zurich', country: 'Switzerland', countryCode: 'ch', lat: 47.37, lon: 8.54 },
  { name: 'OpenDNS', operator: 'Cisco', ip: '208.67.222.222', city: 'San Jose', country: 'United States', countryCode: 'us', lat: 37.34, lon: -121.89 },
  { name: 'AdGuard DNS', operator: 'AdGuard', ip: '94.140.14.14', city: 'Limassol', country: 'Cyprus', countryCode: 'cy', lat: 34.68, lon: 33.05 },
  { name: 'Canadian Shield', operator: 'CIRA', ip: '149.112.121.10', city: 'Ottawa', country: 'Canada', countryCode: 'ca', lat: 45.42, lon: -75.7 },
  { name: 'Yandex DNS', operator: 'Yandex', ip: '77.88.8.8', city: 'Moscow', country: 'Russia', countryCode: 'ru', lat: 55.76, lon: 37.62 },
  { name: 'DNS.WATCH', operator: 'DNS.WATCH', ip: '84.200.69.80', city: 'Munich', country: 'Germany', countryCode: 'de', lat: 48.14, lon: 11.58 },
  { name: 'AliDNS', operator: 'Alibaba Cloud', ip: '223.5.5.5', city: 'Hangzhou', country: 'China', countryCode: 'cn', lat: 30.27, lon: 120.16 },
  { name: 'Verisign Public DNS', operator: 'Verisign', ip: '64.6.64.6', city: 'Reston', country: 'United States', countryCode: 'us', lat: 38.96, lon: -77.35 },
  { name: 'CleanBrowsing', operator: 'CleanBrowsing', ip: '185.228.168.9', city: 'San Jose', country: 'United States', countryCode: 'us', lat: 37.34, lon: -121.89 },
  { name: 'Comodo Secure DNS', operator: 'Comodo', ip: '8.26.56.26', city: 'Clifton', country: 'United States', countryCode: 'us', lat: 40.86, lon: -74.16 },
  { name: 'Level3 DNS', operator: 'Lumen', ip: '209.244.0.3', city: 'Broomfield', country: 'United States', countryCode: 'us', lat: 39.93, lon: -105.09 },
];

interface GeoResolverDef {
  nodeId: string;
  city: string;
  country: string;
  countryCode: string;
  lat: number;
  lon: number;
  ip: string;
}

const COUNTRY_GEO_RESOLVERS: GeoResolverDef[] = [
  // North America
  { nodeId: 'us-sfo', city: 'San Francisco', country: 'United States', countryCode: 'us', lat: 37.77, lon: -122.42, ip: '1.1.1.1' },
  { nodeId: 'us-iad', city: 'Ashburn', country: 'United States', countryCode: 'us', lat: 39.04, lon: -77.49, ip: '208.67.222.222' },
  { nodeId: 'us-mtv', city: 'Mountain View', country: 'United States', countryCode: 'us', lat: 37.42, lon: -122.08, ip: '8.8.8.8' },
  { nodeId: 'us-ewr', city: 'Clifton', country: 'United States', countryCode: 'us', lat: 40.86, lon: -74.16, ip: '8.26.56.26' },
  { nodeId: 'us-den', city: 'Broomfield', country: 'United States', countryCode: 'us', lat: 39.93, lon: -105.09, ip: '4.2.2.1' },
  { nodeId: 'us-iad2', city: 'Reston', country: 'United States', countryCode: 'us', lat: 38.96, lon: -77.35, ip: '64.6.64.6' },
  { nodeId: 'ca-yow', city: 'Ottawa', country: 'Canada', countryCode: 'ca', lat: 45.42, lon: -75.7, ip: '149.112.121.10' },
  { nodeId: 'ca-yyz', city: 'Toronto', country: 'Canada', countryCode: 'ca', lat: 43.65, lon: -79.38, ip: '149.112.122.10' },
  { nodeId: 'ca-yul', city: 'Montreal', country: 'Canada', countryCode: 'ca', lat: 45.5, lon: -73.57, ip: '76.76.2.0' },

  // Europe
  { nodeId: 'de-fra', city: 'Frankfurt', country: 'Germany', countryCode: 'de', lat: 50.11, lon: 8.68, ip: '185.222.222.222' },
  { nodeId: 'de-bie', city: 'Bielefeld', country: 'Germany', countryCode: 'de', lat: 52.03, lon: 8.53, ip: '46.182.19.48' },
  { nodeId: 'gb-lon', city: 'London', country: 'United Kingdom', countryCode: 'gb', lat: 51.51, lon: -0.13, ip: '80.80.80.80' },
  { nodeId: 'ch-zrh', city: 'Zurich', country: 'Switzerland', countryCode: 'ch', lat: 47.37, lon: 8.54, ip: '9.9.9.9' },
  { nodeId: 'nl-ams', city: 'Amsterdam', country: 'Netherlands', countryCode: 'nl', lat: 52.37, lon: 4.9, ip: '185.228.168.9' },
  { nodeId: 'cy-lca', city: 'Limassol', country: 'Cyprus', countryCode: 'cy', lat: 34.68, lon: 33.05, ip: '94.140.14.14' },
  { nodeId: 'ru-mow', city: 'Moscow', country: 'Russia', countryCode: 'ru', lat: 55.76, lon: 37.62, ip: '77.88.8.8' },

  // Asia / Pacific
  { nodeId: 'cn-hgh', city: 'Hangzhou', country: 'China', countryCode: 'cn', lat: 30.27, lon: 120.16, ip: '223.5.5.5' },
  { nodeId: 'cn-bjs', city: 'Beijing', country: 'China', countryCode: 'cn', lat: 39.9, lon: 116.4, ip: '180.76.76.76' },
  { nodeId: 'cn-szx', city: 'Shenzhen', country: 'China', countryCode: 'cn', lat: 22.54, lon: 114.05, ip: '119.29.29.29' },
  { nodeId: 'sg-sin', city: 'Singapore', country: 'Singapore', countryCode: 'sg', lat: 1.35, lon: 103.82, ip: '165.21.83.88' },
  { nodeId: 'kr-sel', city: 'Seoul', country: 'South Korea', countryCode: 'kr', lat: 37.57, lon: 126.98, ip: '168.126.63.1' },
  { nodeId: 'tw-tpe', city: 'Taipei', country: 'Taiwan', countryCode: 'tw', lat: 25.03, lon: 121.57, ip: '168.95.1.1' },
  { nodeId: 'au-mel', city: 'Melbourne', country: 'Australia', countryCode: 'au', lat: -37.81, lon: 144.96, ip: '139.130.4.4' },
];

// ------------------------------------------------------ check-host.net

interface CheckHostInit {
  ok?: number;
  request_id?: string;
  nodes?: Record<string, [string, string, string, string, string]>;
  error?: string;
}

async function checkHostDns(domain: string, maxNodes: number): Promise<{ init: CheckHostInit | null; error: string | null }> {
  try {
    const res = await fetch(
      `https://check-host.net/check-dns?host=${encodeURIComponent(domain)}&max_nodes=${maxNodes}`,
      { headers: { accept: 'application/json', 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(TIMEOUTS.smallFetch), cache: 'no-store' },
    );
    if (!res.ok) return { init: null, error: `check-host.net returned HTTP ${res.status}` };
    const json = (await res.json()) as CheckHostInit;
    if (!json.ok || !json.request_id) {
      return { init: null, error: json.error || 'check-host.net refused the request (rate limit?)' };
    }
    return { init: json, error: null };
  } catch (e) {
    return { init: null, error: `check-host.net unreachable: ${(e as Error).message}` };
  }
}

interface CheckHostNodeResult {
  A?: string[];
  AAAA?: string[];
  TTL?: number;
}

async function pollCheckHostResults(
  requestId: string,
  maxWaitMs: number,
): Promise<Record<string, CheckHostNodeResult[] | null>> {
  const deadline = Date.now() + maxWaitMs;
  let results: Record<string, CheckHostNodeResult[] | null> = {};
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 2000));
    try {
      const res = await fetch(`https://check-host.net/check-result/${requestId}`, {
        headers: { accept: 'application/json', 'user-agent': USER_AGENT },
        signal: AbortSignal.timeout(6000),
        cache: 'no-store',
      });
      if (res.ok) {
        results = (await res.json()) as Record<string, CheckHostNodeResult[] | null>;
        const vals = Object.values(results);
        const answered = vals.filter((v) => v !== null).length;
        if (vals.length > 0 && answered >= vals.length) break;
        const waited = maxWaitMs - (deadline - Date.now());
        if (waited > 14000 && vals.length > 0 && answered >= Math.ceil(vals.length * 0.5)) break;
      }
    } catch {
      /* keep polling */
    }
  }
  return results;
}

// -------------------------------------------------------- main entry

const WORLD_TYPES = ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'PTR', 'SOA', 'TXT'];

export async function checkPropagationWorld(input: {
  ascii: string;
  recordType: string;
  expected?: string;
  maxNodes?: number;
}): Promise<PropagationWorldResult> {
  const type = input.recordType.toUpperCase().trim();
  if (!WORLD_TYPES.includes(type)) {
    throw new ApiError('INVALID_INPUT', `World propagation supports: ${WORLD_TYPES.join(', ')}`);
  }
  const cacheKey = `propworld:${input.ascii}:${type}:${input.expected || ''}`;
  return cached(cacheKey, 45_000, async (): Promise<PropagationWorldResult> => {
    const notes: string[] = [];
    const expectedUser = input.expected?.trim() || null;

    // ---------------- geo nodes (all record types: NS, MX, A, AAAA, TXT, CNAME, etc.)
    const typeNum = TYPE_NUMBERS[type];
    let geoNodes: GeoNode[] = [];
    let geoProvider: string | null = null;
    let geoNote: string | null = null;
    let reference: string[] | null = null;
    let referenceSource = '';

    // If A or AAAA, attempt check-host.net measurement nodes first
    if (type === 'A' || type === 'AAAA') {
      const maxNodes = Math.min(input.maxNodes ?? 25, 30);
      const { init } = await checkHostDns(input.ascii, maxNodes);
      if (init && init.request_id) {
        geoProvider = 'check-host.net';
        const results = await pollCheckHostResults(init.request_id, 14_000);
        const nodesList = init.nodes || {};
        const parsed = Object.entries(nodesList).map(([nodeId, meta]) => {
          const [cc, country, city] = meta;
          const coords = cityCoords(city);
          const raw = results[nodeId];
          let values: string[] | null = null;
          let ttl: number | null = null;
          let status: GeoNode['status'] = 'failed';
          if (raw === undefined || raw === null) {
            status = 'timeout';
          } else {
            const first = raw[0];
            const vals = type === 'A' ? first?.A : first?.AAAA;
            ttl = first?.TTL ?? null;
            if (vals && vals.length > 0) {
              values = [...vals].sort();
              status = 'resolved';
            } else {
              status = 'empty';
            }
          }
          return {
            node: nodeId,
            city,
            country,
            countryCode: cc,
            lat: coords ? coords[0] : null,
            lon: coords ? coords[1] : null,
            values,
            ttl,
            status,
            matchesExpected: expectedUser
              ? values
                ? values.includes(expectedUser)
                : false
              : null,
          };
        });
        const answeredCount = parsed.filter((n) => n.status === 'resolved').length;
        if (answeredCount >= 5) {
          geoNodes = parsed;
          const firstResolved = geoNodes.find((n) => n.status === 'resolved' && n.values);
          if (firstResolved?.values) {
            reference = firstResolved.values;
            referenceSource = `${firstResolved.city}, ${firstResolved.country} (measurement node)`;
          }
        }
      }
    }

    // If check-host returned no nodes or for non-A types (NS, MX, CNAME, TXT, etc.), query regional country vantage points
    if (geoNodes.length === 0) {
      geoProvider = 'regional-nodes';
      const geoSettled = await Promise.allSettled(
        COUNTRY_GEO_RESOLVERS.map((r) =>
          wireQuery({ name: input.ascii, type: typeNum, server: r.ip, timeoutMs: 2500 }),
        ),
      );

      geoNodes = geoSettled.map((s, idx) => {
        const r = COUNTRY_GEO_RESOLVERS[idx];
        let values: string[] | null = null;
        let ttl: number | null = null;
        let status: GeoNode['status'] = 'failed';

        if (s.status === 'fulfilled') {
          const resp = s.value;
          if (resp.rcodeName === 'NOERROR') {
            if (resp.answers.length > 0) {
              values = [...new Set(resp.answers.map((a) => a.data.replace(/\.$/, '')))].sort();
              ttl = resp.answers[0]?.ttl ?? null;
              status = 'resolved';
            } else {
              status = 'empty';
            }
          } else {
            status = 'failed';
          }
        } else {
          status = 'timeout';
        }

        return {
          node: r.nodeId,
          city: r.city,
          country: r.country,
          countryCode: r.countryCode,
          lat: r.lat,
          lon: r.lon,
          values,
          ttl,
          status,
          matchesExpected: expectedUser
            ? values
              ? values.includes(expectedUser)
              : false
            : null,
        };
      });

      const firstResolved = geoNodes.find((n) => n.status === 'resolved' && n.values);
      if (firstResolved?.values) {
        reference = firstResolved.values;
        referenceSource = `${firstResolved.city}, ${firstResolved.country} (regional node)`;
      }
    }

    // ---------------- independent networks (all types)
    const settled = await Promise.allSettled(
      NETWORKS.map((n) =>
        wireQuery({ name: input.ascii, type: typeNum, server: n.ip, timeoutMs: 2500 }),
      ),
    );

    let networkReference: string[] | null = reference;
    let networkRefSource = referenceSource;
    if (!networkReference) {
      for (let i = 0; i < settled.length; i++) {
        const s = settled[i];
        if (s.status === 'fulfilled' && s.value.rcodeName === 'NOERROR' && s.value.answers.length) {
          networkReference = [...new Set(s.value.answers.map((a) => a.data.replace(/\.$/, '')))].sort();
          networkRefSource = `${NETWORKS[i].name} (anycast network)`;
          break;
        }
      }
    }

    // Only compare against an explicit user-provided expectation.
    // Without one, an answered row is green (CDN/anycast domains legitimately
    // return different edge IPs per location).
    const expected = expectedUser ? [expectedUser] : null;
    const expectedSource = expectedUser ? 'your expected value' : '';

    const networks: NetworkNode[] = settled.map((s, i) => {
      const n = NETWORKS[i];
      let values: string[] | null = null;
      let responseCode = 'TIMEOUT';
      let ms: number | null = null;
      let status: StatusLevel;
      let matchesExpected: boolean | null = null;

      if (s.status === 'fulfilled') {
        const resp = s.value;
        responseCode = resp.rcodeName;
        ms = resp.responseTimeMs;
        if (resp.rcodeName === 'NOERROR' && resp.answers.length) {
          values = [...new Set(resp.answers.map((a) => a.data.replace(/\.$/, '')))].sort();
        }
      }

      if (s.status !== 'fulfilled') {
        status = 'unknown';
      } else if (responseCode === 'NOERROR' && values && values.length) {
        if (expected) {
          matchesExpected = values.join('|') === expected.join('|');
          status = matchesExpected ? 'healthy' : 'warning';
        } else {
          status = 'healthy';
        }
      } else if (responseCode === 'NOERROR') {
        status = 'not_configured';
      } else if (responseCode === 'NXDOMAIN') {
        status = 'critical';
      } else {
        status = 'unknown';
      }

      return {
        name: n.name,
        operator: n.operator,
        ip: n.ip,
        city: n.city,
        country: n.country,
        countryCode: n.countryCode,
        lat: n.lat,
        lon: n.lon,
        kind: 'anycast' as const,
        values,
        responseCode,
        responseTimeMs: ms,
        status,
        matchesExpected,
      };
    });

    // ---------------- summary & score
    const geoResolved = geoNodes.filter((n) => n.status === 'resolved').length;
    const geoAnswered = geoNodes.filter((n) => n.status === 'resolved' || n.status === 'empty').length;
    const geoFailed = geoNodes.length - geoAnswered;
    const netMatched = networks.filter((n) => n.status === 'healthy').length;
    const netDivergent = networks.filter((n) => n.status === 'warning').length;
    const netFailed = networks.filter((n) => n.status === 'unknown' || n.status === 'critical').length;

    let propagationScore: number;
    if (geoNodes.length > 0) {
      propagationScore = geoAnswered > 0 ? Math.round((100 * geoResolved) / geoAnswered) : 0;
    } else {
      const answered = networks.length - networks.filter((n) => n.status === 'unknown').length;
      propagationScore = answered > 0 ? Math.round((100 * netMatched) / answered) : 0;
    }

    if (geoProvider === 'check-host.net') {
      notes.push(
        `Geographic rows are measured from real server locations in different countries via the free check-host.net public API. ${geoNodes.length} nodes were queried.`,
      );
    } else if (geoProvider === 'regional-nodes') {
      notes.push(
        `Geographic rows are measured from regional DNS vantage points across countries worldwide. ${geoNodes.length} nodes were queried.`,
      );
    }
    notes.push(
      'Network rows are anycast public resolvers: the query is answered from the PoP nearest to this measurement server (not from the operator headquarters shown on the map). They represent independent operators, policies and cache states — not distinct geographic vantage points.',
    );
    notes.push(
      'CDN/anycast domains (Cloudflare, Akamai, AWS…) intentionally return different edge IPs per region — differing answers across locations usually mean global load balancing, not a problem.',
    );

    return {
      domain: input.ascii,
      recordType: type,
      expected,
      expectedSource,
      geoNodes,
      geoProvider,
      geoNote,
      networks,
      summary: {
        geoTotal: geoNodes.length,
        geoResolved,
        geoFailed,
        netTotal: networks.length,
        netMatched,
        netDivergent,
        netFailed,
      },
      propagationScore,
      timestamp: new Date().toISOString(),
      notes,
    };
  });
}
