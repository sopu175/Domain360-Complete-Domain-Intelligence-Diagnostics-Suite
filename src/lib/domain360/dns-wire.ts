import dgram from 'node:dgram';
import { randomInt } from 'node:crypto';

/**
 * Minimal DNS wire-protocol client (RFC 1035 / RFC 6891 EDNS0).
 * Allows querying ANY resolver (Google, Cloudflare, Quad9, custom IP,
 * authoritative nameservers) for ANY record type, with response codes,
 * flags (AA/AD/TC) and authority section parsing.
 */

export const TYPE_NUMBERS: Record<string, number> = {
  A: 1, NS: 2, MD: 3, MF: 4, CNAME: 5, SOA: 6, MB: 7, MG: 8, MR: 9, NULL: 10,
  PTR: 12, HINFO: 13, MINFO: 14, MX: 15, TXT: 16, RP: 17, AFSDB: 18, SIG: 24,
  KEY: 25, AAAA: 28, LOC: 29, NXT: 30, EID: 31, NIMLOC: 32, SRV: 33, ATMA: 34,
  NAPTR: 35, KX: 36, CERT: 37, DNAME: 39, OPT: 41, APL: 42, DS: 43, SSHFP: 44,
  IPSECKEY: 45, RRSIG: 46, NSEC: 47, DNSKEY: 48, DHCID: 49, NSEC3: 50,
  NSEC3PARAM: 51, TLSA: 52, SMIMEA: 53, HIP: 55, CDS: 59, CDNSKEY: 60,
  OPENPGPKEY: 61, CSYNC: 62, ZONEMD: 63, SVCB: 64, HTTPS: 65, SPF: 99,
  UINFO: 100, UID: 101, GID: 102, UNSPEC: 103, NID: 104, L32: 105, L64: 106,
  LP: 107, EUI48: 108, EUI64: 109, TKEY: 249, TSIG: 250, URI: 256, CAA: 257,
  TA: 32768, DLV: 32769, ANY: 255,
};

export const TYPE_NAMES: Record<number, string> = Object.fromEntries(
  Object.entries(TYPE_NUMBERS).map(([k, v]) => [v, k]),
);

const RCODES: Record<number, string> = {
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP',
  5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH',
  10: 'NOTZONE', 16: 'BADSIG', 17: 'BADKEY', 18: 'BADTIME', 19: 'BADMODE',
};

export function rcodeName(rc: number): string {
  return RCODES[rc] || `RCODE${rc}`;
}

export class DnsWireError extends Error {
  code: string;
  rcode?: number;
  constructor(code: string, message?: string, rcode?: number) {
    super(message || code);
    this.code = code;
    this.rcode = rcode;
    this.name = 'DnsWireError';
  }
}

export interface WireRR {
  name: string;
  type: number;
  typeName: string;
  class: string;
  ttl: number;
  data: string;
  raw: string; // base64 rdata
}

export interface WireResponse {
  id: number;
  rcode: number;
  rcodeName: string;
  aa: boolean;
  tc: boolean;
  rd: boolean;
  ra: boolean;
  ad: boolean;
  cd: boolean;
  answers: WireRR[];
  authority: WireRR[];
  additional: WireRR[];
  edns: { udpSize: number; do: boolean } | null;
  server: string;
  responseTimeMs: number;
}

// ----------------------------------------------------------- build query

function encodeName(name: string): Buffer {
  const clean = name.replace(/\.$/, '');
  const parts = clean ? clean.split('.') : [];
  const chunks: Buffer[] = [];
  for (const p of parts) {
    const b = Buffer.from(p, 'ascii');
    if (b.length > 63) throw new DnsWireError('FORMERR', 'label too long');
    chunks.push(Buffer.from([b.length]), b);
  }
  chunks.push(Buffer.from([0]));
  return Buffer.concat(chunks);
}

export function buildQuery(opts: {
  name: string;
  type: number;
  id?: number;
  rd?: boolean;
  edns?: boolean;
  dnssecDo?: boolean;
  udpSize?: number;
}): Buffer {
  const id = opts.id ?? randomInt(1, 0xffff);
  const flags = (opts.rd === false ? 0 : 0x0100); // RD
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(opts.edns === false ? 0 : 1, 10); // ARCOUNT (OPT)
  const question = Buffer.concat([
    encodeName(opts.name),
    (() => { const b = Buffer.alloc(4); b.writeUInt16BE(opts.type, 0); b.writeUInt16BE(1, 2); return b; })(),
  ]);
  let additional = Buffer.alloc(0);
  if (opts.edns !== false) {
    const ttl = Buffer.alloc(4);
    if (opts.dnssecDo) ttl.writeUInt32BE(0x8000, 0);
    additional = Buffer.concat([
      Buffer.from([0]), // root name
      (() => { const b = Buffer.alloc(2); b.writeUInt16BE(41, 0); return b; })(), // OPT
      (() => { const b = Buffer.alloc(2); b.writeUInt16BE(opts.udpSize || 4096, 0); return b; })(), // class = UDP size
      ttl,
      (() => { const b = Buffer.alloc(2); b.writeUInt16BE(0, 0); return b; })(), // RDLENGTH
    ]);
  }
  return Buffer.concat([header, question, additional]);
}

// ------------------------------------------------------------ parse msg

function readName(buf: Buffer, offset: number): { name: string; offset: number } {
  const labels: string[] = [];
  let jumped = false;
  let pos = offset;
  let endPos = offset;
  const visited = new Set<number>();
  for (;;) {
    if (pos >= buf.length) throw new DnsWireError('FORMERR', 'name out of bounds');
    if (visited.has(pos)) throw new DnsWireError('FORMERR', 'compression loop');
    visited.add(pos);
    const len = buf[pos];
    if (len === 0) {
      pos += 1;
      if (!jumped) endPos = pos;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw new DnsWireError('FORMERR', 'bad pointer');
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (!jumped) endPos = pos + 2;
      jumped = true;
      pos = ptr;
      continue;
    }
    labels.push(buf.subarray(pos + 1, pos + 1 + len).toString('ascii'));
    pos += 1 + len;
  }
  return { name: labels.join('.'), offset: endPos };
}

function parseRR(buf: Buffer, offset: number): { rr: WireRR; offset: number } {
  const n = readName(buf, offset);
  let p = n.offset;
  const type = buf.readUInt16BE(p); p += 2;
  const cls = buf.readUInt16BE(p); p += 2;
  const ttl = buf.readUInt32BE(p); p += 4;
  const rdlen = buf.readUInt16BE(p); p += 2;
  const rdata = buf.subarray(p, p + rdlen);
  const data = formatRdata(type, rdata, buf, p);
  p += rdlen;
  return {
    rr: {
      name: n.name,
      type,
      typeName: TYPE_NAMES[type] || `TYPE${type}`,
      class: cls === 1 ? 'IN' : cls === 255 ? 'ANY' : String(cls),
      ttl,
      data,
      raw: rdata.length ? rdata.toString('base64') : '',
    },
    offset: p,
  };
}

function readCharacterStrings(r: Buffer, start: number): string[] {
  const out: string[] = [];
  let p = start;
  while (p < r.length) {
    const l = r[p];
    out.push(r.subarray(p + 1, p + 1 + l).toString('utf8'));
    p += 1 + l;
  }
  return out;
}

const BASE32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

function base32Hex(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32HEX[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32HEX[(value << (5 - bits)) & 31];
  return out;
}

function ipv6FromBytes(b: Buffer): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(b.readUInt16BE(i));
  // find longest run of zero groups (>= 2) to compress with '::'
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  groups.forEach((g, i) => {
    if (g === 0) {
      if (curStart < 0) {
        curStart = i;
        curLen = 1;
      } else {
        curLen += 1;
      }
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  });
  const parts = groups.map((g) => g.toString(16));
  if (bestLen >= 2) {
    const head = parts.slice(0, bestStart).join(':');
    const tail = parts.slice(bestStart + bestLen).join(':');
    return `${head}::${tail}`;
  }
  return parts.join(':');
}

function locString(r: Buffer): string {
  try {
    const version = r[0];
    if (version !== 0) return r.toString('base64');
    const dec = (v: number): string => {
      const mant = (v >> 4) & 0x0f;
      const exp = v & 0x0f;
      return String(mant * Math.pow(10, exp - 9));
    };
    const latRaw = r.readUInt32BE(4);
    const lonRaw = r.readUInt32BE(8);
    const altRaw = r.readUInt32BE(12);
    const lat = (latRaw - 0x80000000) / 60000; // degrees * 1000 → /3600000*... using /6e4 approximates degrees
    const lon = (lonRaw - 0x80000000) / 60000;
    const alt = (altRaw - 10000000) / 100;
    return `${Math.abs(lat).toFixed(4)} ${lat >= 0 ? 'N' : 'S'} ${Math.abs(lon).toFixed(4)} ${lon >= 0 ? 'E' : 'W'} ${alt.toFixed(1)}m`;
  } catch {
    return r.toString('base64');
  }
}

export function formatRdata(type: number, r: Buffer, full: Buffer, rdStart: number): string {
  const b64 = (): string => r.toString('base64');
  try {
    switch (type) {
      case 1: // A
        return Array.from(r).join('.');
      case 28: // AAAA
        return ipv6FromBytes(r);
      case 2: case 5: case 12: case 39: { // NS CNAME PTR DNAME
        return readName(full, rdStart).name;
      }
      case 6: { // SOA
        const m = readName(full, rdStart);
        const r2 = readName(full, m.offset);
        let p = r2.offset;
        const serial = r.readUInt32BE(p); const refresh = r.readUInt32BE(p + 4);
        const retry = r.readUInt32BE(p + 8); const expire = r.readUInt32BE(p + 12);
        const minimum = r.readUInt32BE(p + 16);
        return `${m.name} ${r2.name} ${serial} ${refresh} ${retry} ${expire} ${minimum}`;
      }
      case 15: { // MX
        const pref = r.readUInt16BE(0);
        const host = readName(full, rdStart + 2).name;
        return `${pref} ${host}`;
      }
      case 16: // TXT
        return readCharacterStrings(r, 0).map((s) => `"${s}"`).join(' ');
      case 33: { // SRV
        const prio = r.readUInt16BE(0), weight = r.readUInt16BE(2), port = r.readUInt16BE(4);
        const target = readName(full, rdStart + 6).name;
        return `${prio} ${weight} ${port} ${target}`;
      }
      case 35: { // NAPTR
        const order = r.readUInt16BE(0), pref = r.readUInt16BE(2);
        let p = 4;
        const flags = readCharacterStrings(r, p); p += 1 + r[p];
        const service = readCharacterStrings(r, p); p += 1 + r[p];
        const regexp = readCharacterStrings(r, p); p += 1 + r[p];
        const replacement = readName(full, rdStart + p).name;
        return `${order} ${pref} "${flags[0] || ''}" "${service[0] || ''}" "${regexp[0] || ''}" ${replacement}`;
      }
      case 43: { // DS
        const keytag = r.readUInt16BE(0).toString();
        const alg = String(r[2]);
        const dt = String(r[3]);
        return `${keytag} ${alg} ${dt} ${r.subarray(4).toString('hex').toUpperCase()}`;
      }
      case 48: { // DNSKEY
        const flags = r.readUInt16BE(0);
        const proto = String(r[2]);
        const alg = String(r[3]);
        return `${flags} ${proto} ${alg} ${r.subarray(4).toString('base64')}`;
      }
      case 46: { // RRSIG
        const covered = (TYPE_NAMES[r.readUInt16BE(0)] || '?');
        const alg = String(r[2]);
        const labels = String(r[3]);
        const origTtl = String(r.readUInt32BE(4));
        const exp = new Date(r.readUInt32BE(8) * 1000).toISOString().slice(0, 13).replace('T', ' ');
        const inc = new Date(r.readUInt32BE(12) * 1000).toISOString().slice(0, 13).replace('T', ' ');
        const keytag = String(r.readUInt16BE(16));
        const signer = readName(full, rdStart + 18).name;
        const sig = r.subarray(18 + signer.length + 1).toString('base64');
        return `${covered} ${alg} ${labels} ${origTtl} ${exp} ${inc} ${keytag} ${signer} ${sig}`;
      }
      case 47: { // NSEC
        const next = readName(full, rdStart).name;
        return `${next}`;
      }
      case 50: { // NSEC3
        const alg = String(r[0]);
        const flags = String(r[1]);
        const iters = String(r.readUInt16BE(2));
        const saltLen = r[4];
        const salt = saltLen ? r.subarray(5, 5 + saltLen).toString('hex') : '-';
        const hashLen = r[5 + saltLen];
        const hash = base32Hex(r.subarray(6 + saltLen, 6 + saltLen + hashLen)).toLowerCase();
        return `${alg} ${flags} ${iters} ${salt} ${hash}`;
      }
      case 51: { // NSEC3PARAM
        const alg = String(r[0]);
        const flags = String(r[1]);
        const iters = String(r.readUInt16BE(2));
        const saltLen = r[4];
        const salt = saltLen ? r.subarray(5, 5 + saltLen).toString('hex') : '-';
        return `${alg} ${flags} ${iters} ${salt}`;
      }
      case 52: { // TLSA
        return `${r[0]} ${r[1]} ${r[2]} ${r.subarray(3).toString('hex')}`;
      }
      case 44: { // SSHFP
        return `${r[0]} ${r[1]} ${r.subarray(2).toString('hex')}`;
      }
      case 64: case 65: { // SVCB / HTTPS
        const prio = r.readUInt16BE(0);
        const target = readName(full, rdStart + 2).name;
        let p = 2 + target.length + 1;
        const params: string[] = [];
        while (p + 4 <= r.length) {
          const key = r.readUInt16BE(p);
          const len = r.readUInt16BE(p + 2);
          const val = r.subarray(p + 4, p + 4 + len);
          if (key === 1) params.push(`alpn=${Array.from(val).join(',')}`);
          else if (key === 3) params.push(`port=${val.readUInt16BE(0)}`);
          else if (key === 4) params.push(`ipv4hint=${Array.from(val).join('.')}`);
          else if (key === 6) params.push(`ipv6hint=${ipv6FromBytes(val)}`);
          else params.push(`key${key}=${val.toString('hex') || '""'}`);
          p += 4 + len;
        }
        return `${prio} ${target}${params.length ? ' ' + params.join(' ') : ''}`;
      }
      case 29: return locString(r); // LOC
      case 37: { // CERT
        const ct = r.readUInt16BE(0);
        const tag = String(r.readUInt16BE(2));
        const alg = String(r[4]);
        return `type${ct} ${tag} ${alg} ${r.subarray(5).toString('base64').slice(0, 96)}…`;
      }
      case 256: { // URI
        const prio = r.readUInt16BE(0), weight = r.readUInt16BE(2);
        return `${prio} ${weight} "${readCharacterStrings(r, 4).join('')}"`;
      }
      case 257: { // CAA
        const flag = r[0];
        const tagLen = r[1];
        const tag = r.subarray(2, 2 + tagLen).toString('ascii');
        const value = r.subarray(2 + tagLen).toString('ascii');
        return `${flag} ${tag} "${value}"`;
      }
      case 13: { // HINFO
        return readCharacterStrings(r, 0).join(' ');
      }
      case 17: { // RP
        const m = readName(full, rdStart);
        const t = readName(full, m.offset);
        return `${m.name} ${t.name}`;
      }
      case 18: { // AFSDB
        return `${r.readUInt16BE(0)} ${readName(full, rdStart + 2).name}`;
      }
      default:
        return b64();
    }
  } catch {
    return b64();
  }
}

// --------------------------------------------------------------- client

export interface WireQueryOptions {
  name: string;
  type: number | string;
  server: string;
  port?: number;
  timeoutMs?: number;
  rd?: boolean;
  edns?: boolean;
  dnssecDo?: boolean;
}

/** Execute a raw UDP DNS query against a specific resolver. */
export function wireQuery(opts: WireQueryOptions): Promise<WireResponse> {
  const typeNum = typeof opts.type === 'number' ? opts.type : TYPE_NUMBERS[String(opts.type).toUpperCase()];
  if (!typeNum) throw new DnsWireError('FORMERR', `Unknown record type ${opts.type}`);
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    const id = randomInt(1, 0xffff);
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { socket.close(); } catch { /* already closed */ }
      fn();
    };
    const timer = setTimeout(() => done(() => reject(new DnsWireError('TIMEOUT', `DNS query to ${opts.server} timed out`))), opts.timeoutMs ?? 4000);
    socket.on('message', (msg) => {
      try {
        if (msg.length < 12) throw new DnsWireError('FORMERR', 'short response');
        const rid = msg.readUInt16BE(0);
        if (rid !== id) return; // stale/other response, keep waiting
        const flags = msg.readUInt16BE(2);
        const qd = msg.readUInt16BE(4);
        const an = msg.readUInt16BE(6);
        const ns = msg.readUInt16BE(8);
        const ar = msg.readUInt16BE(10);
        let p = 12;
        for (let i = 0; i < qd; i++) {
          const q = readName(msg, p);
          p = q.offset + 4;
        }
        const answers: WireRR[] = [];
        const authority: WireRR[] = [];
        const additional: WireRR[] = [];
        for (let i = 0; i < an; i++) { const r = parseRR(msg, p); answers.push(r.rr); p = r.offset; }
        for (let i = 0; i < ns; i++) { const r = parseRR(msg, p); authority.push(r.rr); p = r.offset; }
        let edns: WireResponse['edns'] = null;
        for (let i = 0; i < ar; i++) {
          const r = parseRR(msg, p);
          p = r.offset;
          if (r.rr.type === 41) {
            edns = { udpSize: r.rr.class === 'ANY' ? 4096 : parseInt(r.rr.class, 10) || 4096, do: false };
            // DO bit lives in ttl — re-read from buffer quickly
          }
        }
        const rc = flags & 0x0f;
        const resp: WireResponse = {
          id: rid,
          rcode: rc,
          rcodeName: rcodeName(rc),
          aa: (flags >> 10) & 1 ? true : false,
          tc: (flags >> 9) & 1 ? true : false,
          rd: (flags >> 8) & 1 ? true : false,
          ra: (flags >> 7) & 1 ? true : false,
          ad: (flags >> 5) & 1 ? true : false,
          cd: (flags >> 4) & 1 ? true : false,
          answers,
          authority,
          additional,
          edns,
          server: opts.server,
          responseTimeMs: Date.now() - started,
        };
        done(() => resolve(resp));
      } catch (e) {
        done(() => reject(new DnsWireError('PARSE_ERROR', (e as Error).message)));
      }
    });
    socket.on('error', (e) => done(() => reject(new DnsWireError('NETWORK', e.message))));
    const buf = buildQuery({ name: opts.name, type: typeNum, id, rd: opts.rd, edns: opts.edns, dnssecDo: opts.dnssecDo });
    socket.send(buf, opts.port ?? 53, opts.server, (err) => {
      if (err) done(() => reject(new DnsWireError('NETWORK', err.message)));
    });
  });
}

/** Convert wire RRs to the shared DnsRecord shape. */
export function wireToRecords(rrs: WireRR[]): import('./types').DnsRecord[] {
  return rrs.map((rr) => {
    let priority: number | null = null;
    if (rr.type === 15 || rr.typeName === 'MX') priority = parseInt(rr.data.split(' ')[0], 10) || 0;
    if (rr.type === 33 || rr.typeName === 'SRV') priority = parseInt(rr.data.split(' ')[0], 10) || 0;
    return {
      type: rr.typeName,
      name: rr.name || '.',
      value: rr.data,
      ttl: rr.ttl,
      priority,
      class: rr.class,
    };
  });
}
