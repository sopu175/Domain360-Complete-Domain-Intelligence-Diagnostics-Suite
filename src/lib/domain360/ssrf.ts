import { isIP } from './validation';

/**
 * SSRF protection: user-supplied domains may resolve to internal addresses.
 * Every outbound connection to a user-controlled host must pass through here.
 */

class SsrfError extends Error {
  code = 'BLOCKED_TARGET';
  constructor(msg: string) {
    super(msg);
    this.name = 'SsrfError';
  }
}

function v4ToInt(ip: string): number {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

function inCidr4(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (v4ToInt(ip) & mask) === (v4ToInt(base) & mask);
}

const PRIVATE_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
  '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
  '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
];

export function isPrivateIp(ip: string): boolean {
  const kind = isIP(ip);
  if (kind === 4) {
    return PRIVATE_V4.some((c) => inCidr4(ip, c));
  }
  if (kind === 6) {
    const v = ip.toLowerCase();
    if (v === '::' || v === '::1') return true;
    if (v.startsWith('fe80') || v.startsWith('fc') || v.startsWith('fd')) return true; // link-local / ULA
    if (v.startsWith('::ffff:')) {
      const mapped = v.replace('::ffff:', '');
      if (isIP(mapped) === 4) return isPrivateIp(mapped);
    }
    if (/^f[cd]/.test(v)) return true;
    if (v.startsWith('ff')) return true; // multicast
    if (v.startsWith('2001:db8')) return true; // documentation
    if (v.startsWith('64:ff9b::')) {
      // NAT64 well-known prefix embeds an IPv4
      const tail = v.replace('64:ff9b::', '');
      if (isIP(tail) === 4) return isPrivateIp(tail);
    }
    return false;
  }
  return true; // unparseable → treat as private
}

export function assertPublicIp(ip: string): void {
  if (isPrivateIp(ip)) {
    throw new SsrfError(`Refusing to contact private or reserved address ${ip}`);
  }
}

export { SsrfError };
