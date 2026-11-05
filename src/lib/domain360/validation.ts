import { domainToASCII } from 'node:url';

/**
 * Domain / IP input validation with IDN (punycode) support.
 */

const LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export class ValidationError extends Error {
  code = 'INVALID_INPUT';
}

/** Returns the punycode (ASCII) form of a user-supplied domain, or throws. */
export function toAsciiDomain(raw: string): string {
  let input = (raw || '').trim().toLowerCase();
  if (!input) throw new ValidationError('Please enter a domain name.');
  // strip scheme, credentials, path, port, trailing dot
  input = input
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/^www\./, (m) => m) // keep www (it is a valid host to scan)
    .split(/[/?#]/)[0]
    .split('@')
    .pop()!
    .replace(/:\d+$/, '')
    .replace(/\.+$/, '');
  if (input.includes(' ') || input.includes('_')) {
    // underscores are technically illegal in hostnames but common in DNS;
    // only allow for _dmarc style names — basic lookup domains must not have them
    if (!input.startsWith('_')) throw new ValidationError('Domain names cannot contain spaces or underscores.');
  }
  if (input.length > 253) throw new ValidationError('Domain name is too long.');
  let ascii: string;
  try {
    ascii = domainToASCII(input);
  } catch {
    throw new ValidationError('Invalid domain name.');
  }
  if (!ascii) ascii = input;
  const labels = ascii.split('.');
  if (labels.length < 2) throw new ValidationError('Enter a fully-qualified domain name (e.g. example.com).');
  for (const l of labels) {
    if (!l || l.length > 63) throw new ValidationError('Invalid domain label length.');
    if (!LABEL_RE.test(l)) {
      // allow xn-- punycode labels (they match LABEL_RE anyway) and wildcard-free names
      throw new ValidationError(`"${l}" is not a valid domain label.`);
    }
  }
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,63}$/.test(tld) && !tld.startsWith('xn--')) {
    throw new ValidationError('Invalid top-level domain.');
  }
  const invalidTlds = ['local', 'localhost', 'test', 'example', 'invalid', 'lan', 'home', 'internal'];
  if (invalidTlds.includes(tld)) {
    throw new ValidationError(`.${tld} is a reserved TLD and cannot be looked up.`);
  }
  return ascii;
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIPv4(s: string): boolean {
  const m = IPV4_RE.exec(s);
  if (!m) return false;
  return m.slice(1).every((p) => Number(p) <= 255);
}

export function isIP(s: string): 0 | 4 | 6 {
  if (isIPv4(s)) return 4;
  if (s.includes(':')) {
    // loose IPv6 sanity check
    const parts = s.split(':');
    if (parts.length >= 3 && parts.length <= 9 && /^[0-9a-f:.]+$/i.test(s)) return 6;
  }
  return 0;
}

/** Accepts either a domain or an IP address; reports which one it is. */
export function toAsciiDomainOrIp(raw: string): { value: string; isIp: 0 | 4 | 6 } {
  const input = (raw || '').trim().toLowerCase();
  if (!input) throw new ValidationError('Please enter a domain or IP address.');
  const ipKind = isIP(input);
  if (ipKind) return { value: input, isIp: ipKind };
  return { value: toAsciiDomain(input), isIp: 0 };
}
