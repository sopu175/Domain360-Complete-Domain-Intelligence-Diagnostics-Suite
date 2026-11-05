import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { cached, TTL } from '../cache';
import { TIMEOUTS } from '../config';
import { resolveHostIps } from '../resolver';
import type { SslChainCert, SslResult } from '../types';

const SIG_ALGS: Record<string, string> = {
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
  '1.3.101.112': 'ed25519',
};

const EC_CURVES: Record<string, number> = {
  '1.2.840.10045.3.1.7': 256,
  '1.3.132.0.34': 384,
  '1.3.132.0.35': 521,
  '1.3.132.0.10': 256,
  '1.3.101.110': 253,
  '1.3.101.111': 253,
  '1.3.101.112': 256,
  '1.3.101.113': 256,
};

/** Read first OID after the outer+tbs signature SEQUENCE in a DER cert. */
function readSignatureOid(der: Buffer): string | null {
  try {
    let p = 0;
    const readLen = (): number => {
      const b = der[p++];
      if (b & 0x80) {
        const n = b & 0x7f;
        let len = 0;
        for (let i = 0; i < n; i++) len = len * 256 + der[p++];
        return len;
      }
      return b;
    };
    const expect = (tag: number): boolean => {
      if (der[p] !== tag) return false;
      p++;
      readLen();
      return true;
    };
    if (!expect(0x30)) return null; // Certificate SEQUENCE
    if (!expect(0x30)) return null; // tbsCertificate SEQUENCE
    if (!expect(0x30)) return null; // signatureAlgorithm SEQUENCE
    if (der[p] !== 0x06) return null;
    p++;
    const oidLen = der[p++];
    const oidBytes = der.subarray(p, p + oidLen);
    // decode OID
    const first = oidBytes[0];
    const parts = [String(Math.floor(first / 40)), String(first % 40)];
    let val = 0;
    for (let i = 1; i < oidBytes.length; i++) {
      val = (val << 7) | (oidBytes[i] & 0x7f);
      if (!(oidBytes[i] & 0x80)) {
        parts.push(String(val));
        val = 0;
      }
    }
    return parts.join('.');
  } catch {
    return null;
  }
}

function keyInfo(x509: X509Certificate): { algorithm: string; bits: number | null } {
  try {
    const kt = x509.publicKey.asymmetricKeyType;
    const type = kt ? String(kt) : 'unknown';
    if (type === 'ed25519' || type === 'ed448') return { algorithm: type, bits: type === 'ed25519' ? 256 : 456 };
    const spki = x509.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    if (type === 'rsa') {
      // find modulus INTEGER length inside the BIT STRING
      try {
        const s = spki.indexOf(Buffer.from([0x03]), 10); // BIT STRING
        let p = s + 1;
        const readLen = (): number => {
          const b = spki[p++];
          if (b & 0x80) {
            const n = b & 0x7f;
            let len = 0;
            for (let i = 0; i < n; i++) len = len * 256 + spki[p++];
            return len;
          }
          return b;
        };
        readLen(); // bitstring len
        p += 1; // unused bits byte
        if (spki[p] === 0x30) {
          p++;
          readLen(); // inner SEQUENCE
          if (spki[p] === 0x02) {
            p++;
            const mlen = readLen();
            // strip leading zero
            const modBytes = spki[p] === 0 ? mlen - 1 : mlen;
            return { algorithm: 'rsa', bits: modBytes * 8 };
          }
        }
      } catch {
        /* fall through */
      }
      return { algorithm: 'rsa', bits: null };
    }
    if (type === 'ec') {
      // curve OID is the OID right after the algorithm OID in SPKI
      const oidMatch = spki.subarray(0, 40).toString('hex');
      for (const [oid, bits] of Object.entries(EC_CURVES)) {
        const hex = oid
          .split('.')
          .map((x) => parseInt(x, 10))
          .reduce<Buffer>((acc, n, i) => {
            if (i < 2) return Buffer.from([(acc[0] ?? 0) * 40 + n]);
            const out: number[] = [];
            let v = n;
            const tmp: number[] = [v & 0x7f];
            v >>= 7;
            while (v) {
              tmp.unshift((v & 0x7f) | 0x80);
              v >>= 7;
            }
            out.push(...tmp);
            return Buffer.concat([acc, Buffer.from(out)]);
          }, Buffer.from([0]))
          .toString('hex');
        if (oidMatch.includes(hex)) return { algorithm: 'ec', bits };
      }
      return { algorithm: 'ec', bits: null };
    }
    return { algorithm: type, bits: null };
  } catch {
    return { algorithm: 'unknown', bits: null };
  }
}

function toChainCert(cert: tls.PeerCertificate): SslChainCert {
  const x509 = (() => {
    try {
      return new X509Certificate(cert.raw);
    } catch {
      return null;
    }
  })();
  const sigOid = x509 ? readSignatureOid(cert.raw) : null;
  const ki = x509 ? keyInfo(x509) : { algorithm: 'unknown', bits: null };
  const subjectCn = String(cert.subject?.CN || '');
  const issuerCn = String(cert.issuer?.CN || '');
  const sans = (cert.subjectaltname || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => s.replace(/^DNS:/, 'dns:').replace(/^IP Address:/, 'ip:'));
  return {
    subjectCn,
    subject: Object.fromEntries(Object.entries(cert.subject || {}).map(([k, v]) => [k, String(v)])),
    issuerCn,
    issuer: Object.fromEntries(Object.entries(cert.issuer || {}).map(([k, v]) => [k, String(v)])),
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    serialNumber: cert.serialNumber,
    fingerprint256: cert.fingerprint256 || '',
    sans,
    keyAlgorithm: ki.algorithm,
    keyBits: ki.bits,
    signatureAlgorithm: sigOid ? SIG_ALGS[sigOid] || sigOid : 'unknown',
    selfIssued: subjectCn === issuerCn,
  };
}

function parseInfoAccess(x509: X509Certificate): { ocsp: string[]; crl: string[] } {
  const ocsp: string[] = [];
  const crl: string[] = [];
  try {
    const raw = (x509 as unknown as { infoAccess?: unknown }).infoAccess;
    const text = JSON.stringify(raw ?? '');
    for (const m of text.matchAll(/https?:\/\/[^"\\\s]+/g)) {
      const idx = text.indexOf(m[0]);
      const ctx = text.slice(Math.max(0, idx - 60), idx);
      if (/OCSP/i.test(ctx)) ocsp.push(m[0]);
      else if (/caIssuers/i.test(ctx)) crl.push(m[0]);
    }
  } catch {
    /* not exposed */
  }
  return { ocsp: [...new Set(ocsp)], crl: [...new Set(crl)] };
}

function probeProtocol(ip: string, servername: string, version: tls.SecureVersion): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: ip,
      port: 443,
      servername,
      rejectUnauthorized: false,
      minVersion: version,
      maxVersion: version,
      timeout: 4000,
    });
    let settled = false;
    const done = (v: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(v);
    };
    socket.setTimeout(4000, () => done(false));
    socket.once('secureConnect', () => done(true));
    socket.once('error', () => done(false));
  });
}

function cipherBits(name: string): number | null {
  if (/AES_256|CHACHA20/.test(name)) return 256;
  if (/AES_128/.test(name)) return 128;
  if (/3DES/.test(name)) return 112;
  if (/RC4/.test(name)) return 128;
  return null;
}

export async function inspectSsl(input: { ascii: string }): Promise<SslResult> {
  return cached(`ssl:${input.ascii}`, TTL.ssl, async (): Promise<SslResult> => {
    const errors: string[] = [];
    const ips = await resolveHostIps(input.ascii);
    const ip = ips.v4[0] ?? ips.v6[0] ?? null;

    const base = {
      host: input.ascii,
      ip,
      ocspUrls: [] as string[],
      crlUrls: [] as string[],
      ctLogsSeen: null,
      errors,
      timestamp: new Date().toISOString(),
    };

    if (!ip) {
      return {
        ...base,
        httpsAvailable: false,
        status: 'not_installed',
        hostnameMatch: null,
        cert: null,
        chain: [],
        chainComplete: null,
        daysRemaining: null,
        protocols: [],
        negotiatedProtocol: null,
        cipher: null,
      };
    }

    // main handshake
    const handshake = await new Promise<{
      ok: boolean;
      socket?: tls.TLSSocket;
      error?: string;
    }>((resolve) => {
      const socket = tls.connect({
        host: ip!,
        port: 443,
        servername: input.ascii,
        rejectUnauthorized: false,
        minVersion: 'TLSv1',
        timeout: TIMEOUTS.tls,
      });
      let settled = false;
      const done = (r: { ok: boolean; socket?: tls.TLSSocket; error?: string }) => {
        if (settled) return;
        settled = true;
        resolve(r);
      };
      socket.setTimeout(TIMEOUTS.tls, () => {
        socket.destroy();
        done({ ok: false, error: `Connection timed out after ${TIMEOUTS.tls / 1000}s` });
      });
      socket.once('secureConnect', () => done({ ok: true, socket }));
      socket.once('error', (e) => {
        socket.destroy();
        done({ ok: false, error: e.message });
      });
    });

    if (!handshake.ok || !handshake.socket) {
      const msg = handshake.error || 'handshake failed';
      const notInstalled = /ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|ECONNRESET|timeout/i.test(msg);
      return {
        ...base,
        httpsAvailable: false,
        status: notInstalled ? 'not_installed' : 'unverifiable',
        hostnameMatch: null,
        cert: null,
        chain: [],
        chainComplete: null,
        daysRemaining: null,
        protocols: [],
        negotiatedProtocol: null,
        cipher: null,
      };
    }

    const socket = handshake.socket;
    const peer = socket.getPeerCertificate(true) as tls.PeerCertificate & {
      issuerCertificate?: tls.PeerCertificate;
    };
    const negotiatedProtocol = socket.getProtocol() || null;
    const cipherRaw = socket.getCipher();
    const authorized = socket.authorized;
    const authError = socket.authorizationError ? String(socket.authorizationError) : null;
    socket.end();

    // chain
    type CertWithIssuer = tls.PeerCertificate & { issuerCertificate?: CertWithIssuer };
    const chain: SslChainCert[] = [];
    const seen = new Set<string>();
    let cur: CertWithIssuer | undefined = peer as CertWithIssuer;
    while (cur && cur.fingerprint256 && !seen.has(cur.fingerprint256) && chain.length < 6) {
      seen.add(cur.fingerprint256);
      chain.push(toChainCert(cur));
      cur = cur.issuerCertificate;
      if (cur && seen.has(cur.fingerprint256)) break;
    }
    const leaf = chain[0] ?? null;
    const chainComplete = chain.length >= 2 ? true : leaf ? false : null;

    // x509 helpers
    let x509: X509Certificate | null = null;
    try {
      if (peer.raw) x509 = new X509Certificate(peer.raw);
    } catch {
      x509 = null;
    }
    const { ocsp, crl } = x509 ? parseInfoAccess(x509) : { ocsp: [], crl: [] };

    // hostname match
    let hostnameMatch: boolean | null = null;
    if (authorized) {
      hostnameMatch = true;
    } else if (x509) {
      try {
        const res = x509.checkHost(input.ascii) as unknown;
        // Node returns undefined when the name matches, a reason string when it does not
        hostnameMatch = !(typeof res === 'string' && res.length > 0);
      } catch {
        hostnameMatch = null;
      }
    }
    if (hostnameMatch === null && authError) {
      if (/hostname|IP address mismatch|common name/i.test(authError)) hostnameMatch = false;
    }

    const selfSigned = chain.length === 1 && leaf?.selfIssued;
    const validTo = leaf ? new Date(leaf.validTo) : null;
    const expired = validTo ? validTo.getTime() < Date.now() : false;
    const daysRemaining = validTo
      ? Math.floor((validTo.getTime() - Date.now()) / 86400000)
      : null;

    let status: SslResult['status'];
    if (!leaf) status = 'unverifiable';
    else if (expired) status = 'expired';
    else if (selfSigned || (authError && /self-signed|self signed|DEPTH_ZERO/i.test(authError))) status = 'self_signed';
    else if (hostnameMatch === false || (authError && !authorized)) status = 'invalid';
    else if (daysRemaining !== null && daysRemaining <= 15) status = 'expiring_soon';
    else status = 'valid';

    // protocol probes
    const versions: tls.SecureVersion[] = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
    const protocols: { version: string; supported: boolean }[] = [];
    let clientLimited = false;
    for (const v of versions) {
      const ok = await probeProtocol(ip, input.ascii, v);
      protocols.push({ version: v, supported: ok });
      if (!ok && (v === 'TLSv1' || v === 'TLSv1.1')) {
        clientLimited = true; // may be client-side OpenSSL refusal
      }
    }
    if (clientLimited && !protocols[0].supported && !protocols[1].supported) {
      errors.push(
        'TLSv1.0/1.1 results may be under-reported: this client\'s OpenSSL refuses legacy protocols (security level). Verify legacy support independently if it matters to you.',
      );
    }

    // quick HTTPS HEAD sanity
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 6000);
      await fetch(`https://${input.ascii}/`, { method: 'HEAD', redirect: 'manual', signal: ctl.signal });
      clearTimeout(t);
    } catch (e) {
      errors.push(`TLS handshake OK but HTTPS request failed: ${(e as Error).message}`);
    }

    const cipherName = cipherRaw?.name || null;
    return {
      ...base,
      httpsAvailable: true,
      status,
      hostnameMatch,
      cert: leaf,
      chain,
      chainComplete,
      daysRemaining,
      protocols,
      negotiatedProtocol,
      cipher: cipherName
        ? { name: cipherName, version: cipherRaw?.version || null, bits: cipherBits(cipherName) }
        : null,
      ocspUrls: ocsp,
      crlUrls: crl,
    };
  });
}
