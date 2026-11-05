import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import dnsMod from 'node:dns';
const resolve4 = (h) => dnsMod.promises.resolve4(h).catch(() => []);

function grab(host, ip) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: ip, port: 443, servername: host, rejectUnauthorized: false, minVersion: 'TLSv1' });
    const done = (v) => { try { socket.destroy(); } catch {} resolve(v); };
    socket.setTimeout(8000, () => done({ error: 'timeout' }));
    socket.on('secureConnect', () => {
      const peer = socket.getPeerCertificate(true);
      const x = peer.raw ? new X509Certificate(peer.raw) : null;
      socket.destroy();
      resolve({
        authorized: socket.authorized,
        authErr: socket.authorizationError ? String(socket.authorizationError.message ?? socket.authorizationError) : null,
        authErrType: socket.authorizationError ? typeof socket.authorizationError : null,
        cn: peer.subject?.CN ?? null,
        chainDepth: (() => { let c = peer, d = 0; while (c && c.raw && d < 8) { const n = c.issuerCertificate; if (!n || !n.raw || n === c) break; c = n; d++; } return d + 1; })(),
        leafValidTo: peer.valid_to,
        x509ValidTo: x ? x.validTo : null,
        x509ValidToDate: x ? String(x.validToDate) : null,
        mismatch: x ? x.checkHost('wrong.host.badssl.com') : null,
        selfmatch: x ? x.checkHost(host) : null,
        keyType: x ? x.publicKey.asymmetricKeyType : null,
      });
    });
    socket.on('error', (e) => done({ error: e.message, code: e.code }));
  });
}

for (const h of ['github.com', 'expired.badssl.com', 'self-signed.badssl.com', 'wrong.host.badssl.com']) {
  const ip = (await resolve4(h))[0];
  console.log(h, '->', ip, JSON.stringify(await grab(h, ip)));
}

// Date parse checks
console.log('Date.parse legacy:', Date.parse('Oct 30 00:00:00 2026 GMT'), new Date('Oct 30 00:00:00 2026 GMT').toISOString());
console.log('Date.parse expired:', new Date('Apr 12 23:59:59 2020 GMT').toISOString());

// http2 probe on github
import http2 from 'node:http2';
const h2res = await new Promise((resolve) => {
  let s;
  const fin = (v) => { try { s?.close(); } catch {}; resolve(v); };
  const t = setTimeout(() => fin('timeout'), 5000);
  try { s = http2.connect('https://github.com'); } catch (e) { clearTimeout(t); fin('connect-throw: ' + e.message); return; }
  s.on('error', (e) => { clearTimeout(t); fin('session-error: ' + e.message + ' code=' + e.code); });
  const req = s.request({ ':method': 'HEAD', ':path': '/' });
  req.on('response', (hdrs) => { clearTimeout(t); fin({ ok: true, status: hdrs[':status'] }); });
  req.on('error', (e) => { clearTimeout(t); fin('req-error: ' + e.message); });
  req.end();
});
console.log('h2 probe:', JSON.stringify(h2res));
