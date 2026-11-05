import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';

function probe(host, ip) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: ip, port: 443, servername: host, rejectUnauthorized: false, minVersion: 'TLSv1' });
    const done = (v) => { try { socket.destroy(); } catch {} resolve(v); };
    socket.setTimeout(8000, () => done('TIMEOUT'));
    socket.on('secureConnect', () => {
      const out = { protocol: socket.getProtocol(), cipher: socket.getCipher(), authorized: socket.authorized, authErr: String(socket.authorizationError) };
      const peer = socket.getPeerCertificate(true);
      out.peerKeys = Object.keys(peer);
      const chain = [];
      let cur = peer, depth = 0;
      while (cur && cur.raw && depth < 8) {
        const x = new X509Certificate(cur.raw);
        chain.push({
          cn: (cur.subject && cur.subject.CN) || null,
          subjectStr: x.subject,
          validFrom: x.validFrom,
          validTo: x.validTo,
          serial: x.serialNumber,
          sanType: typeof x.subjectAltName,
          san: x.subjectAltName,
          infoType: typeof x.infoAccess,
          info: x.infoAccess,
          checkHost: x.checkHost(host),
        });
        const nxt = cur.issuerCertificate;
        if (!nxt || !nxt.raw || nxt === cur) break;
        cur = nxt; depth++;
      }
      out.chain = chain;
      socket.destroy();
      resolve(out);
    });
    socket.on('error', (e) => done({ error: e.message, code: e.code }));
  });
}

function probeVersion(ip, host, ver) {
  return new Promise((resolve) => {
    let s;
    try {
      s = tls.connect({ host: ip, port: 443, servername: host, rejectUnauthorized: false, minVersion: ver, maxVersion: ver });
    } catch (e) { resolve({ ver, syncError: e.message }); return; }
    const t = setTimeout(() => { try { s.destroy(); } catch {} resolve({ ver, error: 'timeout' }); }, 4000);
    s.on('secureConnect', () => { clearTimeout(t); try { s.destroy(); } catch {} resolve({ ver, ok: true, protocol: s.getProtocol() }); });
    s.on('error', (e) => { clearTimeout(t); resolve({ ver, error: e.message, code: e.code }); });
  });
}

const dnsMod = await import('node:dns');
const dns = await dnsMod.promises.resolve4('github.com').catch(() => []);
const ip = dns[0];
console.log('IP:', ip);
console.log(JSON.stringify(await probe('github.com', ip), null, 1));
for (const v of ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']) {
  console.log(JSON.stringify(await probeVersion(ip, 'github.com', v)));
}
