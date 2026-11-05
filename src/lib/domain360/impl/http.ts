import http2 from 'node:http2';
import { cached, TTL } from '../cache';
import { MAX_HTTP_BYTES, TIMEOUTS, USER_AGENT } from '../config';
import { assertPublicIp } from '../ssrf';
import { resolveHostIps } from '../resolver';
import type { HttpRedirectHop, HttpResult } from '../types';

function safeCancel(res: Response): void {
  try {
    const b = res.body;
    if (b) void b.cancel().catch(() => {});
  } catch { /* already locked/closed */ }
}

async function fetchLimited(
  url: string,
  timeoutMs: number,
): Promise<Response> {
  return fetch(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
    headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml,*/*;q=0.8' },
    cache: 'no-store',
  });
}

/** Resolve a redirect target host and assert it is public before following. */
async function assertSafeTarget(loc: string): Promise<string | null> {
  try {
    const u = new URL(loc);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
    if (port !== 80 && port !== 443) return null;
    const ips = await resolveHostIps(u.hostname);
    const ip = ips.v4[0] ?? ips.v6[0];
    if (!ip) return null;
    assertPublicIp(ip);
    return loc;
  } catch {
    return null;
  }
}

async function probeH2(host: string): Promise<boolean | null> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v: boolean | null) => {
      if (settled) return;
      settled = true;
      try { client.close(); } catch { /* noop */ }
      resolve(v);
    };
    const client = http2.connect(`https://${host}`, { settings: { enablePush: false } });
    client.setTimeout(5000, () => done(false));
    client.on('error', () => done(false));
    try {
      const req = client.request({ ':path': '/', ':method': 'HEAD' });
      req.setTimeout(5000, () => done(false));
      req.on('response', () => done(true));
      req.on('error', () => done(false));
      req.end();
    } catch {
      done(false);
    }
  });
}

async function readBodyCapped(res: Response, cap: number): Promise<{ text: string; truncated: boolean; bytes: number }> {
  const reader = res.body?.getReader();
  if (!reader) return { text: '', truncated: false, bytes: 0 };
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      chunks.push(value);
      if (total >= cap) {
        truncated = true;
        await reader.cancel().catch(() => {});
        break;
      }
    }
  }
  const merged = new Uint8Array(Math.min(total, cap));
  let off = 0;
  for (const c of chunks) {
    if (off >= merged.length) break;
    merged.set(c.subarray(0, merged.length - off), off);
    off += c.byteLength;
  }
  return { text: new TextDecoder('utf-8', { fatal: false }).decode(merged), truncated, bytes: total };
}

function extract(html: string, re: RegExp, group = 1): string | null {
  const m = re.exec(html);
  return m ? m[group] : null;
}

export async function diagnoseHttp(input: { ascii: string }): Promise<HttpResult> {
  return cached(`http:${input.ascii}`, TTL.http, async (): Promise<HttpResult> => {
    const ips = await resolveHostIps(input.ascii);
    const firstIp = ips.v4[0] ?? ips.v6[0] ?? null;
    const base = {
      target: input.ascii,
      finalUrl: '',
      schemeUsed: 'https' as const,
      statusCode: null as number | null,
      statusText: '',
      httpVersion: null as string | null,
      h2Supported: null as boolean | null,
      h3Supported: 'unknown' as const,
      ttfbMs: null as number | null,
      totalMs: null as number | null,
      redirects: [] as HttpRedirectHop[],
      redirectLoop: false,
      httpsRedirect: null as boolean | null,
      server: null as string | null,
      poweredBy: null as string | null,
      contentType: null as string | null,
      contentLengthBytes: null as number | null,
      compression: { enabled: false, encoding: null as string | null },
      headers: [] as { name: string; value: string }[],
      robots: { url: '', status: null as number | null, sitemaps: [] as string[], exists: null as boolean | null },
      sitemap: { url: '', status: null as number | null, exists: null as boolean | null },
      favicon: { url: '', status: null as number | null, exists: null as boolean | null },
      canonical: null as string | null,
      title: null as string | null,
      mixedContent: { detected: false, samples: [] as string[] },
      error: null as string | null,
      timestamp: new Date().toISOString(),
    };

    if (!firstIp) {
      return { ...base, error: 'Domain does not resolve — nothing to scan.' };
    }
    assertPublicIp(firstIp);

    // ---- redirect chain starting at http://
    const redirects: HttpRedirectHop[] = [];
    const visited = new Set<string>();
    let url = `http://${input.ascii}/`;
    let finalRes: Response | null = null;
    let loop = false;
    let sawHttpsUpgrade = false;
    const startedSchemeHttp = true;

    try {
      for (let hop = 0; hop < 10; hop++) {
        if (visited.has(url)) {
          loop = true;
          break;
        }
        visited.add(url);
        const t0 = Date.now();
        let res: Response;
        try {
          res = await fetchLimited(url, TIMEOUTS.http);
        } catch (e) {
          if (hop === 0) {
            // http failed entirely — try https directly
            const httpsUrl = `https://${input.ascii}/`;
            try {
              res = await fetchLimited(httpsUrl, TIMEOUTS.http);
              url = httpsUrl;
            } catch (e2) {
              return { ...base, error: `HTTP request failed: ${(e2 as Error).message}` };
            }
          } else {
            return { ...base, redirects, redirectLoop: loop, error: `Redirect fetch failed: ${(e as Error).message}` };
          }
        }
        const ms = Date.now() - t0;
        const status = res.status;
        const location = res.headers.get('location');
        if (url.startsWith('https://')) sawHttpsUpgrade = true;
        if (status >= 300 && status < 400 && location) {
          redirects.push({ url, status, location, ms });
          const abs = new URL(location, url).toString();
          const safe = await assertSafeTarget(abs);
          if (!safe) {
            finalRes = res;
            break;
          }
          url = safe;
          continue;
        }
        finalRes = res;
        break;
      }
    } catch (e) {
      return { ...base, redirects, error: `Scan failed: ${(e as Error).message}` };
    }

    if (!finalRes) {
      return { ...base, redirects, redirectLoop: loop, error: 'No final response obtained.' };
    }

    const finalUrl = url;
    const headers: { name: string; value: string }[] = [];
    finalRes.headers.forEach((value, name) => headers.push({ name, value }));

    const isHtml = (finalRes.headers.get('content-type') || '').includes('text/html');

    // ---- body (for html analysis)
    let bodyText = '';
    let bodyBytes = 0;
    if (isHtml) {
      try {
        const { text, bytes } = await readBodyCapped(finalRes, MAX_HTTP_BYTES);
        bodyText = text;
        bodyBytes = bytes;
      } catch {
        /* body read failed — headers still valid */
      }
    } else {
      safeCancel(finalRes);
    }

    // ---- robots / sitemap / favicon on final origin
    const origin = new URL(finalUrl).origin;
    const simpleFetchStatus = async (path: string, timeoutMs = 6000): Promise<{ status: number | null; text?: string }> => {
      try {
        const r = await fetchLimited(origin + path, timeoutMs);
        if (r.status === 200 && path === '/robots.txt') {
          const { text } = await readBodyCapped(r, 65536);
          return { status: r.status, text };
        }
        safeCancel(r);
        return { status: r.status };
      } catch {
        return { status: null };
      }
    };

    const [robotsRes, sitemapRes, faviconRes] = await Promise.all([
      simpleFetchStatus('/robots.txt'),
      simpleFetchStatus('/sitemap.xml'),
      simpleFetchStatus('/favicon.ico'),
    ]);

    const sitemaps: string[] = [];
    if (robotsRes.text) {
      for (const line of robotsRes.text.split('\n')) {
        const m = /^\s*sitemap\s*:\s*(\S+)/i.exec(line);
        if (m) sitemaps.push(m[1]);
      }
    }

    // ---- mixed content
    const mixedSamples: string[] = [];
    if (finalUrl.startsWith('https://') && bodyText) {
      for (const m of bodyText.matchAll(/(?:src|href)=["'](http:\/\/[^"']+)["']/gi)) {
        const u = m[1];
        if (/w3\.org|schema\.org|purl\.org|xmlns/.test(u)) continue;
        mixedSamples.push(u);
        if (mixedSamples.length >= 5) break;
      }
    }

    const h2 = finalUrl.startsWith('https://') ? await probeH2(new URL(finalUrl).hostname) : null;

    const contentLengthHeader = finalRes.headers.get('content-length');

    return {
      ...base,
      finalUrl,
      schemeUsed: finalUrl.startsWith('https://') ? 'https' : 'http',
      statusCode: finalRes.status,
      statusText: finalRes.statusText || '',
      httpVersion: h2 === true ? 'HTTP/2' : finalUrl.startsWith('https://') ? 'HTTP/1.1' : 'HTTP/1.1',
      h2Supported: h2,
      ttfbMs: redirects.length ? null : (redirects[0]?.ms ?? null),
      totalMs: redirects.reduce((a, r) => a + r.ms, 0),
      redirects,
      redirectLoop: loop,
      httpsRedirect: startedSchemeHttp ? sawHttpsUpgrade : null,
      server: finalRes.headers.get('server'),
      poweredBy: finalRes.headers.get('x-powered-by'),
      contentType: finalRes.headers.get('content-type'),
      contentLengthBytes: contentLengthHeader ? Number(contentLengthHeader) : bodyBytes || null,
      compression: {
        enabled: !!finalRes.headers.get('content-encoding'),
        encoding: finalRes.headers.get('content-encoding'),
      },
      headers,
      robots: { url: `${origin}/robots.txt`, status: robotsRes.status, sitemaps, exists: robotsRes.status === 200 },
      sitemap: { url: `${origin}/sitemap.xml`, status: sitemapRes.status, exists: sitemapRes.status === 200 },
      favicon: { url: `${origin}/favicon.ico`, status: faviconRes.status, exists: faviconRes.status === 200 },
      canonical: bodyText ? extract(bodyText, /<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i) : null,
      title: bodyText ? extract(bodyText, /<title[^>]*>([^<]*)<\/title>/i)?.trim() || null : null,
      mixedContent: { detected: mixedSamples.length > 0, samples: mixedSamples },
      error: null,
    };
  });
}
