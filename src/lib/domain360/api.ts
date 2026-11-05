import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { checkRate, clientIpFromHeaders } from './ratelimit';

/**
 * Central API route handler: zod validation, rate limiting,
 * structured JSON envelopes and error normalization.
 */

export const DOMAIN_PARAM = z.string().min(1).max(300);

export class ApiError extends Error {
  code: string;
  status: number;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function jsonOk<T>(data: T): NextResponse {
  return NextResponse.json({ ok: true, data }, { headers: { 'Cache-Control': 'no-store' } });
}

export function jsonError(code: string, message: string, status = 400): NextResponse {
  return NextResponse.json({ ok: false, error: { code, message } }, { status, headers: { 'Cache-Control': 'no-store' } });
}

interface RunOptions<T> {
  req: NextRequest;
  /** route slug, used in the rate-limit key */
  route: string;
  /** requests per minute per client */
  limitPerMinute: number;
  schema: z.ZodType<T>;
  handler: (input: T) => Promise<unknown> | unknown;
}

export async function runApi<T>(opts: RunOptions<T>): Promise<NextResponse> {
  const ip = clientIpFromHeaders(opts.req.headers);
  const verdict = checkRate(`${ip}:${opts.route}`, opts.limitPerMinute);
  if (!verdict.allowed) {
    return jsonError(
      'RATE_LIMITED',
      `Rate limit reached for ${opts.route}. Try again in ${verdict.retryAfterSec}s.`,
      429,
    );
  }
  let params: Record<string, string> = {};
  try {
    const url = new URL(opts.req.url);
    url.searchParams.forEach((v, k) => {
      params[k] = v;
    });
    if (opts.req.method === 'POST') {
      try {
        const body = (await opts.req.json()) as Record<string, unknown>;
        for (const [k, v] of Object.entries(body)) {
          if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
            params[k] = String(v);
          }
        }
      } catch {
        /* empty body is fine */
      }
    }
  } catch {
    return jsonError('BAD_REQUEST', 'Malformed request URL.', 400);
  }
  const parsed = opts.schema.safeParse(params);
  if (!parsed.success) {
    const msg = parsed.error.issues.map((i) => `${i.path.join('.') || 'input'}: ${i.message}`).join('; ');
    return jsonError('INVALID_INPUT', msg || 'Invalid input.', 400);
  }
  try {
    const data = await opts.handler(parsed.data);
    return jsonOk(data);
  } catch (err) {
    if (err instanceof ApiError) {
      return jsonError(err.code, err.message, err.status);
    }
    const e = err as { code?: string; message?: string; name?: string };
    if (e?.name === 'ValidationError' || e?.code === 'INVALID_INPUT') {
      return jsonError('INVALID_INPUT', e.message || 'Invalid input.', 400);
    }
    if (e?.name === 'SsrfError' || e?.code === 'BLOCKED_TARGET') {
      return jsonError('BLOCKED_TARGET', e.message || 'Target blocked for security reasons.', 403);
    }
    // structured log
    console.error(`[domain360:${opts.route}]`, e?.code || e?.name, e?.message);
    return jsonError(
      'INTERNAL_ERROR',
      `Diagnostics failed: ${e?.message || 'unknown error'}. Try again or use a different resolver.`,
      500,
    );
  }
}
