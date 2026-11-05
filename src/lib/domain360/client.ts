'use client';

import type { ApiErrorResponse, ApiResponse } from './types';

export class ApiClientError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = 'ApiClientError';
  }
}

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { ...init, cache: 'no-store' });
  } catch (e) {
    throw new ApiClientError('NETWORK', (e as Error).message || 'Network error');
  }
  let json: ApiResponse<T> | ApiErrorResponse | null = null;
  try {
    json = (await res.json()) as ApiResponse<T> | ApiErrorResponse;
  } catch {
    throw new ApiClientError('BAD_RESPONSE', `Server returned invalid data (HTTP ${res.status})`);
  }
  if (!json) throw new ApiClientError('BAD_RESPONSE', `Server returned no data (HTTP ${res.status})`);
  if (!json.ok) throw new ApiClientError(json.error.code, json.error.message);
  return json.data;
}

export const API = {
  dns: (domain: string, type?: string, resolver?: string) =>
    `/api/domain360/dns${qs({ domain, type, resolver })}`,
  propagation: (domain: string, type?: string) => `/api/domain360/propagation${qs({ domain, type })}`,
  nameservers: (domain: string) => `/api/domain360/nameservers${qs({ domain })}`,
  dnssec: (domain: string) => `/api/domain360/dnssec${qs({ domain })}`,
  ssl: (domain: string) => `/api/domain360/ssl${qs({ domain })}`,
  http: (domain: string) => `/api/domain360/http${qs({ domain })}`,
  whois: (domain: string) => `/api/domain360/whois${qs({ domain })}`,
  ip: (domain: string) => `/api/domain360/ip${qs({ domain })}`,
  email: (domain: string, selectors?: string) => `/api/domain360/email${qs({ domain, selectors })}`,
  subdomains: (domain: string, source?: string) => `/api/domain360/subdomains${qs({ domain, source })}`,
  security: (domain: string, authorize?: boolean) => `/api/domain360/security${qs({ domain, authorize: authorize ? '1' : undefined })}`,
  overview: (domain: string) => `/api/domain360/overview${qs({ domain })}`,
  history: () => `/api/domain360/history`,
  historyDelete: (id: string) => `/api/domain360/history${qs({ id })}`,
  saved: () => `/api/domain360/saved`,
  savedAdd: () => `/api/domain360/saved`,
  savedDelete: (id: string) => `/api/domain360/saved${qs({ id })}`,
};
