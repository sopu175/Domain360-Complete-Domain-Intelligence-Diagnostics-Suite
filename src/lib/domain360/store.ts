'use client';

import { useEffect } from 'react';
import { create } from 'zustand';
import { API, apiFetch, qs } from './client';
import type { DnsLookupResult, HttpResult, IpResult, NameserverResult, OverviewResult, PropagationResult, SslResult, SubdomainResult, WhoisResult, DnssecResult, EmailResult, SecurityResult } from './types';
import type { PropagationWorldResult } from './impl/propagation-geo';

export type ModuleId =
  | 'overview' | 'dns' | 'propagation' | 'propagationWorld' | 'nameservers' | 'ip' | 'ssl'
  | 'whois' | 'email' | 'http' | 'security' | 'subdomains' | 'dnssec';

export type TabId = ModuleId | 'compare' | 'reports';

export interface ModuleEntry {
  status: 'idle' | 'loading' | 'ok' | 'error';
  data?: unknown;
  error?: string;
  lastChecked?: string;
}

export interface ScanStage {
  key: string;
  label: string;
  status: 'pending' | 'running' | 'done' | 'failed';
}

export type ModuleResults = {
  overview: OverviewResult;
  dns: DnsLookupResult;
  propagation: PropagationResult;
  propagationWorld: PropagationWorldResult;
  nameservers: NameserverResult;
  ip: IpResult;
  ssl: SslResult;
  whois: WhoisResult;
  email: EmailResult;
  http: HttpResult;
  security: SecurityResult;
  subdomains: SubdomainResult;
  dnssec: DnssecResult;
};

const STAGE_DEFS: { key: string; label: string; moduleId?: ModuleId; params?: Record<string, string> }[] = [
  { key: 'validate', label: 'Validating domain' },
  { key: 'dns', label: 'Resolving DNS', moduleId: 'dns', params: { type: 'A' } },
  { key: 'ns', label: 'Checking nameservers', moduleId: 'nameservers' },
  { key: 'whois', label: 'Retrieving registration data', moduleId: 'whois' },
  { key: 'ssl', label: 'Inspecting SSL certificate', moduleId: 'ssl' },
  { key: 'email', label: 'Analyzing email security', moduleId: 'email' },
  { key: 'http', label: 'Checking HTTP configuration', moduleId: 'http' },
  { key: 'score', label: 'Generating domain health report', moduleId: 'overview' },
];

interface Domain360State {
  domain: string | null;
  activeTab: TabId;
  modules: Record<string, ModuleEntry>;
  stages: ScanStage[];
  scanning: boolean;
  recents: string[];
  setDomain: (d: string | null) => void;
  setActiveTab: (t: TabId) => void;
  addRecent: (d: string) => void;
  fetchModule: (id: ModuleId, domain: string, params?: Record<string, string | undefined>, force?: boolean) => Promise<ModuleEntry>;
  runScan: (domain: string) => Promise<void>;
  clearAll: () => void;
}

const moduleKey = (id: string, domain: string, params?: Record<string, string | undefined>): string =>
  `${id}:${domain.toLowerCase()}:${params ? Object.entries(params).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}=${v}`).sort().join('&') : ''}`;

const RECENTS_KEY = 'domain360.recents';

/** Shared in-flight module fetches so parallel callers await the same request. */
const inflightFetches = new Map<string, Promise<ModuleEntry>>();

function loadRecents(): string[] {
  if (typeof window === 'undefined') return [];
  try {
    return JSON.parse(window.localStorage.getItem(RECENTS_KEY) || '[]') as string[];
  } catch {
    return [];
  }
}

function persistRecents(list: string[]): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(RECENTS_KEY, JSON.stringify(list.slice(0, 8)));
  } catch { /* ignore */ }
}

function endpointFor(id: ModuleId, domain: string, params?: Record<string, string | undefined>): string {
  const selectors = params?.selectors;
  const type = params?.type;
  const resolver = params?.resolver;
  const source = params?.source;
  const expected = params?.expected;
  switch (id) {
    case 'dns': return API.dns(domain, type || 'A', resolver);
    case 'propagation': return API.propagation(domain, type || 'A');
    case 'propagationWorld': return `/api/domain360/propagation-world${qs({ domain, type: type || 'A', expected })}`;
    case 'nameservers': return API.nameservers(domain);
    case 'dnssec': return API.dnssec(domain);
    case 'ssl': return API.ssl(domain);
    case 'http': return API.http(domain);
    case 'whois': return API.whois(domain);
    case 'ip': return API.ip(domain);
    case 'email': return API.email(domain, selectors);
    case 'subdomains': return API.subdomains(domain, source || 'all');
    case 'security': return API.security(domain);
    case 'overview': return API.overview(domain);
  }
}

export const useStore = create<Domain360State>((set, get) => ({
  domain: null,
  activeTab: 'overview',
  modules: {},
  stages: [],
  scanning: false,
  recents: [],

  setDomain: (d) => set({ domain: d }),
  setActiveTab: (t) => set({ activeTab: t }),

  addRecent: (d) => {
    const list = [d, ...get().recents.filter((x) => x !== d)].slice(0, 8);
    persistRecents(list);
    set({ recents: list });
  },

  fetchModule: async (id, domain, params, force) => {
    const key = moduleKey(id, domain, params);
    const existing = get().modules[key];
    if (!force && existing && existing.status === 'ok') {
      return existing;
    }
    const inflight = inflightFetches.get(key);
    if (!force && inflight) {
      return inflight;
    }
    const promise = (async (): Promise<ModuleEntry> => {
      set((s) => ({ modules: { ...s.modules, [key]: { status: 'loading' } } }));
      try {
        const data = await apiFetch<unknown>(endpointFor(id, domain, params));
        const entry: ModuleEntry = { status: 'ok', data, lastChecked: new Date().toISOString() };
        set((s) => ({ modules: { ...s.modules, [key]: entry } }));
        return entry;
      } catch (e) {
        const entry: ModuleEntry = { status: 'error', error: (e as Error).message };
        set((s) => ({ modules: { ...s.modules, [key]: entry } }));
        return entry;
      } finally {
        inflightFetches.delete(key);
      }
    })();
    inflightFetches.set(key, promise);
    return promise;
  },

  runScan: async (domain) => {
    const host = domain.trim().toLowerCase();
    set({
      domain: host,
      scanning: true,
      activeTab: 'overview',
      stages: STAGE_DEFS.map((s) => ({ key: s.key, label: s.label, status: 'pending' })),
      modules: get().modules, // keep other domains cached
    });
    get().addRecent(host);

    const stages = STAGE_DEFS;
    set((s) => ({
      stages: s.stages.map((st) => ({ ...st, status: st.key === 'validate' ? 'running' : 'pending' })),
    }));
    // validate client-side
    const valid = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(host);
    await new Promise((r) => setTimeout(r, 350));
    set((s) => ({
      stages: s.stages.map((st) => (st.key === 'validate' ? { ...st, status: valid ? 'done' : 'failed' } : st)),
    }));
    if (!valid) {
      set({ scanning: false });
      return;
    }

    await Promise.all(
      stages
        .filter((st) => st.moduleId)
        .map(async (st) => {
          set((s) => ({
            stages: s.stages.map((x) => (x.key === st.key ? { ...x, status: 'running' } : x)),
          }));
          const entry = await get().fetchModule(st.moduleId!, host, st.params);
          set((s) => ({
            stages: s.stages.map((x) =>
              x.key === st.key ? { ...x, status: entry.status === 'ok' ? 'done' : 'failed' } : x,
            ),
          }));
        }),
    );
    set({ scanning: false });
  },

  clearAll: () => set({ domain: null, activeTab: 'overview', modules: {}, stages: [] }),
}));

/** Lazily fetch and observe one diagnostic module. */
export function useModuleData<T extends keyof ModuleResults>(
  id: T,
  params?: Record<string, string | undefined>,
): {
  data: ModuleResults[T] | undefined;
  error: string | undefined;
  loading: boolean;
  lastChecked: string | undefined;
  refresh: () => void;
  entry: ModuleEntry | undefined;
} {
  const domain = useStore((s) => s.domain);
  const key = moduleKey(id, domain || '', params);
  const entry = useStore((s) => s.modules[key]);
  const fetchModule = useStore((s) => s.fetchModule);

  useEffect(() => {
    if (domain && (!entry || entry.status === 'idle')) {
      void fetchModule(id as ModuleId, domain, params);
    }
  }, [key, domain]);

  const refresh = () => {
    if (domain) void fetchModule(id as ModuleId, domain, params, true);
  };

  return {
    data: (entry?.status === 'ok' ? (entry.data as ModuleResults[T]) : undefined),
    error: entry?.status === 'error' ? entry.error : undefined,
    loading: entry?.status === 'loading' || (!entry && !!domain),
    lastChecked: entry?.lastChecked,
    refresh,
    entry,
  };
}

export function initRecents(): void {
  useStore.setState({ recents: loadRecents() });
}
