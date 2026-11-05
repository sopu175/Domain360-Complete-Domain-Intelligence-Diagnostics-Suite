'use client';

import { useEffect, useMemo, useState } from 'react';
import dynamic from 'next/dynamic';
import { AlertCircle, CheckCircle2, Globe2, Info, Loader2, RefreshCw, Search, XCircle, XCircle as Failed } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import {
  DataTable, DNS_RECORD_META, EmptyState, ModuleShell, StatusBadge, type TableColumn,
} from '@/components/domain360/shared-ui';
import { useStore, useModuleData, type TabId } from '@/lib/domain360/store';
import type { GeoNode, NetworkNode, PropagationWorldResult } from '@/lib/domain360/impl/propagation-geo';
import type { MapPin } from '@/components/domain360/world-map';
import { cn } from '@/lib/utils';

const WorldMap = dynamic(() => import('@/components/domain360/world-map'), {
  ssr: false,
  loading: () => <div className="h-[340px] w-full animate-pulse rounded-lg bg-muted sm:h-[400px]" />,
});

const TYPES = ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'PTR', 'SOA', 'TXT'];
const REFRESH_OPTIONS = [
  { value: 'off', label: 'Auto refresh: Off' },
  { value: '30000', label: 'Every 30 seconds' },
  { value: '60000', label: 'Every 1 minute' },
  { value: '300000', label: 'Every 5 minutes' },
];

export function flagEmoji(cc: string | undefined | null): string {
  if (!cc || cc.length !== 2 || !/^[a-z]{2}$/i.test(cc)) return '🌐';
  return cc.toUpperCase().replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)));
}

export function PropagationTab() {
  const domain = useStore((s) => s.domain);
  const setDomain = useStore((s) => s.setDomain);

  const [input, setInput] = useState(domain || '');
  const [type, setType] = useState('A');
  const [expectedInput, setExpectedInput] = useState('');
  const [expected, setExpected] = useState<string | undefined>(undefined);
  const [refreshMs, setRefreshMs] = useState('off');

  const { data, error, loading, lastChecked, refresh } = useModuleData<'propagationWorld'>(
    'propagationWorld',
    { type, expected },
  );
  const result = data as PropagationWorldResult | undefined;

  // sync input when the global domain changes (adjust-during-render pattern)
  const [syncedDomain, setSyncedDomain] = useState(domain);
  if (domain !== syncedDomain) {
    setSyncedDomain(domain);
    if (domain) setInput(domain);
  }

  // auto refresh loop
  useEffect(() => {
    if (refreshMs === 'off' || !domain) return;
    const id = setInterval(() => refresh(), parseInt(refreshMs, 10));
    return () => clearInterval(id);
  }, [refreshMs, type, expected, domain]);

  const submit = (raw?: string, t?: string) => {
    const host = (raw ?? input).trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    const newType = t ?? type;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(host)) return;
    setDomain(host);
    setType(newType);
    setExpected(expectedInput.trim() || undefined);
  };

  const geoPins: MapPin[] = useMemo(() => {
    if (!result) return [];
    return result.geoNodes
      .filter((n) => n.lat !== null && n.lon !== null)
      .map((n) => ({
        id: `geo-${n.node}`,
        lat: n.lat!,
        lon: n.lon!,
        kind: 'geo' as const,
        status: n.status,
        title: `${flagEmoji(n.countryCode)} ${n.city}, ${n.country}`,
        subtitle: `Measurement node · ${n.node}`,
        values: n.values?.join(', ') || null,
      }));
  }, [result]);

  const netPins: MapPin[] = useMemo(() => {
    if (!result) return [];
    return result.networks.map((n) => ({
      id: `net-${n.ip}`,
      lat: n.lat,
      lon: n.lon,
      kind: 'network' as const,
      status: n.status,
      title: `${flagEmoji(n.countryCode)} ${n.name}`,
      subtitle: `Anycast network · HQ: ${n.city}, ${n.country}`,
      values: n.values?.join(', ') || null,
    }));
  }, [result]);

  return (
    <div className="space-y-4">
      {/* ---------- dnschecker-style search panel ---------- */}
      <div className="rounded-xl border bg-card p-4 shadow-xs">
        <div className="flex flex-col gap-2.5 lg:flex-row lg:items-center">
          <div className="flex flex-1 flex-col gap-2.5 sm:flex-row">
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && submit()}
              placeholder="Enter domain or host — e.g. pashagroup.com.bd"
              className="h-11 flex-1 font-mono text-sm"
              aria-label="Domain for propagation check"
            />
            <Input
              value={expectedInput}
              onChange={(e) => setExpectedInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && submit()}
              placeholder="Expected value (optional)"
              className="h-11 w-full font-mono text-sm sm:w-64"
              aria-label="Expected IP or value"
            />
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={() => submit()}
              disabled={loading}
              className="h-11 shrink-0 bg-emerald-600 px-6 font-semibold text-white shadow-xs hover:bg-emerald-700"
            >
              {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
              Search
            </Button>
            <select
              value={refreshMs}
              onChange={(e) => setRefreshMs(e.target.value)}
              aria-label="Auto refresh interval"
              className="h-11 shrink-0 rounded-lg border border-input bg-background px-3 text-xs font-medium text-foreground shadow-xs transition-colors hover:bg-muted/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
            >
              {REFRESH_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
        </div>

        {/* record type pills with tooltips & colored badges */}
        <div className="mt-3 flex flex-wrap gap-1.5" role="tablist" aria-label="Record type">
          {TYPES.map((t) => {
            const meta = DNS_RECORD_META[t];
            return (
              <Tooltip key={t}>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    onClick={() => {
                      setType(t);
                      submit(undefined, t);
                    }}
                    className={cn(
                      'rounded-lg px-3.5 py-1.5 font-mono text-[13px] font-semibold transition-all select-none cursor-pointer',
                      type === t
                        ? 'bg-emerald-600 text-white shadow-xs'
                        : 'border border-border/80 bg-background text-muted-foreground hover:border-emerald-500/50 hover:bg-muted/50 hover:text-foreground',
                    )}
                    aria-pressed={type === t}
                  >
                    {t}
                  </button>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs text-left">
                  <p className="font-semibold text-xs">{meta?.label || `${t} Record`}</p>
                  <p className="mt-0.5 text-[11px] text-muted-foreground leading-normal">
                    {meta?.description || `Query DNS propagation for ${t} records.`}
                  </p>
                </TooltipContent>
              </Tooltip>
            );
          })}
        </div>

        {result ? (
          <div className="mt-3.5 flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t pt-3 text-xs text-muted-foreground">
            <span>
              Checking <span className="font-mono font-semibold text-foreground">{result.domain}</span> · type <span className="font-semibold text-foreground">{result.recordType}</span>
            </span>
            <span className="flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-0.5 font-medium text-emerald-700 dark:text-emerald-300">
              <Globe2 className="h-3.5 w-3.5 text-emerald-500" />
              {result.summary.geoTotal > 0
                ? `${result.summary.geoResolved}/${result.summary.geoTotal} locations resolved`
                : `${result.summary.netMatched}/${result.summary.netTotal} networks answered`}
            </span>
            <span>
              Propagation score:{' '}
              <span className={cn('font-bold', result.propagationScore >= 80 ? 'text-emerald-600 dark:text-emerald-400' : result.propagationScore >= 50 ? 'text-amber-600 dark:text-amber-400' : 'text-red-500')}>
                {result.propagationScore}%
              </span>
            </span>
            {result.expectedSource ? <span className="truncate text-muted-foreground">Reference: {result.expectedSource}</span> : null}
          </div>
        ) : null}
      </div>

      {/* ---------- body ---------- */}
      <ModuleShell
        title="Global DNS Propagation"
        description="What do servers around the world resolve right now? Real geographic measurement nodes plus independent DNS networks."
        icon={<Globe2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
        loading={loading && !result}
        error={error}
        onRetry={refresh}
        lastChecked={lastChecked}
        onRefresh={refresh}
        rawData={result}
      >
        {result ? (
          <div className="space-y-4">
            {/* map with isolated stacking context */}
            <div className="relative isolate z-0 overflow-hidden rounded-xl border bg-muted/20">
              <WorldMap pins={[...geoPins, ...netPins]} />
              <div className="pointer-events-none absolute bottom-3 left-3 z-10 flex flex-wrap gap-2.5 rounded-lg border border-border/80 bg-background/90 px-3 py-1.5 text-[11px] font-medium shadow-xs backdrop-blur">
                <LegendDot color="#10b981" label="Location resolved" />
                <LegendDot color="#ef4444" label="Failed / no answer" />
                <LegendDot color="#f59e0b" label="Divergent / timeout" />
                <LegendDot color="#0d9488" label="DNS network (dashed)" />
              </div>
            </div>

            {/* notes */}
            {result.notes.map((n, i) => (
              <p key={i} className="flex items-start gap-2 rounded-lg border bg-muted/30 px-3.5 py-2.5 text-[12px] leading-relaxed text-muted-foreground">
                <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                {n}
              </p>
            ))}

            {/* geo section */}
            {result.geoNodes.length > 0 ? (
              <Section
                title={`Locations worldwide — ${result.recordType} records (${result.summary.geoResolved}/${result.summary.geoTotal} resolved)`}
                description={
                  result.geoProvider === 'check-host.net'
                    ? "Live measurements from servers in different countries, powered by check-host.net's public API."
                    : 'Live measurements from regional DNS vantage points across countries worldwide.'
                }
              >
                <GeoGrid nodes={result.geoNodes} />
              </Section>
            ) : result.geoNote ? (
              <p className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2.5 text-[12.5px] text-amber-700 dark:text-amber-400">
                <Info className="mt-0.5 h-4 w-4 shrink-0" />
                {result.geoNote}
              </p>
            ) : null}

            {/* networks section */}
            <Section
              title={`Independent DNS networks — ${result.recordType} records (${result.summary.netMatched}/${result.summary.netTotal} answered)`}
              description="Public resolvers run by different operators. Flags mark the operator's headquarters; anycast networks answer from the nearest point of presence."
            >
              <NetworkGrid networks={result.networks} />
            </Section>
          </div>
        ) : null}
      </ModuleShell>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}

function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border bg-card shadow-xs">
      <div className="border-b px-4 py-3">
        <h3 className="text-sm font-semibold">{title}</h3>
        {description ? <p className="mt-0.5 text-[11.5px] text-muted-foreground">{description}</p> : null}
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function StatusCell({ status }: { status: string }) {
  if (status === 'resolved' || status === 'healthy') {
    return <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-500" aria-label="Resolved" />;
  }
  if (status === 'warning' || status === 'timeout' || status === 'unknown') {
    return <AlertCircle className="h-5 w-5 shrink-0 text-amber-500" aria-label="Divergent or timed out" />;
  }
  if (status === 'empty' || status === 'not_configured') {
    return <span className="rounded-full border border-muted-foreground/30 bg-muted px-2 py-0.5 text-[10px] font-semibold text-muted-foreground">EMPTY</span>;
  }
  return <XCircle className="h-5 w-5 shrink-0 text-red-500" aria-label="Failed" />;
}

function GeoGrid({ nodes }: { nodes: GeoNode[] }) {
  return (
    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
      {nodes.map((n) => (
        <div
          key={n.node}
          className="group flex items-center justify-between gap-2.5 rounded-xl border border-border/70 bg-card p-3 shadow-xs transition-all hover:border-emerald-500/40 hover:bg-muted/30"
        >
          <div className="min-w-0 flex-1">
            <p className="flex items-center gap-1.5 truncate text-[13px] font-medium text-foreground">
              <span className="text-base leading-none">{flagEmoji(n.countryCode)}</span>
              <span className="truncate">{n.city}, {n.country}</span>
            </p>
            <div className="mt-1 flex flex-wrap items-center gap-1">
              {n.values && n.values.length > 0 ? (
                n.values.map((val) => (
                  <span
                    key={val}
                    className="inline-block rounded-md border border-border/80 bg-muted/70 px-1.5 py-0.5 font-mono text-[11.5px] font-medium text-foreground"
                    title={val}
                  >
                    {val}
                  </span>
                ))
              ) : (
                <span className="font-mono text-[11.5px] text-muted-foreground">
                  {n.status === 'timeout' ? 'Timed out' : n.status === 'empty' ? 'No record' : 'Failed'}
                </span>
              )}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {n.matchesExpected === false ? (
              <span className="rounded bg-red-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-red-600 dark:text-red-400">Mismatch</span>
            ) : null}
            {n.ttl ? <span className="rounded bg-muted/60 px-1.5 py-0.5 text-[10px] tabular-nums text-muted-foreground">TTL {n.ttl}</span> : null}
            <StatusCell status={n.status} />
          </div>
        </div>
      ))}
    </div>
  );
}

function NetworkGrid({ networks }: { networks: NetworkNode[] }) {
  return (
    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
      {networks.map((n) => (
        <div
          key={n.ip}
          className="group flex items-center justify-between gap-2.5 rounded-xl border border-border/70 bg-card p-3 shadow-xs transition-all hover:border-emerald-500/40 hover:bg-muted/30"
        >
          <div className="min-w-0 flex-1">
            <p className="flex items-center gap-1.5 truncate text-[13px] font-medium text-foreground">
              <span className="text-base leading-none">{flagEmoji(n.countryCode)}</span>
              <span className="truncate">{n.name}</span>
            </p>
            <div className="mt-1 flex flex-wrap items-center gap-1">
              {n.values && n.values.length > 0 ? (
                n.values.map((val) => (
                  <span
                    key={val}
                    className="inline-block rounded-md border border-border/80 bg-muted/70 px-1.5 py-0.5 font-mono text-[11.5px] font-medium text-foreground"
                    title={val}
                  >
                    {val}
                  </span>
                ))
              ) : (
                <span className="font-mono text-[11.5px] text-muted-foreground">
                  {n.status === 'not_configured'
                    ? `No record (${n.responseCode})`
                    : `${n.responseCode}${n.status === 'critical' ? ' — domain does not exist here' : ''}`}
                </span>
              )}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {n.responseTimeMs !== null ? <span className="rounded bg-muted/60 px-1.5 py-0.5 text-[10px] tabular-nums text-muted-foreground">{n.responseTimeMs} ms</span> : null}
            <StatusCell status={n.status} />
          </div>
        </div>
      ))}
    </div>
  );
}
