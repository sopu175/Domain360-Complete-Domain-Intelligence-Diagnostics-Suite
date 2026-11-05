'use client';

import { useState } from 'react';
import { Database } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import {
  CopyButton, DataTable, DnsRecordBadge, InfoGrid, IpBadge, ModuleShell, SectionCard, type TableColumn,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { DnsLookupResult } from '@/lib/domain360/types';

const RECORD_TYPES = [
  'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'PTR', 'CAA', 'SRV',
  'NAPTR', 'DS', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'TLSA',
  'SSHFP', 'SVCB', 'HTTPS', 'LOC', 'CERT', 'URI', 'DNAME', 'ANY',
];

const RESOLVERS = [
  { value: 'system', label: 'System / default' },
  { value: 'google', label: 'Google (8.8.8.8)' },
  { value: 'cloudflare', label: 'Cloudflare (1.1.1.1)' },
  { value: 'quad9', label: 'Quad9 (9.9.9.9)' },
  { value: 'opendns', label: 'OpenDNS' },
  { value: 'adguard', label: 'AdGuard' },
];

export function DnsTab() {
  const [type, setType] = useState('A');
  const [resolver, setResolver] = useState('system');
  const { data, error, loading, lastChecked, refresh } = useModuleData<'dns'>('dns', { type, resolver });
  const result = data as DnsLookupResult | undefined;

  const columns: TableColumn[] = [
    { key: 'type', header: 'Type', className: 'w-28' },
    { key: 'name', header: 'Name', mono: true },
    { key: 'value', header: 'Value / Answer' },
    { key: 'ttl', header: 'TTL', className: 'w-24 tabular-nums' },
    { key: 'prio', header: 'Priority', className: 'w-24 tabular-nums' },
    { key: 'copy', header: '', className: 'w-10' },
  ];

  const isIpValue = (val: string, rType: string) => {
    if (rType === 'A' || rType === 'AAAA') return true;
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val) || (val.includes(':') && !val.includes(' '));
  };

  const rows = (result?.records || []).map((r, i) => ({
    _key: `${i}-${r.value}`,
    type: <DnsRecordBadge type={r.type} />,
    name: <span className="font-mono text-[12px]">{r.name}</span>,
    value: isIpValue(r.value, r.type) ? (
      <IpBadge ip={r.value} version={r.type === 'AAAA' ? 6 : 4} />
    ) : (
      <span className="font-mono text-[12.5px] break-all">{r.value}</span>
    ),
    ttl:
      r.ttl !== null ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-help rounded bg-muted/70 px-1.5 py-0.5 font-mono text-[11px] tabular-nums underline decoration-dotted decoration-muted-foreground/50 underline-offset-2">
              {r.ttl}s
            </span>
          </TooltipTrigger>
          <TooltipContent side="top">
            <p className="font-semibold text-xs">Time To Live (TTL)</p>
            <p className="text-[11px] text-muted-foreground">
              Cached for {r.ttl} seconds before resolvers re-query authoritative nameservers.
            </p>
          </TooltipContent>
        </Tooltip>
      ) : (
        '—'
      ),
    prio:
      r.priority !== undefined && r.priority !== null ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-help rounded bg-muted/70 px-1.5 py-0.5 font-mono text-[11px] font-semibold tabular-nums text-foreground underline decoration-dotted decoration-muted-foreground/50 underline-offset-2">
              {r.priority}
            </span>
          </TooltipTrigger>
          <TooltipContent side="top">
            <p className="font-semibold text-xs">MX Delivery Priority</p>
            <p className="text-[11px] text-muted-foreground">
              Priority level {r.priority}. Lower numeric values indicate higher delivery preference.
            </p>
          </TooltipContent>
        </Tooltip>
      ) : (
        '—'
      ),
    copy: <CopyButton value={r.value} />,
  }));

  const authRows = (result?.authority || []).map((r, i) => ({
    _key: `auth-${i}-${r.value}`,
    type: <DnsRecordBadge type={r.type} />,
    name: <span className="font-mono text-[12px]">{r.name}</span>,
    value: isIpValue(r.value, r.type) ? (
      <IpBadge ip={r.value} version={r.type === 'AAAA' ? 6 : 4} />
    ) : (
      <span className="font-mono text-[12.5px] break-all">{r.value}</span>
    ),
    ttl:
      r.ttl !== null ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-help rounded bg-muted/70 px-1.5 py-0.5 font-mono text-[11px] tabular-nums underline decoration-dotted decoration-muted-foreground/50 underline-offset-2">
              {r.ttl}s
            </span>
          </TooltipTrigger>
          <TooltipContent side="top">
            <p className="font-semibold text-xs">Time To Live (TTL)</p>
            <p className="text-[11px] text-muted-foreground">
              Cached for {r.ttl} seconds.
            </p>
          </TooltipContent>
        </Tooltip>
      ) : (
        '—'
      ),
    prio: '—',
    copy: <CopyButton value={r.value} />,
  }));

  return (
    <ModuleShell
      title="DNS Lookup"
      description="Query any record type against your choice of resolver — raw DNS wire queries with DNSSEC DO bit, plus automatic DNS-over-HTTPS fallback."
      icon={<Database className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
      loading={loading}
      error={error}
      onRetry={refresh}
      lastChecked={lastChecked}
      onRefresh={refresh}
      rawData={result}
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <Select value={type} onValueChange={setType}>
            <SelectTrigger className="h-8 w-[120px] text-xs" aria-label="Record type">
              <SelectValue placeholder="Type" />
            </SelectTrigger>
            <SelectContent className="max-h-72">
              {RECORD_TYPES.map((t) => (
                <SelectItem key={t} value={t}>{t}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={resolver} onValueChange={setResolver}>
            <SelectTrigger className="h-8 w-[170px] text-xs" aria-label="Resolver">
              <SelectValue placeholder="Resolver" />
            </SelectTrigger>
            <SelectContent>
              {RESOLVERS.map((r) => (
                <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      }
    >
      {result ? (
        <div className="space-y-4">
          <InfoGrid
            items={[
              { label: 'Response code', value: <span className={result.responseCode === 'NOERROR' ? 'font-semibold text-emerald-600 dark:text-emerald-400' : 'font-semibold text-red-500'}>{result.responseCode}</span> },
              { label: 'Response time', value: `${result.responseTimeMs} ms` },
              { label: 'Resolver', value: result.resolverLabel, mono: true },
              { label: 'DNSSEC (AD flag)', value: result.dnssecAd === null ? '—' : result.dnssecAd ? 'Validated' : 'Not validated' },
              { label: 'Records', value: result.records.length },
              { label: 'Source', value: result.source === 'wire' ? 'Raw UDP (port 53)' : 'DNS-over-HTTPS' },
            ]}
            cols={3}
          />
          {result.note ? (
            <p className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
              {result.note}
            </p>
          ) : null}
          <SectionCard title={`${type} records`} description={`Answer section for ${result.domain}`}>
            <DataTable columns={columns} rows={rows} empty={result.responseCode === 'NOERROR' ? `No ${type} records exist for this name` : `No records — response was ${result.responseCode}`} />
          </SectionCard>
          {authRows.length ? (
            <SectionCard title="Authority section" description="Additional records returned by the resolver">
              <DataTable columns={columns} rows={authRows} />
            </SectionCard>
          ) : null}
        </div>
      ) : null}
    </ModuleShell>
  );
}
