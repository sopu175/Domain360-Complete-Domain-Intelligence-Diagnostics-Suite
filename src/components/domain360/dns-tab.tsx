'use client';

import { useState } from 'react';
import { Database } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  CopyButton, DataTable, InfoGrid, ModuleShell, SectionCard, type TableColumn,
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
    { key: 'type', header: 'Type', className: 'w-24 font-semibold' },
    { key: 'name', header: 'Name', mono: true },
    { key: 'value', header: 'Value / Answer', mono: true },
    { key: 'ttl', header: 'TTL', className: 'w-20 tabular-nums' },
    { key: 'prio', header: 'Priority', className: 'w-20 tabular-nums' },
    { key: 'copy', header: '', className: 'w-10' },
  ];

  const rows = (result?.records || []).map((r, i) => ({
    _key: `${i}-${r.value}`,
    type: r.type,
    name: r.name,
    value: r.value,
    ttl: r.ttl ?? '—',
    prio: r.priority ?? '—',
    copy: <CopyButton value={r.value} />,
  }));

  const authRows = (result?.authority || []).map((r, i) => ({
    _key: `auth-${i}-${r.value}`,
    type: r.type,
    name: r.name,
    value: r.value,
    ttl: r.ttl ?? '—',
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
