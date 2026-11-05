'use client';

import { useState } from 'react';
import { GitBranch } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  DataTable, ModuleShell, SectionCard, StatusBadge, type TableColumn,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { SubdomainResult } from '@/lib/domain360/types';

export function SubdomainsTab() {
  const [source, setSource] = useState('all');
  const { data, error, loading, lastChecked, refresh } = useModuleData<'subdomains'>('subdomains', { source });
  const result = data as SubdomainResult | undefined;

  const columns: TableColumn[] = [
    { key: 'host', header: 'Subdomain', mono: true },
    { key: 'ips', header: 'Resolved IP(s)', mono: true },
    { key: 'verified', header: 'Verification', className: 'w-32' },
    { key: 'http', header: 'HTTP', className: 'w-20 tabular-nums' },
    { key: 'ssl', header: 'TLS', className: 'w-20' },
    { key: 'source', header: 'Source', className: 'w-32' },
    { key: 'seen', header: 'Last seen', className: 'w-32' },
  ];

  return (
    <ModuleShell
      title="Subdomain Discovery"
      description="Passive discovery: Certificate Transparency logs (historical certificates) + DNS resolution of a built-in common-name wordlist. No active scanning of third-party infrastructure."
      icon={<GitBranch className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
      loading={loading}
      error={error}
      onRetry={refresh}
      lastChecked={lastChecked}
      onRefresh={refresh}
      rawData={result}
      actions={
        <Select value={source} onValueChange={setSource}>
          <SelectTrigger className="h-8 w-[180px] text-xs" aria-label="Discovery source">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All sources</SelectItem>
            <SelectItem value="ct">CT logs only</SelectItem>
            <SelectItem value="dns">DNS wordlist only</SelectItem>
          </SelectContent>
        </Select>
      }
    >
      {result ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Total found" value={String(result.counts.total)} />
            <Stat label="Live (resolved now)" value={String(result.counts.live)} tone="text-emerald-600 dark:text-emerald-400" />
            <Stat label="Historical (CT)" value={String(result.counts.historical)} tone="text-amber-600 dark:text-amber-400" />
            <Stat label="CT log service" value={result.ctAvailable ? 'Available' : 'Unavailable'} />
          </div>

          {result.ctError ? (
            <p className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
              Certificate Transparency source: {result.ctError}. Results shown are from the remaining sources.
            </p>
          ) : null}

          <p className="rounded-lg border bg-muted/30 px-3 py-2 text-[11.5px] leading-relaxed text-muted-foreground">
            {result.note}
          </p>

          <SectionCard
            title={`Discovered subdomains (${result.entries.length}${result.truncated ? '+, truncated' : ''})`}
            description="live = resolved via DNS right now · historical = seen in CT logs, may no longer exist"
          >
            <DataTable
              columns={columns}
              rows={result.entries.map((e) => ({
                _key: e.subdomain,
                host: e.subdomain,
                ips: e.ips.join(', ') || '—',
                verified: <StatusBadge status={e.verified === 'live' ? 'healthy' : 'not_configured'} />,
                http: e.httpStatus ?? '—',
                ssl: e.sslValid === null ? '—' : e.sslValid ? 'Valid' : 'Invalid',
                source: e.source.join(' + '),
                seen: e.lastSeen ? new Date(e.lastSeen).toLocaleDateString() : '—',
              }))}
              empty="No subdomains discovered from the selected sources"
            />
          </SectionCard>
        </div>
      ) : null}
    </ModuleShell>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-xl border bg-card px-3.5 py-3">
      <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={`mt-1 text-xl font-bold tabular-nums ${tone || ''}`}>{value}</p>
    </div>
  );
}
