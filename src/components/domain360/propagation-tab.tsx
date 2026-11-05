'use client';

import { useState } from 'react';
import { Globe2, Info } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  DataTable, ModuleShell, SectionCard, StatusBadge, type TableColumn,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { PropagationResult } from '@/lib/domain360/types';

const TYPES = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME'];

export function PropagationTab() {
  const [type, setType] = useState('A');
  const { data, error, loading, lastChecked, refresh } = useModuleData<'propagation'>('propagation', { type });
  const result = data as PropagationResult | undefined;

  const columns: TableColumn[] = [
    { key: 'status', header: 'Status', className: 'w-32' },
    { key: 'name', header: 'Public resolver' },
    { key: 'ip', header: 'IP', mono: true, className: 'w-32' },
    { key: 'values', header: 'Resolved value(s)', mono: true },
    { key: 'ms', header: 'Time', className: 'w-20 tabular-nums' },
  ];

  const rows = (result?.nodes || []).map((n, i) => ({
    _key: `${i}-${n.ip}`,
    status: <StatusBadge status={n.status} />,
    name: n.name,
    ip: n.ip,
    values: n.values ? n.values.join(', ') : `— (${n.responseCode})`,
    ms: n.responseTimeMs !== null ? `${n.responseTimeMs} ms` : '—',
  }));

  return (
    <ModuleShell
      title="Global DNS Propagation"
      description="Query the same record across independent public resolvers operated by different companies to see what the world currently sees."
      icon={<Globe2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
      loading={loading}
      error={error}
      onRetry={refresh}
      lastChecked={lastChecked}
      onRefresh={refresh}
      rawData={result}
      actions={
        <Select value={type} onValueChange={setType}>
          <SelectTrigger className="h-8 w-[110px] text-xs" aria-label="Record type">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TYPES.map((t) => (
              <SelectItem key={t} value={t}>{t}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      }
    >
      {result ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatBox label="Propagation" value={`${result.propagationScore}%`} />
            <StatBox label="Matched" value={String(result.summary.matched)} tone="text-emerald-600 dark:text-emerald-400" />
            <StatBox label="Divergent" value={String(result.summary.divergent)} tone="text-amber-600 dark:text-amber-400" />
            <StatBox label="Failed" value={String(result.summary.failed)} tone="text-red-500" />
          </div>

          <div className="flex items-start gap-2 rounded-lg border bg-muted/30 px-3 py-2.5 text-xs leading-relaxed text-muted-foreground">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <p><span className="font-medium text-foreground">Honest scope note:</span> {result.note}</p>
          </div>

          <SectionCard
            title={`${result.recordType} answers across ${result.summary.total} resolvers`}
            description={result.expectedSource ? `Reference answer from ${result.expectedSource}: ${result.expected?.join(', ')}` : 'No reference answer available'}
          >
            <DataTable columns={columns} rows={rows} />
          </SectionCard>
        </div>
      ) : null}
    </ModuleShell>
  );
}

function StatBox({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-xl border bg-card px-3.5 py-3">
      <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={`mt-1 text-xl font-bold tabular-nums ${tone || ''}`}>{value}</p>
    </div>
  );
}
