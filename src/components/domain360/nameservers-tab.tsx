'use client';

import { Server } from 'lucide-react';
import {
  DataTable, FindingList, InfoGrid, ModuleShell, SectionCard, StatusBadge, type TableColumn,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { NameserverResult } from '@/lib/domain360/types';

export function NameserversTab() {
  const { data, error, loading, lastChecked, refresh } = useModuleData<'nameservers'>('nameservers');
  const result = data as NameserverResult | undefined;

  const columns: TableColumn[] = [
    { key: 'ns', header: 'Nameserver', mono: true },
    { key: 'ips', header: 'IP addresses', mono: true },
    { key: 'responded', header: 'Responds', className: 'w-24' },
    { key: 'ms', header: 'Time', className: 'w-20 tabular-nums' },
    { key: 'serial', header: 'SOA serial', className: 'w-32 tabular-nums' },
    { key: 'lame', header: 'Health', className: 'w-28' },
  ];

  const rows = (result?.authoritative || []).map((a) => ({
    _key: a.nameserver,
    ns: a.nameserver,
    ips: a.ips.length ? a.ips.join(', ') : '—',
    responded: a.responded ? 'Yes' : 'No',
    ms: a.responseTimeMs !== null ? `${a.responseTimeMs} ms` : '—',
    serial: a.soaSerial ?? '—',
    lame: <StatusBadge status={a.isLame ? 'critical' : 'healthy'} />,
  }));

  return (
    <ModuleShell
      title="Nameserver & Delegation Analysis"
      description="Inspect parent-zone delegation, glue records, per-server SOA serials and reachability of every authoritative nameserver."
      icon={<Server className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
      loading={loading}
      error={error}
      onRetry={refresh}
      lastChecked={lastChecked}
      onRefresh={refresh}
      rawData={result}
    >
      {result ? (
        <div className="space-y-4">
          <InfoGrid
            items={[
              { label: 'Parent zone', value: result.delegation.parentZone || '—', mono: true },
              { label: 'Parent name servers', value: result.delegation.parentNsUsed.join(', ') || '—', mono: true },
              { label: 'Delegation (NS at parent)', value: result.delegation.parentDelegationNs.join(', ') || 'Not directly verified', mono: true },
              { label: 'Glue A records', value: result.delegation.glueA.length ? result.delegation.glueA.join(', ') : 'None (or out-of-bailiwick)', mono: true },
              { label: 'NS set consistency', value: <StatusBadge status={result.consistency.setsMatch ? 'healthy' : 'warning'} />, },
              { label: 'SOA serial consistency', value: <StatusBadge status={result.consistency.serialsMatch ? 'healthy' : 'warning'} /> },
            ]}
            cols={2}
          />

          <SectionCard title="Authoritative servers" description="Each nameserver probed directly (SOA + NS queries, recursion disabled)">
            <DataTable columns={columns} rows={rows} empty="No nameservers discovered" />
          </SectionCard>

          <SectionCard title="Delegation findings">
            <FindingList findings={result.issues} />
          </SectionCard>
        </div>
      ) : null}
    </ModuleShell>
  );
}
