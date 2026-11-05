'use client';

import { KeyRound } from 'lucide-react';
import {
  CopyButton, DataTable, FindingList, InfoGrid, ModuleShell, SectionCard,
  StatusBadge, type TableColumn,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { DnssecResult } from '@/lib/domain360/types';

export function DnssecTab() {
  const { data, error, loading, lastChecked, refresh } = useModuleData<'dnssec'>('dnssec');
  const result = data as DnssecResult | undefined;

  const keyColumns: TableColumn[] = [
    { key: 'type', header: 'Record', className: 'w-28 font-semibold' },
    { key: 'value', header: 'Value', mono: true },
    { key: 'copy', header: '', className: 'w-10' },
  ];

  return (
    <ModuleShell
      title="DNSSEC Analyzer"
      description="Structural DNSSEC analysis: DS/DNSKEY records, real KSK↔DS digest verification, signature validity, and a validating resolver's AD flag."
      icon={<KeyRound className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
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
              { label: 'Status', value: <StatusBadge status={result.enabled === false ? 'not_configured' : result.validatedByResolver === true ? 'healthy' : result.validatedByResolver === false ? 'critical' : 'warning'} /> },
              { label: 'DNSSEC enabled', value: result.enabled === null ? 'Unknown' : result.enabled ? 'Yes' : 'No' },
              { label: 'Validated by resolver (AD)', value: result.validatedByResolver === null ? '—' : result.validatedByResolver ? 'Yes (Google DoH)' : 'No' },
              { label: 'RRSIG', value: result.rrsig.present ? `alg ${result.rrsig.algorithm} (${result.rrsig.algorithmName})` : 'None' },
              { label: 'Signature expires', value: result.rrsig.expiration ? new Date(result.rrsig.expiration).toLocaleString() : '—' },
              { label: 'Signature expired', value: result.rrsig.expired === null ? '—' : result.rrsig.expired ? 'YES' : 'No' },
            ]}
            cols={3}
          />

          <SectionCard title="Chain of trust validation" description="Step-by-step verification from the parent zone down to the zone apex.">
            <ol className="space-y-2">
              {result.chain.map((step, i) => (
                <li key={i} className="flex items-start gap-3 rounded-lg border px-3 py-2.5">
                  <StatusBadge status={step.status === 'pass' ? 'healthy' : step.status === 'fail' ? 'critical' : 'unknown'} />
                  <div>
                    <p className="text-sm font-medium">{step.step}</p>
                    <p className="text-[12.5px] leading-relaxed text-muted-foreground">{step.detail}</p>
                  </div>
                </li>
              ))}
            </ol>
          </SectionCard>

          {result.algorithmsInfo.length ? (
            <SectionCard title="Algorithms in use">
              <ul className="list-inside list-disc space-y-1 text-sm text-muted-foreground">
                {result.algorithmsInfo.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </SectionCard>
          ) : null}

          {result.ds.length || result.dnskey.length ? (
            <SectionCard title="DS & DNSKEY records" description="Full record data — copy for debugging with dig/online validators.">
              <DataTable
                columns={keyColumns}
                rows={[
                  ...result.ds.map((r, i) => ({ _key: `ds-${i}`, type: 'DS', value: r.value, copy: <CopyButton value={r.value} /> })),
                  ...result.dnskey.map((r, i) => ({ _key: `key-${i}`, type: r.value.startsWith('257') ? 'DNSKEY (KSK)' : 'DNSKEY (ZSK)', value: r.value.length > 140 ? `${r.value.slice(0, 140)}…` : r.value, copy: <CopyButton value={r.value} /> })),
                ]}
              />
            </SectionCard>
          ) : null}

          <SectionCard title="Issues">
            <FindingList findings={result.issues} />
          </SectionCard>
        </div>
      ) : null}
    </ModuleShell>
  );
}
