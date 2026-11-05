'use client';

import { FileSearch } from 'lucide-react';
import {
  CopyButton, InfoGrid, ModuleShell, SectionCard,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { WhoisResult } from '@/lib/domain360/types';

function fmtDate(iso: string | null): string {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
}

export function WhoisTab() {
  const { data, error, loading, lastChecked, refresh } = useModuleData<'whois'>('whois');
  const result = data as WhoisResult | undefined;

  return (
    <ModuleShell
      title="WHOIS / RDAP Registration"
      description="Modern RDAP lookup (registry-grade JSON) with raw WHOIS port-43 fallback. Redacted/privacy-protected registrant data is respected and never de-obfuscated."
      icon={<FileSearch className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
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
            cols={3}
            items={[
              { label: 'Registrar', value: result.registrar || '—' },
              { label: 'Registered on', value: fmtDate(result.creationDate) },
              { label: 'Expires on', value: fmtDate(result.expirationDate) },
              { label: 'Last updated', value: fmtDate(result.updatedDate) },
              { label: 'Domain age', value: result.ageDays !== null ? `${Math.floor(result.ageDays / 365.25)} years` : '—' },
              { label: 'Days to expiry', value: result.daysToExpiry !== null ? String(result.daysToExpiry) : '—' },
              { label: 'Transfer lock', value: result.transferLocked === null ? '—' : result.transferLocked ? 'clientTransferProhibited' : 'Not locked' },
              { label: 'DNSSEC (registry)', value: result.dnssec === null ? '—' : result.dnssec ? 'Signed' : 'Unsigned' },
              { label: 'Data source', value: result.source, mono: true },
              { label: 'Abuse contact', value: result.abuseContact || '—', mono: true, copy: result.abuseContact || undefined },
              { label: 'Registrar URL', value: result.registrarUrl || '—', mono: true },
              { label: 'Registry', value: result.registry || '—', mono: true },
              { label: 'Registrant organization', value: result.registrant.privacyProtected ? 'Privacy protected' : result.registrant.organization || '—' },
              { label: 'Registrant country', value: result.registrant.privacyProtected ? 'Privacy protected' : result.registrant.country || '—' },
              { label: 'WHOIS server', value: result.whoisServerQueried || '—', mono: true },
            ]}
          />

          <SectionCard title="Domain status codes" description="EPP status codes from the registry.">
            {result.statusCodes.length ? (
              <div className="flex flex-wrap gap-2">
                {result.statusCodes.map((s) => (
                  <span key={s} className="rounded-md border bg-muted/40 px-2 py-1 font-mono text-[11.5px]">
                    {s}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">None published.</p>
            )}
          </SectionCard>

          {result.nameServers.length ? (
            <SectionCard title="Name servers (registry)">
              <ul className="space-y-1">
                {result.nameServers.map((ns) => (
                  <li key={ns} className="flex items-center gap-2 font-mono text-[13px]">
                    {ns}
                    <CopyButton value={ns} />
                  </li>
                ))}
              </ul>
            </SectionCard>
          ) : null}
        </div>
      ) : null}
    </ModuleShell>
  );
}
