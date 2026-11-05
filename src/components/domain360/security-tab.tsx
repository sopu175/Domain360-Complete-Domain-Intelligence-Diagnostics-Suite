'use client';

import { useState } from 'react';
import { ShieldAlert, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import {
  DataTable, FindingList, InfoGrid, ModuleShell, ScoreRing, SectionCard, SeverityBadge, StatusBadge, type TableColumn,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { SecurityResult } from '@/lib/domain360/types';

export function SecurityTab() {
  const [authorize, setAuthorize] = useState(false);
  const { data, error, loading, lastChecked, refresh } = useModuleData<'security'>('security', { authorize: authorize ? '1' : undefined });
  const result = data as SecurityResult | undefined;

  const headerColumns: TableColumn[] = [
    { key: 'name', header: 'Header', className: 'w-56 font-semibold' },
    { key: 'present', header: 'Present', className: 'w-24' },
    { key: 'severity', header: 'Importance', className: 'w-28' },
    { key: 'value', header: 'Value', mono: true },
  ];

  return (
    <ModuleShell
      title="Security Configuration Scanner"
      description="Passive, non-invasive checks: TLS posture, DNSSEC, CAA, security headers, email spoofing protection, accidentally-exposed files and (only with your authorization) DNS zone-transfer exposure."
      icon={result && result.score >= 70 ? <ShieldCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-400" /> : <ShieldAlert className="h-5 w-5 text-amber-500" />}
      loading={loading}
      error={error}
      onRetry={refresh}
      lastChecked={lastChecked}
      onRefresh={refresh}
      rawData={result}
      actions={
        <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
          Re-scan
        </Button>
      }
    >
      <div className="mb-4 flex items-center gap-2 rounded-lg border px-3 py-2.5">
        <Checkbox id="axfr" checked={authorize} onCheckedChange={(v) => setAuthorize(v === true)} />
        <Label htmlFor="axfr" className="text-xs leading-snug text-muted-foreground">
          I am authorized to test this domain and want to include a DNS zone-transfer (AXFR) exposure check
        </Label>
      </div>

      {result ? (
        <div className="space-y-4">
          <div className="flex flex-col items-center gap-4 rounded-xl border bg-card p-4 sm:flex-row">
            <ScoreRing score={result.score} grade={result.grade} size={110} />
            <div className="w-full">
            <InfoGrid
              cols={2}
              items={[
                { label: 'HTTPS enforced', value: result.httpsEnforced === null ? '—' : result.httpsEnforced ? 'Yes' : 'No', status: result.httpsEnforced === false ? 'warning' : result.httpsEnforced ? 'healthy' : undefined },
                { label: 'DNSSEC', value: result.dnssecEnabled === null ? '—' : result.dnssecEnabled ? 'Enabled' : 'Not enabled', status: result.dnssecEnabled ? 'healthy' : 'not_configured' },
                { label: 'CAA policy', value: result.caa?.records.length ? `${result.caa.records.length} record(s)` : 'None', status: result.caa?.records.length ? 'healthy' : 'not_configured' },
                { label: 'HSTS', value: result.hsts?.present ? `max-age ${result.hsts.maxAge ?? '?'}${result.hsts.includeSubdomains ? ', subdomains' : ''}` : 'Missing', status: result.hsts?.present ? 'healthy' : 'warning' },
                { label: 'CSP', value: result.csp?.present ? (result.csp.reportOnly ? 'Report-only' : 'Enforcing') : 'Missing', status: result.csp?.present ? (result.csp.reportOnly ? 'warning' : 'healthy') : 'warning' },
                { label: 'Zone transfer (AXFR)', value: !result.zoneTransfer?.tested ? 'Not tested (authorization required)' : result.zoneTransfer.vulnerable ? 'VULNERABLE' : 'Safe', status: result.zoneTransfer?.vulnerable ? 'critical' : result.zoneTransfer?.tested ? 'healthy' : 'unknown' },
              ]}
            />
            </div>
          </div>

          {/* Blacklist / Threat Reputation section */}
          {result.blacklists && result.blacklists.entries.length > 0 ? (
            <SectionCard
              title="Threat Reputation & Blacklist Audit (DNSBL)"
              description={`Queried ${result.blacklists.checked} industry blacklist databases (Spamhaus, SpamCop, Barracuda, SORBS).`}
            >
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
                {result.blacklists.entries.map((entry) => (
                  <div
                    key={entry.name}
                    className="flex items-center justify-between gap-2.5 rounded-xl border border-border/70 bg-card p-3 shadow-xs"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-[13px] font-medium">{entry.name}</p>
                      <p className="truncate font-mono text-[11px] text-muted-foreground">{entry.host}</p>
                    </div>
                    <StatusBadge status={entry.listed ? 'critical' : 'healthy'} />
                  </div>
                ))}
              </div>
            </SectionCard>
          ) : null}

          <SectionCard title="Security findings" description="Severity-ordered with explanations and concrete fixes.">
            <FindingList findings={result.findings} />
          </SectionCard>

          <SectionCard title="HTTP security headers" description="Checked against the final HTTPS response.">
            <DataTable
              columns={headerColumns}
              rows={result.headersChecked.map((h) => ({
                _key: h.name,
                name: h.name,
                present: <StatusBadge status={h.present ? 'healthy' : 'critical'} />,
                severity: <SeverityBadge severity={h.severity} />,
                value: h.value ? (h.value.length > 80 ? `${h.value.slice(0, 80)}…` : h.value) : '—',
              }))}
            />
            {result.headersChecked.some((h) => !h.present) ? (
              <ul className="mt-3 space-y-2">
                {result.headersChecked.filter((h) => !h.present).map((h) => (
                  <li key={h.name} className="rounded-lg bg-muted/40 px-3 py-2 text-[12.5px]">
                    <p className="font-medium">{h.name}</p>
                    <p className="text-muted-foreground">{h.description}</p>
                    <p className="mt-0.5 font-mono text-[11.5px] text-emerald-700 dark:text-emerald-400">{h.recommendation}</p>
                  </li>
                ))}
              </ul>
            ) : null}
          </SectionCard>

          <SectionCard title="Sensitive file exposure probe" description="Existence-only probe of common accidentally-deployed files. Content is never retrieved or displayed beyond a safe signature check.">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {result.exposedFiles.map((f) => (
                <div key={f.path} className="flex items-center justify-between rounded-lg border px-3 py-2">
                  <span className="font-mono text-[12px]">{f.path}</span>
                  <StatusBadge status={f.exposed ? 'critical' : 'healthy'} />
                </div>
              ))}
            </div>
          </SectionCard>
        </div>
      ) : null}
    </ModuleShell>
  );
}
