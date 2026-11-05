'use client';

import { useState } from 'react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Mail } from 'lucide-react';
import {
  DataTable, FindingList, InfoGrid, IpBadge, ModuleShell, ScoreRing, SectionCard, StatusBadge, flagEmoji, type TableColumn,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { EmailResult } from '@/lib/domain360/types';

export function EmailTab() {
  const [selectorInput, setSelectorInput] = useState('');
  const [selectors, setSelectors] = useState<string | undefined>(undefined);
  const { data, error, loading, lastChecked, refresh } = useModuleData<'email'>('email', { selectors });
  const result = data as EmailResult | undefined;

  const mxColumns: TableColumn[] = [
    { key: 'priority', header: 'Priority', className: 'w-16 tabular-nums' },
    { key: 'exchange', header: 'Mail exchanger', mono: true, className: 'min-w-[220px]' },
    { key: 'ips', header: 'IP addresses', className: 'min-w-[190px]' },
    { key: 'location', header: 'Location / Country', className: 'min-w-[160px]' },
    { key: 'ptr', header: 'Reverse DNS', mono: true, className: 'min-w-[170px]' },
    { key: 'provider', header: 'Provider', className: 'min-w-[130px]' },
    { key: 'smtp', header: 'SMTP :25', className: 'min-w-[140px]' },
  ];

  return (
    <ModuleShell
      title="Email DNS & Deliverability"
      description="MX infrastructure plus SPF syntax/limits, DMARC policy, DKIM selector discovery, BIMI, MTA-STS and TLS-RPT — with an email security score."
      icon={<Mail className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
      loading={loading}
      error={error}
      onRetry={refresh}
      lastChecked={lastChecked}
      onRefresh={refresh}
      rawData={result}
      actions={
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            setSelectors(selectorInput.trim() || undefined);
          }}
        >
          <Input
            value={selectorInput}
            onChange={(e) => setSelectorInput(e.target.value)}
            placeholder="Custom DKIM selector(s), comma-separated"
            className="h-8 w-56 text-xs"
            aria-label="DKIM selectors"
          />
          <Button type="submit" variant="outline" size="sm">Check</Button>
        </form>
      }
    >
      {result ? (
        <div className="space-y-4">
          {result.grade === 'N/A' ? (
            <div className="rounded-lg border bg-muted/30 px-3 py-2.5 text-sm text-muted-foreground">
              No mail configuration detected on this domain (no MX, SPF or DMARC) — the score below is informational only.
            </div>
          ) : null}

          <div className="flex flex-col items-center gap-4 rounded-xl border bg-card p-4 sm:flex-row">
            <ScoreRing score={result.score} grade={result.grade === 'N/A' ? '—' : result.grade} size={110} />
            <div className="w-full">
              <p className="text-sm font-semibold">Email security score: {result.score}/100</p>
              <p className="mt-1 text-[12.5px] leading-relaxed text-muted-foreground">
                MX presence &amp; redundancy, SPF validity &amp; strictness, DMARC enforcement level, DKIM signing keys,
                MTA-STS and TLS-RPT. Missing features that don&apos;t apply (e.g. no mail service) are never counted as failures.
              </p>
            </div>
          </div>

          <SectionCard title={`Mail exchangers (${result.mx.length})`}>
            <DataTable
              columns={mxColumns}
              rows={result.mx.map((m) => ({
                _key: `${m.priority}-${m.exchange}`,
                priority: m.priority,
                exchange: m.exchange,
                ips: m.ips.length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {m.ips.map((i) => (
                      <IpBadge key={i.ip} ip={i.ip} version={i.version} />
                    ))}
                  </div>
                ) : (
                  '—'
                ),
                location: m.countryCode || m.country ? (
                  <div className="flex items-center gap-1.5 text-xs font-medium">
                    <span className="text-base leading-none">{flagEmoji(m.countryCode)}</span>
                    <span className="truncate max-w-[160px]">
                      {m.city ? `${m.city}, ` : ''}{m.country || m.countryCode}
                    </span>
                  </div>
                ) : (
                  <span className="text-xs text-muted-foreground">—</span>
                ),
                ptr: m.ptr || '—',
                provider: m.providerGuess || '—',
                smtp: m.reachable === null
                  ? <span className="text-xs text-muted-foreground" title="Outbound SMTP is often blocked in cloud environments; result is inconclusive">Not testable</span>
                  : m.reachable
                    ? <span className="text-xs font-medium text-emerald-600 dark:text-emerald-400">Open{m.banner ? ` — ${m.banner}` : ''}</span>
                    : <span className="text-xs text-muted-foreground">Refused</span>,
              }))}
              empty="No MX records"
            />
          </SectionCard>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <SectionCard title="SPF" description={result.spf?.record || 'No SPF record found'}>
              {result.spf ? (
                <div className="space-y-2 text-sm">
                  <InfoGrid
                    cols={2}
                    items={[
                      { label: 'Policy', value: result.spf.policy, status: result.spf.policy === 'fail' ? 'healthy' : result.spf.policy === 'softfail' ? 'warning' : 'critical' },
                      { label: 'DNS lookups', value: `${result.spf.dnsLookups} / 10` },
                    ]}
                  />
                  {result.spf.issues.map((i, idx) => (
                    <p key={idx} className="rounded-md border border-amber-500/30 bg-amber-500/5 px-2.5 py-1.5 text-xs text-amber-700 dark:text-amber-400">{i}</p>
                  ))}
                </div>
              ) : (
                <StatusBadge status="critical" />
              )}
            </SectionCard>

            <SectionCard title="DMARC" description={result.dmarc?.record || 'No DMARC record found (_dmarc)'}>
              {result.dmarc ? (
                <InfoGrid
                  cols={2}
                  items={[
                    { label: 'Policy (p=)', value: result.dmarc.policy || '—', status: result.dmarc.policy === 'reject' ? 'healthy' : result.dmarc.policy === 'quarantine' ? 'warning' : 'critical' },
                    { label: 'Subdomain policy', value: result.dmarc.subdomainPolicy || 'inherits' },
                    { label: 'Applied to', value: result.dmarc.pct !== null ? `${result.dmarc.pct}% of mail` : '100%' },
                    { label: 'Aggregate reports', value: result.dmarc.rua ? 'Configured' : 'None' },
                  ]}
                />
              ) : (
                <StatusBadge status="critical" />
              )}
            </SectionCard>
          </div>

          <SectionCard title={`DKIM selectors (${result.dkim.length} found)`} description="Checked against 30+ common selectors plus any you entered above.">
            {result.dkim.length ? (
              <DataTable
                columns={[
                  { key: 'selector', header: 'Selector', className: 'w-40 font-semibold' },
                  { key: 'alg', header: 'Key type', className: 'w-28' },
                  { key: 'bits', header: 'Key size', className: 'w-24 tabular-nums' },
                  { key: 'record', header: 'Record (truncated)', mono: true },
                ]}
                rows={result.dkim.map((d) => ({
                  _key: d.selector,
                  selector: d.selector,
                  alg: d.algorithm,
                  bits: d.keyBits ? `${d.keyBits}-bit` : '—',
                  record: d.record?.slice(0, 100) || '—',
                }))}
              />
            ) : (
              <StatusBadge status="not_configured" />
            )}
          </SectionCard>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <SectionCard title="BIMI"><StatusBadge status={result.bimi?.valid ? 'healthy' : 'not_configured'} /><p className="mt-1 truncate font-mono text-[11px] text-muted-foreground">{result.bimi?.record || 'No record at default._bimi'}</p></SectionCard>
            <SectionCard title="MTA-STS"><StatusBadge status={result.mtaSts?.dnsRecord ? (result.mtaSts.policy ? 'healthy' : 'warning') : 'not_configured'} /><p className="mt-1 text-[11px] text-muted-foreground">{result.mtaSts?.dnsRecord ? 'DNS present' + (result.mtaSts.policy ? ' + policy served' : ', policy unreachable') : 'No _mta-sts record'}</p></SectionCard>
            <SectionCard title="TLS-RPT"><StatusBadge status={result.tlsRpt?.valid ? 'healthy' : 'not_configured'} /><p className="mt-1 truncate font-mono text-[11px] text-muted-foreground">{result.tlsRpt?.record || 'No _smtp._tls record'}</p></SectionCard>
          </div>

          <SectionCard title="Findings & recommendations">
            <FindingList findings={result.findings} />
          </SectionCard>
        </div>
      ) : null}
    </ModuleShell>
  );
}
