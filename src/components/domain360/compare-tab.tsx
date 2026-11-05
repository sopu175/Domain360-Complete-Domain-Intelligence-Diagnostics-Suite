'use client';

import { useState } from 'react';
import { ArrowRight, Scale, Trash2, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { StatusBadge } from '@/components/domain360/shared-ui';
import { API, apiFetch } from '@/lib/domain360/client';
import type { OverviewResult } from '@/lib/domain360/types';
import { cn } from '@/lib/utils';

interface Column {
  domain: string;
  loading: boolean;
  error?: string;
  data?: OverviewResult;
}

export function CompareTab() {
  const [inputs, setInputs] = useState<string[]>(['', '']);
  const [cols, setCols] = useState<Column[]>([]);

  const run = async () => {
    const domains = inputs.map((d) => d.trim().toLowerCase()).filter(Boolean);
    if (!domains.length) return;
    setCols(domains.map((domain) => ({ domain, loading: true })));
    await Promise.all(
      domains.map(async (domain, i) => {
        try {
          const data = await apiFetch<OverviewResult>(API.overview(domain));
          setCols((c) => c.map((col, j) => (j === i ? { domain, loading: false, data } : col)));
        } catch (e) {
          setCols((c) => c.map((col, j) => (j === i ? { domain, loading: false, error: (e as Error).message } : col)));
        }
      }),
    );
  };

  const update = (i: number, v: string) => setInputs((arr) => arr.map((x, j) => (j === i ? v : x)));

  return (
    <div className="space-y-4">
      <div>
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          <Scale className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
          Domain Comparison
        </h2>
        <p className="mt-0.5 text-[13px] text-muted-foreground">
          Compare health scores, registration, SSL, email and security posture across multiple domains side by side.
        </p>
      </div>

      <div className="space-y-2 rounded-xl border bg-card p-4">
        {inputs.map((v, i) => (
          <div key={i} className="flex items-center gap-2">
            <Input
              value={v}
              onChange={(e) => update(i, e.target.value)}
              placeholder={`domain ${i + 1}.com`}
              className="h-10 font-mono"
              aria-label={`Domain ${i + 1}`}
            />
            {inputs.length > 2 ? (
              <Button variant="ghost" size="icon" aria-label="Remove domain" onClick={() => setInputs((arr) => arr.filter((_, j) => j !== i))}>
                <X className="h-4 w-4" />
              </Button>
            ) : null}
            {i < inputs.length - 1 ? <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground" /> : null}
          </div>
        ))}
        <div className="flex gap-2 pt-1">
          <Button onClick={run} disabled={cols.some((c) => c.loading)}>
            Compare
          </Button>
          {inputs.length < 4 ? (
            <Button variant="outline" onClick={() => setInputs((arr) => [...arr, ''])}>
              Add domain
            </Button>
          ) : null}
        </div>
      </div>

      {cols.length ? (
        <div className="overflow-x-auto rounded-xl border">
          <table className="w-full min-w-[640px] text-sm">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="w-44 px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Attribute</th>
                {cols.map((c) => (
                  <th key={c.domain} className="px-3 py-2.5 text-left">
                    <span className="font-mono text-[13px] font-bold">{c.domain}</span>
                    {c.data ? (
                      <span className={cn('ml-2 rounded-full px-2 py-0.5 text-xs font-bold',
                        c.data.score.total >= 75 ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                          : c.data.score.total >= 50 ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
                            : 'bg-red-500/10 text-red-500')}>
                        {c.data.score.total} · {c.data.score.grade}
                      </span>
                    ) : null}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cols.some((c) => c.loading) ? (
                <tr><td colSpan={cols.length + 1} className="p-4"><Skeleton className="h-24 w-full" /></td></tr>
              ) : (
                ROWS.map((row) => (
                  <tr key={row.label} className="border-t">
                    <td className="px-3 py-2 text-[12px] font-medium text-muted-foreground">{row.label}</td>
                    {cols.map((c) => (
                      <td key={c.domain} className="px-3 py-2 align-top">
                        {c.error ? (
                          <span className="text-xs text-red-500">{c.error}</span>
                        ) : c.data ? (
                          <span className="text-[13px]">{row.value(c.data)}</span>
                        ) : null}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

const fmtDate = (iso: string | null) =>
  iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—';

const ROWS: { label: string; value: (d: OverviewResult) => React.ReactNode }[] = [
  { label: 'Overall status', value: (d) => <StatusBadge status={d.cards.status} /> },
  { label: 'Registrar', value: (d) => d.cards.registrar || '—' },
  { label: 'Registered', value: (d) => fmtDate(d.cards.createdDate) },
  { label: 'Expires', value: (d) => `${fmtDate(d.cards.expirationDate)}${d.cards.daysToExpiry !== null ? ` (${d.cards.daysToExpiry}d)` : ''}` },
  { label: 'Nameservers', value: (d) => d.cards.nameServers.length || '—' },
  { label: 'DNS provider', value: (d) => d.cards.dnsProvider || '—' },
  { label: 'IPv4', value: (d) => d.cards.ip4.join(', ') || '—' },
  { label: 'Hosting', value: (d) => d.cards.hosting ? `${d.cards.hosting.org || '?'}${d.cards.hosting.country ? ` · ${d.cards.hosting.country}` : ''}` : '—' },
  { label: 'SSL status', value: (d) => d.cards.sslStatus?.replace('_', ' ') || '—' },
  { label: 'SSL days left', value: (d) => d.cards.sslDaysRemaining ?? '—' },
  { label: 'Website', value: (d) => (d.cards.websiteUp === null ? '—' : d.cards.websiteUp ? `Up (${d.cards.httpStatus})` : 'Down') },
  { label: 'Mail', value: (d) => d.cards.mailProvider || (d.cards.mxCount ? `${d.cards.mxCount} MX` : 'none') },
  { label: 'SPF / DMARC', value: (d) => `${d.cards.spf ? '✓' : '✗'} / ${d.cards.dmarc ? '✓' : '✗'}` },
  { label: 'DNSSEC', value: (d) => (d.cards.dnssec === null ? '—' : d.cards.dnssec ? 'Enabled' : 'Off') },
  { label: 'CAA', value: (d) => (d.cards.caa ? 'Present' : 'None') },
  { label: 'HTTPS enforced', value: (d) => (d.cards.httpRedirectsToHttps === null ? '—' : d.cards.httpRedirectsToHttps ? 'Yes' : 'No') },
  {
    label: 'DNS health', value: (d) => {
      const c = d.score.categories.find((x) => x.key === 'dns');
      return c ? `${c.score}/${c.max}` : '—';
    },
  },
  {
    label: 'SSL health', value: (d) => {
      const c = d.score.categories.find((x) => x.key === 'ssl');
      return c ? `${c.score}/${c.max}` : '—';
    },
  },
  {
    label: 'Email security', value: (d) => {
      const c = d.score.categories.find((x) => x.key === 'email');
      return c ? `${c.score}/${c.max}` : '—';
    },
  },
  {
    label: 'HTTP security', value: (d) => {
      const c = d.score.categories.find((x) => x.key === 'http');
      return c ? `${c.score}/${c.max}` : '—';
    },
  },
];
