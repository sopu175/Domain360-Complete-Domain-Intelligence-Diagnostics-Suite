'use client';

import { useCallback, useEffect, useState } from 'react';
import { Download, FileBarChart2, FileJson, FileSpreadsheet, Printer, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from '@/components/domain360/shared-ui';
import { API, apiFetch } from '@/lib/domain360/client';
import { useStore, useModuleData } from '@/lib/domain360/store';
import type { HistoryItem, OverviewResult } from '@/lib/domain360/types';

export function ReportsTab() {
  const domain = useStore((s) => s.domain);
  const runScan = useStore((s) => s.runScan);
  const [items, setItems] = useState<HistoryItem[] | null>(null);
  const [error, setError] = useState<string | undefined>();
  const overview = useModuleData<'overview'>('overview');

  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setError(undefined);
    apiFetch<{ items: HistoryItem[] }>(API.history())
      .then((data) => {
        if (!cancelled) setItems(data.items);
      })
      .catch((e) => {
        if (!cancelled) setError((e as Error).message);
      });
    return () => {
      cancelled = true;
    };
  }, [reloadTick]);

  const load = useCallback(() => {
    setError(undefined);
    setItems(null);
    setReloadTick((t) => t + 1);
  }, []);

  const download = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportJson = () => {
    if (!domain) return;
    const norm = domain.toLowerCase();
    const payload: Record<string, unknown> = { domain, generatedAt: new Date().toISOString() };
    const state = useStore.getState();
    for (const m of ['overview', 'dns', 'propagation', 'nameservers', 'ip', 'ssl', 'whois', 'email', 'http', 'security', 'subdomains', 'dnssec']) {
      const matchKey = Object.keys(state.modules).find((k) => k.startsWith(`${m}:${norm}:`));
      if (matchKey && state.modules[matchKey]?.status === 'ok') {
        payload[m] = state.modules[matchKey].data;
      }
    }
    download(JSON.stringify(payload, null, 2), `domain360-${domain}.json`, 'application/json');
  };

  const exportCsv = () => {
    const o = overview.data as OverviewResult | undefined;
    if (!o) return;
    const rows = [
      ['domain', 'checked_at', 'score', 'grade', 'category', 'category_score', 'category_max'],
      ...o.score.categories.map((c) => [o.domain, o.checkedAt, String(o.score.total), o.score.grade, c.label, String(c.score), String(c.max)]),
      [],
      ['finding_severity', 'finding_title', 'finding_description'],
      ...o.score.findings.map((f) => [f.severity, f.title, f.description.replace(/"/g, "'")]),
    ];
    const csv = rows.map((r) => r.map((cell) => `"${String(cell ?? '')}"`).join(',')).join('\n');
    download(csv, `domain360-${o.domain}-score.csv`, 'text/csv');
  };

  const deleteItem = async (id: string) => {
    try {
      await fetch(API.historyDelete(id), { method: 'DELETE' });
      setItems((list) => (list ? list.filter((i) => i.id !== id) : list));
    } catch { /* ignore */ }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <FileBarChart2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
            Reports & History
          </h2>
          <p className="mt-0.5 text-[13px] text-muted-foreground">
            Export the current scan and browse previous scans stored locally in this deployment.
          </p>
        </div>
        {domain ? (
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={exportJson}>
              <FileJson className="mr-1.5 h-3.5 w-3.5" /> JSON
            </Button>
            <Button variant="outline" size="sm" onClick={exportCsv} disabled={!overview.data}>
              <FileSpreadsheet className="mr-1.5 h-3.5 w-3.5" /> CSV
            </Button>
            <Button variant="outline" size="sm" onClick={() => window.print()}>
              <Printer className="mr-1.5 h-3.5 w-3.5" /> Print / PDF
            </Button>
          </div>
        ) : null}
      </div>

      {domain && overview.data ? (
        <div className="rounded-xl border bg-card p-4">
          <p className="text-sm font-medium">Current report: <span className="font-mono">{domain}</span></p>
          <p className="mt-1 text-[12.5px] text-muted-foreground">
            Health score {overview.data.score.total}/100 (grade {overview.data.score.grade}) · checked {new Date(overview.data.checkedAt).toLocaleString()}
          </p>
          <p className="mt-1 text-[11.5px] text-muted-foreground">
            Tip: JSON contains every completed module&apos;s raw data; Print/PDF uses your browser&apos;s print dialog with a print-optimized layout.
          </p>
        </div>
      ) : null}

      <div className="rounded-xl border bg-card p-4">
        <p className="mb-3 text-sm font-semibold">Scan history</p>
        {error ? (
          <ErrorState message={error} onRetry={load} />
        ) : items === null ? (
          <LoadingRows rows={4} />
        ) : items.length === 0 ? (
          <EmptyState
            icon={<Download className="h-6 w-6" />}
            title="No scans recorded yet"
            description="Run a domain scan and it will appear here."
          />
        ) : (
          <div className="max-h-96 overflow-auto rounded-lg border">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-muted/95 backdrop-blur">
                <tr>
                  <th className="px-3 py-2 text-left text-[11px] font-semibold uppercase text-muted-foreground">Domain</th>
                  <th className="px-3 py-2 text-left text-[11px] font-semibold uppercase text-muted-foreground">Score</th>
                  <th className="px-3 py-2 text-left text-[11px] font-semibold uppercase text-muted-foreground">When</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.id} className="border-t transition-colors hover:bg-muted/40">
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        onClick={() => void runScan(i.domain)}
                        className="font-mono text-[13px] font-semibold text-emerald-600 hover:underline dark:text-emerald-400"
                        title={`Load scan for ${i.domain}`}
                      >
                        {i.domain}
                      </button>
                    </td>
                    <td className="px-3 py-2">
                      {i.score !== null ? (
                        <span className="flex items-center gap-2">
                          <span className="font-semibold tabular-nums">{i.score}</span>
                          {i.grade ? <StatusBadge status={i.score >= 75 ? 'healthy' : i.score >= 50 ? 'warning' : 'critical'} /> : null}
                        </span>
                      ) : '—'}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">{new Date(i.createdAt).toLocaleString()}</td>
                    <td className="px-3 py-2 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs text-muted-foreground hover:text-foreground"
                          onClick={() => void runScan(i.domain)}
                        >
                          Load
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 w-7 text-muted-foreground hover:text-red-500"
                          aria-label="Delete history entry"
                          onClick={() => deleteItem(i.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
