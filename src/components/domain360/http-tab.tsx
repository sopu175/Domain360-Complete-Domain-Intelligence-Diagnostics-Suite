'use client';

import { Activity } from 'lucide-react';
import {
  DataTable, InfoGrid, ModuleShell, SectionCard, StatusBadge, type TableColumn,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { HttpResult } from '@/lib/domain360/types';

export function HttpTab() {
  const { data, error, loading, lastChecked, refresh } = useModuleData<'http'>('http');
  const result = data as HttpResult | undefined;

  const hopColumns: TableColumn[] = [
    { key: 'step', header: '#', className: 'w-10' },
    { key: 'status', header: 'Status', className: 'w-20 font-semibold' },
    { key: 'url', header: 'URL', mono: true },
    { key: 'location', header: 'Redirects to', mono: true },
    { key: 'ms', header: 'Time', className: 'w-20 tabular-nums' },
  ];

  return (
    <ModuleShell
      title="Website & HTTP Diagnostics"
      description="Real HTTP requests with SSRF-safe redirect following: response codes, timing, compression, HTTP/2, robots/sitemap/favicon and mixed-content scan."
      icon={<Activity className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
      loading={loading}
      error={error}
      onRetry={refresh}
      lastChecked={lastChecked}
      onRefresh={refresh}
      rawData={result}
    >
      {result ? (
        <div className="space-y-4">
          {result.error ? (
            <div className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-sm text-red-600 dark:text-red-400">
              {result.error}
            </div>
          ) : null}

          <InfoGrid
            cols={4}
            items={[
              { label: 'Final status', value: result.statusCode ? `${result.statusCode} ${result.statusText}` : '—', status: result.statusCode ? (result.statusCode < 400 ? 'healthy' : 'critical') : undefined },
              { label: 'Final URL', value: result.finalUrl, mono: true },
              { label: 'Transport', value: result.httpVersion || '—', mono: true },
              { label: 'HTTP/2', value: result.h2Supported === null ? '—' : result.h2Supported ? 'Yes' : 'No', status: result.h2Supported ? 'healthy' : 'not_configured' },
              { label: 'HTTP/3', value: 'Not probed (UDP/QUIC)' },
              { label: 'Compression', value: result.compression.enabled ? result.compression.encoding : 'None', status: result.compression.enabled ? 'healthy' : 'warning' },
              { label: 'HTTPS redirect', value: result.httpsRedirect === null ? '—' : result.httpsRedirect ? 'Yes' : 'No', status: result.httpsRedirect === false ? 'warning' : result.httpsRedirect ? 'healthy' : undefined },
              { label: 'Content type', value: result.contentType || '—', mono: true },
              { label: 'Body size', value: result.contentLengthBytes ? `${(result.contentLengthBytes / 1024).toFixed(1)} KB` : '—' },
              { label: 'Server', value: result.server || '—', mono: true },
              { label: 'X-Powered-By', value: result.poweredBy || '—', mono: true },
              { label: 'Page title', value: result.title || '—' },
            ]}
          />

          {result.redirects.length ? (
            <SectionCard title={`Redirect chain (${result.redirects.length} hop${result.redirects.length > 1 ? 's' : ''})`} description={result.redirectLoop ? 'A redirect LOOP was detected!' : 'Each hop verified against SSRF protection (public IPs only, ports 80/443).'}>
              <DataTable
                columns={hopColumns}
                rows={result.redirects.map((h, i) => ({
                  _key: `${i}-${h.url}`,
                  step: i + 1,
                  status: h.status,
                  url: h.url,
                  location: h.location,
                  ms: `${h.ms} ms`,
                }))}
              />
            </SectionCard>
          ) : null}

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <SectionCard title="robots.txt">
              <div className="space-y-1.5 text-sm">
                <div className="flex items-center gap-2">
                  <StatusBadge status={result.robots.exists ? 'healthy' : 'not_configured'} />
                  <span>{result.robots.exists ? 'Found' : `Not found (HTTP ${result.robots.status ?? '?'})`}</span>
                </div>
                {result.robots.sitemaps.length ? (
                  <p className="break-all font-mono text-[11.5px] text-muted-foreground">Sitemaps: {result.robots.sitemaps.join(', ')}</p>
                ) : (
                  <p className="text-xs text-muted-foreground">No Sitemap directive.</p>
                )}
              </div>
            </SectionCard>
            <SectionCard title="sitemap.xml">
              <div className="flex items-center gap-2 text-sm">
                <StatusBadge status={result.sitemap.exists ? 'healthy' : 'not_configured'} />
                <span>{result.sitemap.exists ? 'Found' : `Not found (HTTP ${result.sitemap.status ?? '?'})`}</span>
              </div>
            </SectionCard>
            <SectionCard title="favicon.ico">
              <div className="flex items-center gap-2 text-sm">
                <StatusBadge status={result.favicon.exists ? 'healthy' : 'not_configured'} />
                <span>{result.favicon.exists ? 'Found' : `Not found (HTTP ${result.favicon.status ?? '?'})`}</span>
              </div>
            </SectionCard>
          </div>

          <SectionCard title="Canonical URL & mixed content">
            <div className="space-y-2 text-sm">
              <p><span className="font-medium">Canonical:</span> <span className="font-mono text-[12.5px]">{result.canonical || 'Not declared'}</span></p>
              <div className="flex items-center gap-2">
                <span className="font-medium">Mixed content:</span>
                <StatusBadge status={result.mixedContent.detected ? 'warning' : 'healthy'} />
                <span className="text-muted-foreground">{result.mixedContent.detected ? `${result.mixedContent.samples.length} insecure http:// resource(s) on an HTTPS page` : 'None detected'}</span>
              </div>
              {result.mixedContent.samples.length ? (
                <ul className="list-inside list-disc font-mono text-[11.5px] text-muted-foreground">
                  {result.mixedContent.samples.map((s) => (
                    <li key={s} className="break-all">{s}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          </SectionCard>

          <SectionCard title="Response headers" description="All headers from the final response.">
            <DataTable
              columns={[
                { key: 'name', header: 'Header', className: 'w-56 font-semibold' },
                { key: 'value', header: 'Value', mono: true },
              ]}
              rows={result.headers.map((h) => ({ _key: h.name, name: h.name, value: h.value }))}
            />
          </SectionCard>
        </div>
      ) : null}
    </ModuleShell>
  );
}
