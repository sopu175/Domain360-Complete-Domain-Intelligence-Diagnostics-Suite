'use client';

import { MapPin } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import {
  CopyButton, InfoGrid, IpBadge, ModuleShell, SectionCard, StatusBadge,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { IpDetail, IpResult } from '@/lib/domain360/types';
import { cn } from '@/lib/utils';

function ipCard(d: IpDetail) {
  return (
    <div key={d.ip} className="rounded-xl border bg-card shadow-xs">
      <div className="flex items-center justify-between border-b px-3.5 py-2.5">
        <IpBadge ip={d.ip} version={d.version} />
        <span className="text-xs text-muted-foreground">{d.city && d.country ? `${d.city}, ${d.country}` : 'Global IP'}</span>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2 px-3.5 py-3 text-[12.5px] sm:grid-cols-3">
        <Field label="PTR (Reverse DNS)" value={d.ptr} mono tooltip="Reverse DNS pointer resolving this IP address back to its host domain." />
        <Field label="ASN" value={d.asn} mono tooltip="Autonomous System Number identifying the network operator (BGP routing)." />
        <Field label="Org / ISP" value={d.isp || d.org} tooltip="Internet Service Provider or enterprise hosting organization." />
        <Field label="Country" value={d.country ? `${d.country}${d.countryCode ? ` (${d.countryCode})` : ''}` : null} />
        <Field label="Region" value={d.region} />
        <Field label="City" value={d.city} />
        <Field label="Coordinates" value={d.latitude !== null && d.longitude !== null ? `${d.latitude.toFixed(3)}, ${d.longitude.toFixed(3)}` : null} mono />
        <Field label="Timezone" value={d.timezone} />
        <Field label="IP Type" value={d.ipType !== 'unknown' ? d.ipType.toUpperCase() : null} tooltip="Network classification: Datacenter/Hosting, Residential, Business, or Education." />
        <Field label="Network" value={d.asnOrg} />
        <Field label="Provider domain" value={d.providerDomain} mono />
        <Field label="Geo source" value={d.source} />
      </div>
    </div>
  );
}

function Field({ label, value, mono, tooltip }: { label: string; value?: string | null; mono?: boolean; tooltip?: string }) {
  const content = (
    <div>
      <p className="text-[10.5px] font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={cn('truncate', mono ? 'font-mono text-[12px]' : '')} title={value || undefined}>
        {value || '—'}
      </p>
    </div>
  );

  if (!tooltip) return content;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className="cursor-help">{content}</div>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-left">
        <p className="font-semibold text-xs">{label}</p>
        <p className="mt-0.5 text-[11px] text-muted-foreground">{tooltip}</p>
      </TooltipContent>
    </Tooltip>
  );
}

export function IpTab() {
  const { data, error, loading, lastChecked, refresh } = useModuleData<'ip'>('ip');
  const result = data as IpResult | undefined;

  return (
    <ModuleShell
      title="IP Address & Hosting Intelligence"
      description="Resolved IPv4/IPv6 with reverse DNS, ASN, hosting network, geolocation plus CDN / cloud-provider detection."
      icon={<MapPin className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
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
              { label: 'Query', value: result.query, mono: true },
              { label: 'IPv4 addresses', value: result.ipv4.length },
              { label: 'IPv6 addresses', value: result.ipv6.length },
              { label: 'CDN detected', value: result.cdn ? `${result.cdn.name} (${result.cdn.confidence} confidence)` : 'None detected', status: result.cdn ? 'info' : undefined },
              { label: 'Cloud provider', value: result.cloudProvider || 'None detected' },
              { label: 'PTR records', value: [...result.ipv4, ...result.ipv6].filter((d) => d.ptr).length },
            ]}
          />

          <p className="rounded-lg border bg-muted/30 px-3 py-2 text-[11.5px] leading-relaxed text-muted-foreground">
            {result.ipTypeNote}
          </p>

          {result.ipv4.length ? (
            <SectionCard title="IPv4 addresses">
              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">{result.ipv4.map(ipCard)}</div>
            </SectionCard>
          ) : (
            <SectionCard title="IPv4 addresses"><StatusBadge status="not_configured" /> <span className="ml-2 text-sm text-muted-foreground">No A records.</span></SectionCard>
          )}

          {result.ipv6.length ? (
            <SectionCard title="IPv6 addresses">
              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">{result.ipv6.map(ipCard)}</div>
            </SectionCard>
          ) : null}
        </div>
      ) : null}
    </ModuleShell>
  );
}
