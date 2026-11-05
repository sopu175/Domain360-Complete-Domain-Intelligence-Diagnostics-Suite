'use client';

import {
  Award, BadgeCheck, Building2, CalendarClock, Database, FileSearch,
  Globe2, KeyRound, Mail, RefreshCw, Server, ShieldCheck, Activity,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  FindingList, InfoGrid, ModuleShell, ScoreRing, SectionCard, StatusBadge, statusMeta,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { OverviewResult } from '@/lib/domain360/types';
import { cn } from '@/lib/utils';

function formatDate(iso: string | null): string {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function OverviewTab() {
  const { data, error, loading, lastChecked, refresh } = useModuleData<'overview'>('overview');
  const overview = data as OverviewResult | undefined;

  return (
    <ModuleShell
      title="Domain Overview"
      description="Aggregated health report built from live DNS, TLS, RDAP, HTTP and email checks."
      icon={<Globe2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
      loading={loading}
      error={error}
      onRetry={refresh}
      lastChecked={lastChecked}
      onRefresh={refresh}
      rawData={overview}
    >
      {overview ? (
        <div className="space-y-5">
          {/* score + categories */}
          <SectionCard
            title="Domain Health Score"
            description={overview.score.methodology}
            icon={<Award className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />}
          >
            <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-start">
              <div className="flex flex-col items-center gap-2">
                <ScoreRing score={overview.score.total} grade={overview.score.grade} />
                <StatusBadge status={overview.cards.status} />
              </div>
              <div className="w-full flex-1 space-y-2.5">
                {overview.score.categories.map((c) => {
                  const pct = Math.round((c.score / c.max) * 100);
                  return (
                    <div key={c.key}>
                      <div className="mb-1 flex items-center justify-between text-[13px]">
                        <span className="font-medium">{c.label}</span>
                        <span className="tabular-nums text-muted-foreground">
                          {c.score}/{c.max}
                        </span>
                      </div>
                      <div className="h-2 overflow-hidden rounded-full bg-muted">
                        <div
                          className={cn(
                            'h-full rounded-full transition-all duration-700',
                            pct >= 80 ? 'bg-emerald-500' : pct >= 50 ? 'bg-amber-500' : 'bg-red-500',
                          )}
                          style={{ width: `${Math.max(3, pct)}%` }}
                        />
                      </div>
                      {c.notes.length ? (
                        <p className="mt-1 text-[11.5px] leading-snug text-muted-foreground">{c.notes.join(' · ')}</p>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            </div>
            <p className="mt-4 rounded-lg bg-muted/40 px-3 py-2 text-[11.5px] leading-relaxed text-muted-foreground">
              {overview.score.disclaimer}
            </p>
          </SectionCard>

          {/* key cards */}
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <MiniCard
              icon={<Building2 className="h-4 w-4" />}
              label="Registrar"
              value={overview.cards.registrar || '—'}
              hint={overview.cards.createdDate ? `Registered ${formatDate(overview.cards.createdDate)}` : undefined}
            />
            <MiniCard
              icon={<CalendarClock className="h-4 w-4" />}
              label="Expires"
              value={overview.cards.expirationDate ? formatDate(overview.cards.expirationDate) : '—'}
              hint={overview.cards.daysToExpiry !== null ? `in ${overview.cards.daysToExpiry} days` : undefined}
              warn={overview.cards.daysToExpiry !== null && overview.cards.daysToExpiry < 60}
            />
            <MiniCard
              icon={<ShieldCheck className="h-4 w-4" />}
              label="SSL / TLS"
              value={overview.cards.sslStatus ? overview.cards.sslStatus.replace('_', ' ') : '—'}
              hint={overview.cards.sslDaysRemaining !== null ? `${overview.cards.sslDaysRemaining} days remaining` : undefined}
              status={overview.cards.sslStatus === 'valid' ? 'healthy' : overview.cards.sslStatus === 'expiring_soon' ? 'warning' : overview.cards.sslStatus ? 'critical' : undefined}
            />
            <MiniCard
              icon={<Activity className="h-4 w-4" />}
              label="Website"
              value={overview.cards.websiteUp === null ? '—' : overview.cards.websiteUp ? `Up (HTTP ${overview.cards.httpStatus})` : 'Down'}
              hint={overview.cards.httpRedirectsToHttps === true ? 'HTTPS enforced' : overview.cards.httpRedirectsToHttps === false ? 'No HTTPS redirect' : undefined}
              status={overview.cards.websiteUp === null ? 'unknown' : overview.cards.websiteUp ? 'healthy' : 'critical'}
            />
            <MiniCard
              icon={<Server className="h-4 w-4" />}
              label="Nameservers"
              value={overview.cards.nameServers.length ? `${overview.cards.nameServers.length} servers` : '—'}
              hint={overview.cards.dnsProvider || overview.cards.nameServers[0]}
            />
            <MiniCard
              icon={<Database className="h-4 w-4" />}
              label="IP Addresses"
              value={overview.cards.ip4.length ? overview.cards.ip4[0] : '—'}
              hint={[...overview.cards.ip4.slice(1), ...overview.cards.ip6].join(', ') || undefined}
              copy={overview.cards.ip4[0]}
            />
            <MiniCard
              icon={<Mail className="h-4 w-4" />}
              label="Email"
              value={overview.cards.mxCount ? overview.cards.mailProvider || `${overview.cards.mxCount} MX` : 'No mail'}
              hint={`SPF ${overview.cards.spf ? '✓' : '✗'} · DMARC ${overview.cards.dmarc ? '✓' : '✗'}`}
              status={overview.cards.mxCount === 0 ? 'not_configured' : overview.cards.spf && overview.cards.dmarc ? 'healthy' : 'warning'}
            />
            <MiniCard
              icon={<KeyRound className="h-4 w-4" />}
              label="DNSSEC"
              value={overview.cards.dnssec === null ? 'Unknown' : overview.cards.dnssec ? 'Enabled' : 'Not enabled'}
              hint={overview.cards.caa ? 'CAA policy present' : 'No CAA policy'}
              status={overview.cards.dnssec === null ? 'unknown' : overview.cards.dnssec ? 'healthy' : 'not_configured'}
            />
          </div>

          {/* module statuses */}
          <SectionCard title="Module status" description="Each diagnostic module and its current result." icon={<FileSearch className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />}>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {overview.moduleStatus.map((m) => (
                <div key={m.module} className="flex items-center justify-between rounded-lg border px-3 py-2">
                  <div>
                    <p className="text-sm font-medium">{m.module}</p>
                    <p className="text-[11.5px] text-muted-foreground">{m.summary}</p>
                  </div>
                  <StatusBadge status={m.status} />
                </div>
              ))}
            </div>
          </SectionCard>

          {/* findings */}
          <SectionCard
            title="Findings & recommendations"
            description="Issues detected across all modules, most severe first."
            icon={<BadgeCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />}
            actions={
              <Button variant="outline" size="sm" onClick={refresh}>
                <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Re-run
              </Button>
            }
          >
            <FindingList findings={overview.score.findings} />
          </SectionCard>
        </div>
      ) : null}
    </ModuleShell>
  );
}

function MiniCard({
  icon, label, value, hint, status, warn, copy,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  hint?: string;
  status?: string;
  warn?: boolean;
  copy?: string;
}) {
  return (
    <div className="rounded-xl border bg-card p-3.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-muted-foreground">
          {icon}
          <span className="text-[11px] font-medium uppercase tracking-wide">{label}</span>
        </div>
        {status ? <span className={cn('h-2 w-2 rounded-full', statusMeta(status).dot)} /> : null}
      </div>
      <p className={cn('mt-2 truncate text-[13.5px] font-semibold', warn && 'text-amber-600 dark:text-amber-400')} title={value}>
        {value}
      </p>
      {hint ? <p className="mt-0.5 truncate text-[11.5px] text-muted-foreground" title={hint}>{hint}</p> : null}
      {copy ? (
        <p className="sr-only">{copy}</p>
      ) : null}
    </div>
  );
}
