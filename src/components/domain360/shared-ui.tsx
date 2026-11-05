'use client';

import { useState, type ReactNode } from 'react';
import { Check, ChevronDown, Copy, Loader2, RefreshCw, AlertTriangle, Clock } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import type { Severity, StatusLevel } from '@/lib/domain360/types';

// ---------------------------------------------------------------- status

const STATUS_META: Record<string, { label: string; cls: string; dot: string }> = {
  healthy: { label: 'Healthy', cls: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30', dot: 'bg-emerald-500' },
  warning: { label: 'Warning', cls: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30', dot: 'bg-amber-500' },
  critical: { label: 'Critical', cls: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30', dot: 'bg-red-500' },
  unknown: { label: 'Unknown', cls: 'bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border-zinc-500/30', dot: 'bg-zinc-400' },
  not_configured: { label: 'Not configured', cls: 'bg-zinc-500/10 text-zinc-500 dark:text-zinc-400 border-zinc-500/30', dot: 'bg-zinc-400' },
  info: { label: 'Info', cls: 'bg-zinc-500/10 text-zinc-600 dark:text-zinc-300 border-zinc-500/30', dot: 'bg-zinc-400' },
};

const SEVERITY_META: Record<Severity, { label: string; cls: string }> = {
  critical: { label: 'Critical', cls: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30' },
  high: { label: 'High', cls: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30' },
  medium: { label: 'Medium', cls: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30' },
  low: { label: 'Low', cls: 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/30' },
  info: { label: 'Info', cls: 'bg-zinc-500/10 text-zinc-600 dark:text-zinc-300 border-zinc-500/30' },
  pass: { label: 'Pass', cls: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30' },
};

export function statusMeta(s: string) {
  return STATUS_META[s] || STATUS_META.unknown;
}

export function StatusBadge({ status, className }: { status: StatusLevel | string; className?: string }) {
  const m = statusMeta(status);
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium', m.cls, className)}>
      <span className={cn('h-1.5 w-1.5 rounded-full', m.dot)} />
      {m.label}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const m = SEVERITY_META[severity];
  return (
    <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide', m.cls)}>
      {m.label}
    </span>
  );
}

export function flagEmoji(cc: string | undefined | null): string {
  if (!cc || cc.length !== 2 || !/^[a-z]{2}$/i.test(cc)) return '🌐';
  return cc.toUpperCase().replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)));
}

// ---------------------------------------------------------------- DNS Record & IP Badges

export const DNS_RECORD_META: Record<string, { label: string; description: string; cls: string; dot: string }> = {
  A: {
    label: 'A Record (Address)',
    description: 'Maps a hostname directly to a 32-bit IPv4 address (e.g. 192.0.2.1).',
    cls: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30 hover:bg-blue-500/20',
    dot: 'bg-blue-500',
  },
  AAAA: {
    label: 'AAAA Record (IPv6 Address)',
    description: 'Maps a hostname to a 128-bit IPv6 address (e.g. 2606:4700::6815:172d).',
    cls: 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/30 hover:bg-indigo-500/20',
    dot: 'bg-indigo-500',
  },
  CNAME: {
    label: 'CNAME Record (Canonical Name)',
    description: 'An alias that points this hostname to another domain name.',
    cls: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30 hover:bg-purple-500/20',
    dot: 'bg-purple-500',
  },
  MX: {
    label: 'MX Record (Mail Exchange)',
    description: 'Directs email to the mail servers responsible for accepting messages on this domain.',
    cls: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20',
    dot: 'bg-emerald-500',
  },
  TXT: {
    label: 'TXT Record (Text)',
    description: 'Holds machine-readable text used for SPF authentication, DKIM keys, DMARC policies, and verification tokens.',
    cls: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30 hover:bg-amber-500/20',
    dot: 'bg-amber-500',
  },
  NS: {
    label: 'NS Record (Name Server)',
    description: 'Delegates authority for this DNS zone to authoritative nameservers.',
    cls: 'bg-teal-500/10 text-teal-600 dark:text-teal-400 border-teal-500/30 hover:bg-teal-500/20',
    dot: 'bg-teal-500',
  },
  SOA: {
    label: 'SOA Record (Start of Authority)',
    description: 'Zone administrative metadata: primary nameserver, admin email, zone serial, refresh, retry, and expire timers.',
    cls: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30 hover:bg-rose-500/20',
    dot: 'bg-rose-500',
  },
  CAA: {
    label: 'CAA Record (Certificate Authority Authorization)',
    description: 'Specifies which Certificate Authorities (CAs) are authorized to issue SSL/TLS certificates for this domain.',
    cls: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30 hover:bg-cyan-500/20',
    dot: 'bg-cyan-500',
  },
  PTR: {
    label: 'PTR Record (Pointer / Reverse DNS)',
    description: 'Resolves an IP address back to its associated domain name (Reverse DNS lookup).',
    cls: 'bg-violet-500/10 text-violet-600 dark:text-violet-400 border-violet-500/30 hover:bg-violet-500/20',
    dot: 'bg-violet-500',
  },
  SRV: {
    label: 'SRV Record (Service)',
    description: 'Specifies the hostname and port number for servers providing specific services (SIP, XMPP, LDAP).',
    cls: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30 hover:bg-orange-500/20',
    dot: 'bg-orange-500',
  },
  DNSKEY: {
    label: 'DNSKEY Record (DNSSEC Key)',
    description: 'Public cryptographic signing key used to validate DNSSEC RRSIG signatures.',
    cls: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-500/30 hover:bg-yellow-500/20',
    dot: 'bg-yellow-500',
  },
  DS: {
    label: 'DS Record (Delegation Signer)',
    description: 'Cryptographic digest of DNSKEY placed in the parent zone to establish the DNSSEC chain of trust.',
    cls: 'bg-lime-500/10 text-lime-600 dark:text-lime-400 border-lime-500/30 hover:bg-lime-500/20',
    dot: 'bg-lime-500',
  },
  RRSIG: {
    label: 'RRSIG Record (DNSSEC Signature)',
    description: 'Cryptographic digital signature securing a resource record set against DNS spoofing and cache poisoning.',
    cls: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20',
    dot: 'bg-emerald-500',
  },
  TLSA: {
    label: 'TLSA Record (DANE)',
    description: 'DANE association binding a certificate or public key to a service port.',
    cls: 'bg-fuchsia-500/10 text-fuchsia-600 dark:text-fuchsia-400 border-fuchsia-500/30 hover:bg-fuchsia-500/20',
    dot: 'bg-fuchsia-500',
  },
  HTTPS: {
    label: 'HTTPS Record',
    description: 'Provides transport parameters (HTTP/2, HTTP/3, ECH) and IP addresses for secure connections.',
    cls: 'bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/30 hover:bg-sky-500/20',
    dot: 'bg-sky-500',
  },
};

export function DnsRecordBadge({
  type,
  showTooltip = true,
  className,
}: {
  type: string;
  showTooltip?: boolean;
  className?: string;
}) {
  const upper = type.toUpperCase();
  const meta = DNS_RECORD_META[upper] || {
    label: `${upper} Record`,
    description: `DNS resource record of type ${upper}.`,
    cls: 'bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border-zinc-500/30 hover:bg-zinc-500/20',
    dot: 'bg-zinc-400',
  };

  const badge = (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11.5px] font-bold tracking-wide transition-colors select-none',
        meta.cls,
        className,
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', meta.dot)} />
      {upper}
    </span>
  );

  if (!showTooltip) return badge;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="cursor-help inline-block">{badge}</span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-left">
        <p className="font-semibold text-xs">{meta.label}</p>
        <p className="mt-0.5 text-[11px] text-muted-foreground leading-normal">{meta.description}</p>
      </TooltipContent>
    </Tooltip>
  );
}

export function IpBadge({
  ip,
  version,
  copyable = true,
  className,
}: {
  ip: string;
  version?: 4 | 6;
  copyable?: boolean;
  className?: string;
}) {
  const isV6 = version === 6 || (version === undefined && ip.includes(':'));
  const vLabel = isV6 ? 'IPv6' : 'IPv4';
  const vCls = isV6
    ? 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/30'
    : 'bg-blue-500/15 text-blue-700 dark:text-blue-300 border-blue-500/30';

  return (
    <div
      className={cn(
        'inline-flex items-center gap-1.5 rounded-lg border border-border/80 bg-muted/40 px-2 py-0.5 text-xs transition-colors hover:bg-muted/70',
        className,
      )}
    >
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className={cn(
              'rounded px-1 py-0.2 font-mono text-[9.5px] font-bold uppercase tracking-wider border cursor-help select-none',
              vCls,
            )}
          >
            {vLabel}
          </span>
        </TooltipTrigger>
        <TooltipContent side="top">
          <p className="font-semibold">{isV6 ? 'Internet Protocol Version 6' : 'Internet Protocol Version 4'}</p>
          <p className="text-[11px] text-muted-foreground">
            {isV6 ? '128-bit hexadecimal address' : '32-bit dot-decimal numerical address'}
          </p>
        </TooltipContent>
      </Tooltip>
      <span className="font-mono text-[12px] font-medium tracking-tight text-foreground select-all">{ip}</span>
      {copyable ? <CopyButton value={ip} ariaLabel={`Copy ${ip}`} className="h-5 w-5 p-0.5 shrink-0 text-muted-foreground hover:text-foreground" /> : null}
    </div>
  );
}

// ---------------------------------------------------------------- copy

export function CopyButton({
  value,
  label,
  ariaLabel,
  className,
}: {
  value: string;
  label?: string;
  ariaLabel?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn('h-7 px-2 text-xs text-muted-foreground hover:text-foreground', className)}
      aria-label={ariaLabel || (label ? `Copy ${label}` : 'Copy value')}
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch { /* clipboard unavailable */ }
      }}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
      {label ? <span className="ml-1">{label}</span> : null}
    </Button>
  );
}

// ---------------------------------------------------------------- cards

export function SectionCard({
  title, description, icon, actions, children, className,
}: {
  title: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn('gap-4', className)}>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base font-semibold">
            {icon}
            {title}
          </CardTitle>
          {description ? <CardDescription>{description}</CardDescription> : null}
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-1">{actions}</div> : null}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

export interface InfoItem {
  label: string;
  value: ReactNode;
  mono?: boolean;
  status?: StatusLevel | string;
  copy?: string;
}

export function InfoGrid({ items, cols = 2 }: { items: InfoItem[]; cols?: 2 | 3 | 4 }) {
  return (
    <div className={cn(
      'grid gap-3',
      cols === 2 && 'grid-cols-1 sm:grid-cols-2',
      cols === 3 && 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
      cols === 4 && 'grid-cols-2 lg:grid-cols-4',
    )}>
      {items.map((item) => (
        <div key={item.label} className="rounded-lg border bg-muted/30 px-3 py-2.5">
          <div className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{item.label}</div>
          <div className={cn('mt-1 flex items-center gap-1.5 text-sm', item.mono && 'font-mono text-[13px] break-all')}>
            {item.status ? <StatusBadge status={item.status} /> : null}
            <span className={cn(!item.value && item.value !== 0 ? 'text-muted-foreground' : '')}>
              {item.value === null || item.value === undefined || item.value === '' ? '—' : item.value}
            </span>
            {item.copy ? <CopyButton value={item.copy} /> : null}
          </div>
        </div>
      ))}
    </div>
  );
}

export function LoadingCards({ count = 4, className }: { count?: number; className?: string }) {
  return (
    <div className={cn('grid gap-4 sm:grid-cols-2', className)}>
      {Array.from({ length: count }).map((_, i) => (
        <Skeleton key={i} className="h-28 w-full rounded-xl" />
      ))}
    </div>
  );
}

export function LoadingRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full rounded-md" />
      ))}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-red-500/30 bg-red-500/5 px-6 py-10 text-center">
      <AlertTriangle className="h-8 w-8 text-red-500" />
      <p className="max-w-md text-sm text-muted-foreground">{message}</p>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="mr-2 h-3.5 w-3.5" /> Retry
        </Button>
      ) : null}
    </div>
  );
}

export function EmptyState({ icon, title, description }: { icon?: ReactNode; title: string; description?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed px-6 py-10 text-center">
      {icon ? <div className="text-muted-foreground">{icon}</div> : null}
      <p className="text-sm font-medium">{title}</p>
      {description ? <p className="max-w-md text-xs text-muted-foreground">{description}</p> : null}
    </div>
  );
}

export function Spinner() {
  return <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />;
}

// ---------------------------------------------------------------- tables

export interface TableColumn {
  key: string;
  header: string;
  className?: string;
  mono?: boolean;
}

export function DataTable({
  columns,
  rows,
  empty = 'No data',
}: {
  columns: TableColumn[];
  rows: (Record<string, ReactNode> & { _key: string })[];
  empty?: string;
}) {
  if (!rows.length) {
    return <EmptyState title={empty} />;
  }
  return (
    <div className="max-h-96 overflow-auto rounded-lg border">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-muted/95 backdrop-blur">
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={cn('whitespace-nowrap px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wide text-muted-foreground', c.className)}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row._key} className="border-t transition-colors hover:bg-muted/40">
              {columns.map((c) => (
                <td key={c.key} className={cn('px-3 py-2 align-top', c.mono && 'font-mono text-[12.5px] break-words [word-break:break-word]', c.className)}>
                  {row[c.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------- findings

export function FindingList({ findings, limit }: { findings: { id: string; title: string; severity: Severity; description: string; recommendation?: string; reference?: string }[]; limit?: number }) {
  const list = limit ? findings.slice(0, limit) : findings;
  if (!list.length) {
    return <EmptyState title="No findings" description="Nothing to report for this section." />;
  }
  return (
    <ul className="space-y-2.5">
      {list.map((f) => (
        <li key={f.id} className="rounded-lg border px-3.5 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <span className="text-sm font-medium">{f.title}</span>
          </div>
          <p className="mt-1 text-[13px] leading-relaxed text-muted-foreground">{f.description}</p>
          {f.recommendation ? (
            <p className="mt-1.5 text-[13px] leading-relaxed">
              <span className="font-medium text-emerald-600 dark:text-emerald-400">Fix: </span>
              {f.recommendation}
            </p>
          ) : null}
          {f.reference ? (
            <a href={f.reference} target="_blank" rel="noreferrer" className="mt-1 inline-block text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground">
              Reference documentation ↗
            </a>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------- raw viewer

export function RawViewer({ data }: { data: unknown }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between px-3 py-2 text-xs font-medium text-muted-foreground hover:text-foreground"
        aria-expanded={open}
      >
        <span>Raw response (JSON)</span>
        <ChevronDown className={cn('h-4 w-4 transition-transform', open && 'rotate-180')} />
      </button>
      {open ? (
        <pre className="max-h-96 overflow-auto border-t bg-muted/40 p-3 font-mono text-[11.5px] leading-relaxed">
          {JSON.stringify(data, null, 2)}
        </pre>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------- module shell

export function ModuleShell({
  title, description, icon, loading, error, onRetry, lastChecked, onRefresh, rawData, actions, children,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  loading: boolean;
  error?: string;
  onRetry?: () => void;
  lastChecked?: string;
  onRefresh?: () => void;
  rawData?: unknown;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            {icon}
            {title}
          </h2>
          {description ? <p className="mt-0.5 max-w-2xl text-[13px] text-muted-foreground">{description}</p> : null}
        </div>
        <div className="flex items-center gap-2">
          {actions}
          {lastChecked ? (
            <span className="flex items-center gap-1 text-[11px] text-muted-foreground" title="Last checked">
              <Clock className="h-3 w-3" />
              {new Date(lastChecked).toLocaleTimeString()}
            </span>
          ) : null}
          {onRefresh ? (
            <Button variant="outline" size="sm" onClick={onRefresh} disabled={loading} aria-label="Refresh module">
              <RefreshCw className={cn('mr-1.5 h-3.5 w-3.5', loading && 'animate-spin')} />
              Refresh
            </Button>
          ) : null}
        </div>
      </div>
      {loading ? (
        <LoadingCards count={4} />
      ) : error ? (
        <ErrorState message={error} onRetry={onRetry} />
      ) : (
        <>
          {children}
          {rawData !== undefined ? <RawViewer data={rawData} /> : null}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- score ring

export function ScoreRing({ score, grade, size = 140 }: { score: number; grade: string; size?: number }) {
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const color = score >= 75 ? '#10b981' : score >= 50 ? '#f59e0b' : '#ef4444';
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} strokeWidth={10} className="stroke-muted" fill="none" />
        <circle
          cx={size / 2} cy={size / 2} r={radius} strokeWidth={10} fill="none"
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - pct)}
          strokeLinecap="round"
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold tabular-nums" style={{ color }}>{score}</span>
        <span className="text-xs text-muted-foreground">Grade {grade}</span>
      </div>
    </div>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('font-mono text-[12.5px] break-all', className)}>{children}</span>;
}

export { Badge };
