'use client';

import { useState, type ReactNode } from 'react';
import { Check, ChevronDown, Copy, Loader2, RefreshCw, AlertTriangle, Clock } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
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

// ---------------------------------------------------------------- copy

export function CopyButton({ value, label, className }: { value: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn('h-7 px-2 text-xs text-muted-foreground hover:text-foreground', className)}
      aria-label={label ? `Copy ${label}` : 'Copy value'}
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
                <td key={c.key} className={cn('px-3 py-2 align-top', c.mono && 'font-mono text-[12.5px] break-all', c.className)}>
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
