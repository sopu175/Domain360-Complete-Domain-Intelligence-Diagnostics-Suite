'use client';

import { Check, Settings, Star } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

interface PlanRow {
  feature: string;
  free: string | boolean;
  pro: string | boolean;
  business: string | boolean;
}

const PLAN_MATRIX: PlanRow[] = [
  { feature: 'Basic DNS lookups (A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, PTR, SRV)', free: 'Unlimited*', pro: true, business: true },
  { feature: 'Advanced DNS records (DNSKEY, RRSIG, TLSA, SVCB, HTTPS, LOC…)', free: true, pro: true, business: true },
  { feature: 'Custom resolver selection + DoH fallback', free: true, pro: true, business: true },
  { feature: 'WHOIS / RDAP lookup', free: true, pro: true, business: true },
  { feature: 'SSL/TLS checker', free: true, pro: true, business: true },
  { feature: 'IP & hosting intelligence', free: true, pro: true, business: true },
  { feature: 'HTTP status & headers', free: true, pro: true, business: true },
  { feature: 'Email security (SPF/DKIM/DMARC + score)', free: true, pro: true, business: true },
  { feature: 'Global DNS propagation (14 public resolvers)', free: true, pro: true, business: true },
  { feature: 'DNSSEC analyzer with chain validation', free: true, pro: true, business: true },
  { feature: 'Subdomain discovery (CT logs + wordlist)', free: '300 results', pro: '1,000 results', business: '5,000 results' },
  { feature: 'Domain comparison', free: true, pro: true, business: true },
  { feature: 'JSON / CSV export & print-to-PDF', free: true, pro: true, business: true },
  { feature: 'Zone-transfer (AXFR) exposure check', free: 'With authorization', pro: true, business: true },
  { feature: 'Scan history', free: true, pro: true, business: true },
  { feature: 'Bulk domain analysis', free: false, pro: false, business: '50 domains' },
  { feature: 'Scheduled monitoring & alerts (SSL expiry, DNS change)', free: false, pro: 'Roadmap', business: true },
  { feature: 'Team accounts & permissions', free: false, pro: false, business: 'Roadmap' },
  { feature: 'Public API access & webhooks', free: false, pro: true, business: true },
];

function Cell({ value }: { value: string | boolean }) {
  if (value === true) return <Check className="mx-auto h-4 w-4 text-emerald-600 dark:text-emerald-400" aria-label="Included" />;
  if (value === false) return <span className="text-muted-foreground" aria-label="Not included">—</span>;
  return <span className="text-xs">{value}</span>;
}

export function SettingsTab() {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          <Settings className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
          Settings & Plans
        </h2>
        <p className="mt-0.5 text-[13px] text-muted-foreground">
          Theme preference, plan information and fair-use limits.
        </p>
      </div>

      <div className="rounded-xl border bg-card p-4">
        <p className="text-sm font-semibold">Appearance</p>
        <p className="mt-1 text-[12.5px] text-muted-foreground">
          Switch between light and dark mode with the moon/sun button in the header. The preference follows your system theme by default.
        </p>
      </div>

      <div className="rounded-xl border bg-card p-4">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-sm font-semibold">Current plan: Free</p>
          <Badge className="bg-emerald-600 text-white hover:bg-emerald-600">Active</Badge>
        </div>
        <p className="mt-1 text-[12.5px] leading-relaxed text-muted-foreground">
          Pro and Business tiers are shown below for transparency but are <span className="font-medium text-foreground">not purchasable in this deployment</span> — no payment provider is configured, so we don&apos;t pretend paid features are active. The free tier is fully usable, subject to per-minute fair-use limits (DNS 60/min, propagation 8/min, heavy scans 8–20/min).
        </p>
      </div>

      <div className="overflow-x-auto rounded-xl border">
        <table className="w-full min-w-[680px] text-sm">
          <thead>
            <tr className="border-b bg-muted/50">
              <th className="px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Feature</th>
              <th className="w-24 px-3 py-2.5 text-center text-[11px] font-semibold uppercase tracking-wide text-emerald-600 dark:text-emerald-400">Free</th>
              <th className="w-24 px-3 py-2.5 text-center text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                <span className="inline-flex items-center gap-1"><Star className="h-3 w-3" /> Pro</span>
              </th>
              <th className="w-28 px-3 py-2.5 text-center text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Business</th>
            </tr>
          </thead>
          <tbody>
            {PLAN_MATRIX.map((row) => (
              <tr key={row.feature} className="border-t">
                <td className="px-3 py-2 text-[13px]">{row.feature}</td>
                <td className={cn('px-3 py-2 text-center')}><Cell value={row.free} /></td>
                <td className="px-3 py-2 text-center"><Cell value={row.pro} /></td>
                <td className="px-3 py-2 text-center"><Cell value={row.business} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-[11.5px] leading-relaxed text-muted-foreground">
        * DNS lookups are limited to 60/minute per client for abuse protection. All diagnostics run server-side with SSRF protection (private IP ranges and cloud-metadata endpoints are blocked), outbound ports are restricted to 53/80/443, and destructive testing is never performed. The AXFR check only runs after explicit authorization.
      </p>
    </div>
  );
}
