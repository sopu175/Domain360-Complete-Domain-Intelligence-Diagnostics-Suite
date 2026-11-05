'use client';

import {
  Activity, FileBarChart2, FileSearch, Gauge, GitBranch, Globe2, KeyRound,
  Mail, MapPin, Network, Scale, Server, Settings, ShieldAlert, ShieldCheck,
} from 'lucide-react';
import { useStore, type TabId } from '@/lib/domain360/store';
import { cn } from '@/lib/utils';

export const NAV_ITEMS: { id: TabId; label: string; icon: typeof Gauge }[] = [
  { id: 'overview', label: 'Overview', icon: Gauge },
  { id: 'dns', label: 'DNS', icon: Network },
  { id: 'propagation', label: 'Propagation', icon: Globe2 },
  { id: 'nameservers', label: 'Nameservers', icon: Server },
  { id: 'ip', label: 'IP & Hosting', icon: MapPin },
  { id: 'ssl', label: 'SSL / TLS', icon: ShieldCheck },
  { id: 'whois', label: 'WHOIS / RDAP', icon: FileSearch },
  { id: 'email', label: 'Email', icon: Mail },
  { id: 'security', label: 'Security', icon: ShieldAlert },
  { id: 'http', label: 'HTTP', icon: Activity },
  { id: 'subdomains', label: 'Subdomains', icon: GitBranch },
  { id: 'dnssec', label: 'DNSSEC', icon: KeyRound },
  { id: 'compare', label: 'Compare', icon: Scale },
  { id: 'reports', label: 'Reports', icon: FileBarChart2 },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export function ModuleNav() {
  const activeTab = useStore((s) => s.activeTab);
  const setActiveTab = useStore((s) => s.setActiveTab);

  return (
    <nav aria-label="Diagnostic modules" className="sticky top-14 z-30 -mx-4 border-b bg-background/90 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/75 sm:-mx-6 sm:px-6">
      <div className="scrollbar-thin flex gap-1 overflow-x-auto py-2" role="tablist">
        {NAV_ITEMS.map((item) => {
          const active = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setActiveTab(item.id)}
              className={cn(
                'flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-[13px] font-medium transition-colors',
                active
                  ? 'bg-emerald-600 text-white shadow-sm'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground',
              )}
            >
              <item.icon className="h-3.5 w-3.5" />
              {item.label}
            </button>
          );
        })}
      </div>
    </nav>
  );
}
