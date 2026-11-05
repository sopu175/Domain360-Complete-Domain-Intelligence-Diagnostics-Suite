'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import {
  Activity, ChevronLeft, ChevronRight, FileBarChart2, FileSearch, Gauge, GitBranch, Globe2, KeyRound,
  Mail, MapPin, Network, Scale, Server, ShieldAlert, ShieldCheck,
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
];

export function ModuleNav() {
  const activeTab = useStore((s) => s.activeTab);
  const setActiveTab = useStore((s) => s.setActiveTab);
  const scrollRef = useRef<HTMLDivElement>(null);

  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);

  const checkScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    setCanScrollLeft(el.scrollLeft > 4);
    setCanScrollRight(el.scrollLeft + el.clientWidth < el.scrollWidth - 4);
  }, []);

  useEffect(() => {
    checkScroll();
    window.addEventListener('resize', checkScroll);
    return () => window.removeEventListener('resize', checkScroll);
  }, [checkScroll]);

  // Center the active tab in view whenever activeTab changes
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const activeEl = el.querySelector<HTMLButtonElement>(`[data-tab-id="${activeTab}"]`);
    if (activeEl) {
      activeEl.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    }
    // Re-evaluate scroll boundaries after scrolling
    setTimeout(checkScroll, 350);
  }, [activeTab, checkScroll]);

  const handleScroll = (direction: 'left' | 'right') => {
    const el = scrollRef.current;
    if (!el) return;
    const offset = direction === 'left' ? -280 : 280;
    el.scrollBy({ left: offset, behavior: 'smooth' });
    setTimeout(checkScroll, 300);
  };

  return (
    <nav
      aria-label="Diagnostic modules"
      className="sticky top-14 z-40 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80"
    >
      <div className="relative mx-auto flex w-full max-w-7xl items-center px-4 sm:px-6">
        {/* Left scroll chevron */}
        {canScrollLeft && (
          <button
            type="button"
            onClick={() => handleScroll('left')}
            className="absolute left-2 z-10 hidden h-7 w-7 items-center justify-center rounded-full border bg-background/90 text-muted-foreground shadow-xs backdrop-blur hover:text-foreground md:flex"
            aria-label="Scroll navigation left"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
        )}

        {/* Left fade gradient */}
        <div
          className={cn(
            'pointer-events-none absolute left-4 top-0 bottom-0 z-[5] w-6 bg-gradient-to-r from-background to-transparent transition-opacity sm:left-6',
            canScrollLeft ? 'opacity-100' : 'opacity-0',
          )}
        />

        {/* Horizontal tabs */}
        <div
          ref={scrollRef}
          onScroll={checkScroll}
          className="scrollbar-none flex w-full gap-1.5 overflow-x-auto py-2.5"
          role="tablist"
        >
          {NAV_ITEMS.map((item) => {
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                data-tab-id={item.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setActiveTab(item.id)}
                className={cn(
                  'flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-[13px] font-medium transition-all select-none',
                  active
                    ? 'bg-emerald-600 font-semibold text-white shadow-xs'
                    : 'text-muted-foreground hover:bg-muted/70 hover:text-foreground',
                )}
              >
                <item.icon className="h-3.5 w-3.5" />
                {item.label}
              </button>
            );
          })}
        </div>

        {/* Right fade gradient */}
        <div
          className={cn(
            'pointer-events-none absolute right-4 top-0 bottom-0 z-[5] w-6 bg-gradient-to-l from-background to-transparent transition-opacity sm:right-6',
            canScrollRight ? 'opacity-100' : 'opacity-0',
          )}
        />

        {/* Right scroll chevron */}
        {canScrollRight && (
          <button
            type="button"
            onClick={() => handleScroll('right')}
            className="absolute right-2 z-10 hidden h-7 w-7 items-center justify-center rounded-full border bg-background/90 text-muted-foreground shadow-xs backdrop-blur hover:text-foreground md:flex"
            aria-label="Scroll navigation right"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        )}
      </div>
    </nav>
  );
}
