'use client';

import { useEffect, useRef } from 'react';
import { AnimatePresence } from 'framer-motion';
import { Globe2 } from 'lucide-react';
import { SiteHeader } from '@/components/domain360/site-header';
import { SearchHero } from '@/components/domain360/search-hero';
import { ScanProgress } from '@/components/domain360/scan-progress';
import { ModuleNav } from '@/components/domain360/module-nav';
import { initRecents, useStore } from '@/lib/domain360/store';
import { OverviewTab } from '@/components/domain360/overview-tab';
import { DnsTab } from '@/components/domain360/dns-tab';
import { PropagationTab } from '@/components/domain360/propagation-tab';
import { NameserversTab } from '@/components/domain360/nameservers-tab';
import { IpTab } from '@/components/domain360/ip-tab';
import { SslTab } from '@/components/domain360/ssl-tab';
import { WhoisTab } from '@/components/domain360/whois-tab';
import { EmailTab } from '@/components/domain360/email-tab';
import { SecurityTab } from '@/components/domain360/security-tab';
import { HttpTab } from '@/components/domain360/http-tab';
import { SubdomainsTab } from '@/components/domain360/subdomains-tab';
import { DnssecTab } from '@/components/domain360/dnssec-tab';
import { CompareTab } from '@/components/domain360/compare-tab';
import { ReportsTab } from '@/components/domain360/reports-tab';

function TabContent() {
  const activeTab = useStore((s) => s.activeTab);
  switch (activeTab) {
    case 'overview': return <OverviewTab />;
    case 'dns': return <DnsTab />;
    case 'propagation': return <PropagationTab />;
    case 'nameservers': return <NameserversTab />;
    case 'ip': return <IpTab />;
    case 'ssl': return <SslTab />;
    case 'whois': return <WhoisTab />;
    case 'email': return <EmailTab />;
    case 'security': return <SecurityTab />;
    case 'http': return <HttpTab />;
    case 'subdomains': return <SubdomainsTab />;
    case 'dnssec': return <DnssecTab />;
    case 'compare': return <CompareTab />;
    case 'reports': return <ReportsTab />;
    default: return <OverviewTab />;
  }
}

export default function Home() {
  const domain = useStore((s) => s.domain);
  const activeTab = useStore((s) => s.activeTab);
  const runScan = useStore((s) => s.runScan);
  const clearAll = useStore((s) => s.clearAll);
  const bootstrapped = useRef(false);

  useEffect(() => {
    if (!bootstrapped.current) {
      bootstrapped.current = true;
      initRecents();
      const sp = new URLSearchParams(window.location.search);
      const d = sp.get('domain');
      if (d) void runScan(d);
    }
  }, [runScan]);

  // keep URL shareable
  useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    if (domain) {
      if (sp.get('domain') !== domain) {
        sp.set('domain', domain);
        if (activeTab !== 'overview') sp.set('tab', activeTab); else sp.delete('tab');
        window.history.replaceState(null, '', `/?${sp.toString()}`);
      }
    } else if (sp.has('domain')) {
      window.history.replaceState(null, '', '/');
    }
  }, [domain, activeTab]);

  useEffect(() => {
    const onHome = () => clearAll();
    window.addEventListener('domain360:home', onHome);
    return () => window.removeEventListener('domain360:home', onHome);
  }, [clearAll]);

  return (
    <div className="flex min-h-screen flex-col">
      <SiteHeader />

      {!domain ? (
        <main className="flex-1">
          <SearchHero />
        </main>
      ) : (
        <>
          <ModuleNav />
          <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6">
            <div className="space-y-5">
              <ScanProgress />
              <AnimatePresence mode="wait">
                <TabContent />
              </AnimatePresence>
            </div>
          </main>
        </>
      )}

      <footer className="mt-auto border-t bg-muted/30">
        <div className="mx-auto flex w-full max-w-7xl flex-col items-center justify-between gap-2 px-4 py-4 text-xs text-muted-foreground sm:flex-row sm:px-6">
          <p className="flex items-center gap-1.5">
            <Globe2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
            Domain360 — passive domain diagnostics. Scores are informational and not a certified security assessment.
          </p>
          <p>Live DNS · TLS · RDAP · HTTP checks · No mock data</p>
        </div>
      </footer>
    </div>
  );
}
