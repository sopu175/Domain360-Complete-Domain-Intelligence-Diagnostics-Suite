'use client';

import { useEffect, useState } from 'react';
import { useTheme } from 'next-themes';
import {
  Activity, ArrowRight, CornerDownLeft, FileBarChart2, FileSearch,
  Gauge, GitBranch, Globe2, History, KeyRound, Mail, MapPin, Moon,
  Network, Scale, Search, Server, Settings, ShieldAlert, ShieldCheck, Sun, Trash2,
} from 'lucide-react';
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command';
import { useStore, type TabId } from '@/lib/domain360/store';
import { NAV_ITEMS } from '@/components/domain360/module-nav';

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [query, setQuery] = useState('');
  const { resolvedTheme, setTheme } = useTheme();

  const domain = useStore((s) => s.domain);
  const recents = useStore((s) => s.recents);
  const runScan = useStore((s) => s.runScan);
  const setActiveTab = useStore((s) => s.setActiveTab);
  const clearAll = useStore((s) => s.clearAll);

  // Global Cmd+K / Ctrl+K keyboard shortcut
  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        onOpenChange(!open);
      }
    };
    window.addEventListener('keydown', down);
    return () => window.removeEventListener('keydown', down);
  }, [open, onOpenChange]);

  const handleScan = (targetDomain: string) => {
    const clean = targetDomain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (clean) {
      onOpenChange(false);
      setQuery('');
      void runScan(clean);
    }
  };

  const handleSelectTab = (tabId: TabId) => {
    setActiveTab(tabId);
    onOpenChange(false);
    setQuery('');
  };

  const isDomainQuery = query.includes('.') && !query.includes(' ') && query.length >= 3;

  return (
    <CommandDialog
      open={open}
      onOpenChange={(val) => {
        onOpenChange(val);
        if (!val) setQuery('');
      }}
      title="Domain360 Command Palette"
      description="Search domains, jump across diagnostic tabs, or trigger quick actions"
    >
      <CommandInput
        placeholder="Type a domain to scan, or jump to a module..."
        value={query}
        onValueChange={setQuery}
      />
      <CommandList>
        <CommandEmpty>No matching modules or actions found.</CommandEmpty>

        {/* Dynamic Scan Trigger if query looks like a domain */}
        {isDomainQuery && (
          <CommandGroup heading="Scan Target Domain">
            <CommandItem
              onSelect={() => handleScan(query)}
              className="flex items-center justify-between cursor-pointer py-2.5 font-medium"
            >
              <div className="flex items-center gap-2">
                <Search className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                <span>
                  Scan <span className="font-mono font-semibold text-emerald-600 dark:text-emerald-400">{query.trim()}</span>
                </span>
              </div>
              <CornerDownLeft className="h-3.5 w-3.5 text-muted-foreground" />
            </CommandItem>
          </CommandGroup>
        )}

        {/* Diagnostic Tabs Navigation */}
        <CommandGroup heading={domain ? `Diagnostic Modules for ${domain}` : 'Diagnostic Modules'}>
          {NAV_ITEMS.map((item) => (
            <CommandItem
              key={item.id}
              value={item.label}
              onSelect={() => handleSelectTab(item.id)}
              className="flex items-center justify-between cursor-pointer"
            >
              <div className="flex items-center gap-2">
                <item.icon className="h-4 w-4 text-muted-foreground" />
                <span>{item.label}</span>
              </div>
              <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-60" />
            </CommandItem>
          ))}
        </CommandGroup>

        <CommandSeparator />

        {/* Recent Searches */}
        {recents.length > 0 && (
          <CommandGroup heading="Recent Domains">
            {recents.slice(0, 5).map((d) => (
              <CommandItem
                key={d}
                value={`recent ${d}`}
                onSelect={() => handleScan(d)}
                className="flex items-center justify-between cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <History className="h-4 w-4 text-muted-foreground" />
                  <span className="font-mono text-xs">{d}</span>
                </div>
                <span className="text-[10px] text-muted-foreground uppercase">Scan</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}

        <CommandSeparator />

        {/* Quick Utility Actions */}
        <CommandGroup heading="System & Actions">
          <CommandItem
            onSelect={() => {
              setTheme(resolvedTheme === 'dark' ? 'light' : 'dark');
              onOpenChange(false);
            }}
            className="flex items-center justify-between cursor-pointer"
          >
            <div className="flex items-center gap-2">
              {resolvedTheme === 'dark' ? <Sun className="h-4 w-4 text-amber-500" /> : <Moon className="h-4 w-4 text-blue-500" />}
              <span>Toggle Dark / Light Theme</span>
            </div>
            <span className="text-xs text-muted-foreground capitalize">{resolvedTheme || 'System'}</span>
          </CommandItem>

          {domain && (
            <CommandItem
              onSelect={() => {
                clearAll();
                onOpenChange(false);
              }}
              className="flex items-center justify-between cursor-pointer text-red-500 dark:text-red-400"
            >
              <div className="flex items-center gap-2">
                <Trash2 className="h-4 w-4" />
                <span>Clear Scanned Domain (Back to Home)</span>
              </div>
            </CommandItem>
          )}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}

