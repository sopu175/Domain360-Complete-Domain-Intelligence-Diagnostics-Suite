'use client';

import { useTheme } from 'next-themes';
import { Globe2, Moon, Sun } from 'lucide-react';
import { Button } from '@/components/ui/button';

export function SiteHeader() {
  const { resolvedTheme, setTheme } = useTheme();

  return (
    <header className="sticky top-0 z-40 border-b bg-background/85 backdrop-blur supports-[backdrop-filter]:bg-background/70">
      <div className="mx-auto flex h-14 w-full max-w-7xl items-center justify-between gap-3 px-4 sm:px-6">
        <button
          type="button"
          className="flex items-center gap-2.5"
          onClick={() => window.dispatchEvent(new CustomEvent('domain360:home'))}
          aria-label="Domain360 home"
        >
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-600 text-white shadow-sm">
            <Globe2 className="h-4.5 w-4.5" />
          </span>
          <span className="text-[15px] font-bold tracking-tight">
            Domain<span className="text-emerald-600 dark:text-emerald-400">360</span>
          </span>
          <span className="hidden rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground sm:inline-block">
            Domain Intelligence
          </span>
        </button>
        <div className="flex items-center gap-2">
          <span className="hidden rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-400 md:inline-block">
            Free plan — no signup
          </span>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Toggle dark mode"
            onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}
          >
            <Sun className="h-4.5 w-4.5 dark:hidden" />
            <Moon className="hidden h-4.5 w-4.5 dark:block" />
          </Button>
        </div>
      </div>
    </header>
  );
}
