'use client';

import { useState } from 'react';
import { useTheme } from 'next-themes';
import { Globe2, Moon, Search, Sun } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { CommandPalette } from '@/components/domain360/command-palette';

export function SiteHeader() {
  const { resolvedTheme, setTheme } = useTheme();
  const [paletteOpen, setPaletteOpen] = useState(false);

  return (
    <>
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
        <div className="mx-auto flex h-14 w-full max-w-7xl items-center justify-between gap-3 px-4 sm:px-6">
          <button
            type="button"
            className="flex items-center gap-2.5 transition-opacity hover:opacity-90"
            onClick={() => window.dispatchEvent(new CustomEvent('domain360:home'))}
            aria-label="Domain360 home"
          >
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-600 text-white shadow-xs">
              <Globe2 className="h-4.5 w-4.5" />
            </span>
            <span className="text-[15px] font-bold tracking-tight">
              Domain<span className="text-emerald-600 dark:text-emerald-400">360</span>
            </span>
            <span className="hidden rounded-full border border-border/80 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground sm:inline-block">
              Domain Intelligence
            </span>
          </button>

          <div className="flex items-center gap-2">
            {/* Quick Command Palette Button */}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPaletteOpen(true)}
              className="flex h-8 items-center gap-2 rounded-lg border-border/80 px-2.5 text-xs text-muted-foreground shadow-xs hover:border-emerald-500/40 hover:text-foreground"
              aria-label="Open command palette"
            >
              <Search className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Search or jump to...</span>
              <kbd className="pointer-events-none hidden rounded border bg-muted px-1.5 py-0.5 font-mono text-[10px] font-semibold text-muted-foreground sm:inline-block">
                ⌘K
              </kbd>
            </Button>

            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              aria-label="Toggle dark mode"
              onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}
            >
              <Sun className="h-4 w-4 dark:hidden" />
              <Moon className="hidden h-4 w-4 dark:block" />
            </Button>
          </div>
        </div>
      </header>

      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </>
  );
}
