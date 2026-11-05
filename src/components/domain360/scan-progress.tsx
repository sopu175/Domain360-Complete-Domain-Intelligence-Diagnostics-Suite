'use client';

import { AnimatePresence, motion } from 'framer-motion';
import { Check, Loader2, X } from 'lucide-react';
import { useStore } from '@/lib/domain360/store';
import { cn } from '@/lib/utils';

export function ScanProgress() {
  const stages = useStore((s) => s.stages);
  const scanning = useStore((s) => s.scanning);
  if (!stages.length || (!scanning && stages.every((s) => s.status === 'done'))) return null;

  const done = stages.filter((s) => s.status === 'done').length;

  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, height: 0 }}
      className="rounded-xl border bg-card p-4"
    >
      <div className="mb-3 flex items-center justify-between">
        <p className="text-sm font-semibold">
          Running diagnostics{scanning ? '…' : ' — finished'}
        </p>
        <span className="text-xs tabular-nums text-muted-foreground">{done}/{stages.length}</span>
      </div>
      <div className="mb-3 h-1.5 overflow-hidden rounded-full bg-muted">
        <div
          className="h-full rounded-full bg-emerald-500 transition-all duration-500"
          style={{ width: `${(done / stages.length) * 100}%` }}
        />
      </div>
      <ul className="grid grid-cols-1 gap-x-6 gap-y-1.5 sm:grid-cols-2">
        <AnimatePresence initial={false}>
          {stages.map((s) => (
            <motion.li
              key={s.key}
              layout
              initial={{ opacity: 0.4 }}
              animate={{ opacity: 1 }}
              className="flex items-center gap-2 text-[13px]"
            >
              <span
                className={cn(
                  'flex h-4.5 w-4.5 shrink-0 items-center justify-center rounded-full border',
                  s.status === 'done' && 'border-emerald-500 bg-emerald-500/10',
                  s.status === 'running' && 'border-amber-500 bg-amber-500/10',
                  s.status === 'failed' && 'border-red-500 bg-red-500/10',
                  s.status === 'pending' && 'border-muted-foreground/30',
                )}
              >
                {s.status === 'done' ? <Check className="h-3 w-3 text-emerald-600 dark:text-emerald-400" /> : null}
                {s.status === 'running' ? <Loader2 className="h-3 w-3 animate-spin text-amber-600 dark:text-amber-400" /> : null}
                {s.status === 'failed' ? <X className="h-3 w-3 text-red-500" /> : null}
              </span>
              <span className={cn(s.status === 'pending' && 'text-muted-foreground')}>{s.label}</span>
            </motion.li>
          ))}
        </AnimatePresence>
      </ul>
    </motion.div>
  );
}
