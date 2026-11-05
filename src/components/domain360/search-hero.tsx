'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Globe2, Search, ShieldCheck, Database, Server, FileSearch, Mail, Activity, Network, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useStore } from '@/lib/domain360/store';

const EXAMPLES = ['github.com', 'cloudflare.com', 'wikipedia.org', 'google.com'];

const FEATURES = [
  { icon: Database, title: 'Complete DNS', desc: 'A, AAAA, MX, TXT, NS, SOA, CAA, SRV + 14 advanced record types with custom resolvers' },
  { icon: Globe2, title: 'DNS Propagation', desc: 'Compare answers from 14 independent public resolvers in real time' },
  { icon: Server, title: 'Nameserver Audit', desc: 'Delegation, glue records, SOA serial consistency, lame-delegation detection' },
  { icon: ShieldCheck, title: 'SSL / TLS Analysis', desc: 'Certificate chain, expiry, protocols, ciphers, OCSP, hostname validation' },
  { icon: FileSearch, title: 'WHOIS / RDAP', desc: 'Registrar, dates, status codes, DNSSEC, abuse contacts with privacy respect' },
  { icon: Mail, title: 'Email Security', desc: 'SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT with a deliverability score' },
  { icon: Activity, title: 'HTTP Diagnostics', desc: 'Redirect chains, compression, HTTP/2, security headers, robots.txt' },
  { icon: Network, title: 'DNSSEC Analyzer', desc: 'Real DS↔DNSKEY digest verification and validating-resolver AD check' },
];

export function SearchHero() {
  const [value, setValue] = useState('');
  const [invalid, setInvalid] = useState(false);
  const runScan = useStore((s) => s.runScan);
  const recents = useStore((s) => s.recents);

  const submit = (raw: string) => {
    const host = raw.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(host)) {
      setInvalid(true);
      setTimeout(() => setInvalid(false), 2000);
      return;
    }
    void runScan(host);
  };

  return (
    <div className="mx-auto w-full max-w-5xl px-4 pb-16 pt-10 sm:px-6 sm:pt-16">
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, ease: 'easeOut' }}
        className="text-center"
      >
        <div className="mx-auto mb-5 inline-flex items-center gap-2 rounded-full border bg-muted/50 px-3 py-1 text-xs text-muted-foreground">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500" />
          Real diagnostics — live DNS, TLS, RDAP &amp; HTTP queries. No mock data.
        </div>
        <h1 className="text-balance text-3xl font-bold tracking-tight sm:text-5xl">
          Complete domain intelligence,
          <span className="text-emerald-600 dark:text-emerald-400"> one search away</span>
        </h1>
        <p className="mx-auto mt-4 max-w-2xl text-pretty text-[15px] leading-relaxed text-muted-foreground">
          Enter any domain to get a full technical report: DNS records, nameserver delegation,
          SSL certificates, WHOIS registration, email authentication, HTTP security headers,
          DNSSEC validation, subdomains and a transparent 0–100 health score.
        </p>

        <form
          className="mx-auto mt-8 flex max-w-2xl items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            submit(value);
          }}
        >
          <div className="relative flex-1">
            <Globe2 className="pointer-events-none absolute left-3.5 top-1/2 h-4.5 w-4.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="Enter domain name — e.g. example.com"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              aria-label="Domain name to analyze"
              aria-invalid={invalid}
              className={`h-12 rounded-xl pl-11 pr-4 text-[15px] ${invalid ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
            />
          </div>
          <Button type="submit" size="lg" className="h-12 rounded-xl px-5 font-semibold shadow-sm">
            <Search className="mr-1.5 h-4.5 w-4.5" />
            Analyze
            <ArrowRight className="ml-1 h-4 w-4 opacity-70" />
          </Button>
        </form>
        {invalid ? (
          <p className="mt-2 text-xs text-red-500">Please enter a valid domain name like example.com</p>
        ) : null}

        <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
          <span className="text-xs text-muted-foreground">Try:</span>
          {EXAMPLES.map((d) => (
            <button
              key={d}
              type="button"
              onClick={() => {
                setValue(d);
                submit(d);
              }}
              className="rounded-full border px-3 py-1 font-mono text-xs text-muted-foreground transition-colors hover:border-emerald-500/50 hover:text-emerald-600 dark:hover:text-emerald-400"
            >
              {d}
            </button>
          ))}
        </div>

        {recents.length ? (
          <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
            <span className="text-xs text-muted-foreground">Recent:</span>
            {recents.slice(0, 5).map((d) => (
              <button
                key={d}
                type="button"
                onClick={() => submit(d)}
                className="rounded-full bg-muted/60 px-3 py-1 font-mono text-xs transition-colors hover:bg-muted"
              >
                {d}
              </button>
            ))}
          </div>
        ) : null}
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.15, ease: 'easeOut' }}
        className="mt-14 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4"
      >
        {FEATURES.map((f) => (
          <div key={f.title} className="rounded-xl border bg-card p-4 transition-shadow hover:shadow-sm">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
              <f.icon className="h-4 w-4" />
            </div>
            <h3 className="mt-3 text-sm font-semibold">{f.title}</h3>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{f.desc}</p>
          </div>
        ))}
      </motion.div>
    </div>
  );
}
