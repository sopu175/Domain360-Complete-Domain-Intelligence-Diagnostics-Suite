'use client';

import { ShieldCheck } from 'lucide-react';
import {
  DataTable, InfoGrid, ModuleShell, SectionCard, StatusBadge, type TableColumn,
} from '@/components/domain360/shared-ui';
import { useModuleData } from '@/lib/domain360/store';
import type { SslResult } from '@/lib/domain360/types';

const STATUS_MAP: Record<string, string> = {
  valid: 'healthy', expiring_soon: 'warning', expired: 'critical', invalid: 'critical',
  self_signed: 'critical', not_installed: 'not_configured', unverifiable: 'unknown',
};

export function SslTab() {
  const { data, error, loading, lastChecked, refresh } = useModuleData<'ssl'>('ssl');
  const result = data as SslResult | undefined;

  const chainColumns: TableColumn[] = [
    { key: 'depth', header: '#', className: 'w-10' },
    { key: 'subject', header: 'Subject', mono: true },
    { key: 'issuer', header: 'Issuer' },
    { key: 'valid', header: 'Valid until', className: 'w-32' },
    { key: 'bits', header: 'Key', className: 'w-28' },
    { key: 'sig', header: 'Signature' },
  ];

  return (
    <ModuleShell
      title="SSL / TLS Certificate Checker"
      description="Real TLS handshake against port 443: full certificate chain, protocols, cipher suites, OCSP endpoints and hostname validation."
      icon={<ShieldCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
      loading={loading}
      error={error}
      onRetry={refresh}
      lastChecked={lastChecked}
      onRefresh={refresh}
      rawData={result}
    >
      {result ? (
        <div className="space-y-4">
          <div className="flex items-center gap-3 rounded-xl border bg-card px-4 py-3">
            <StatusBadge status={STATUS_MAP[result.status] || 'unknown'} />
            <p className="text-sm">
              {result.status === 'valid' && `Valid for ${result.daysRemaining} more days`}
              {result.status === 'expiring_soon' && `Expires in ${result.daysRemaining} days — renew soon`}
              {result.status === 'expired' && 'Certificate has EXPIRED'}
              {result.status === 'invalid' && 'Certificate validation failed'}
              {result.status === 'self_signed' && 'Self-signed certificate'}
              {result.status === 'not_installed' && 'No TLS service on port 443'}
              {result.status === 'unverifiable' && 'Could not verify'}
            </p>
          </div>

          <InfoGrid
            cols={3}
            items={[
              { label: 'Hostname match', value: result.hostnameMatch === null ? '—' : result.hostnameMatch ? 'Yes' : 'No', status: result.hostnameMatch === false ? 'critical' : result.hostnameMatch ? 'healthy' : undefined },
              { label: 'Negotiated protocol', value: result.negotiatedProtocol || '—' },
              { label: 'Cipher', value: result.cipher ? `${result.cipher.name}${result.cipher.bits ? ` (${result.cipher.bits}-bit)` : ''}` : '—', mono: true },
              { label: 'HTTPS available', value: result.httpsAvailable ? 'Yes' : 'No', status: result.httpsAvailable ? 'healthy' : 'critical' },
              { label: 'Connected IP', value: result.ip || '—', mono: true },
              { label: 'Chain complete', value: result.chainComplete === null ? '—' : result.chainComplete ? `Yes (${result.chain.length} certs)` : 'Leaf only' },
              { label: 'OCSP responder', value: result.ocspUrls[0] || '—', mono: true },
              { label: 'Serial number', value: result.cert?.serialNumber || '—', mono: true },
              { label: 'Fingerprint (SHA-256)', value: result.cert?.fingerprint256 || '—', mono: true },
            ]}
          />

          {result.cert ? (
            <SectionCard title="Leaf certificate">
              <InfoGrid
                cols={2}
                items={[
                  { label: 'Subject CN', value: result.cert.subjectCn, mono: true },
                  { label: 'Issuer', value: result.cert.issuerCn, mono: true },
                  { label: 'Valid from', value: new Date(result.cert.validFrom).toLocaleString() },
                  { label: 'Valid until', value: new Date(result.cert.validTo).toLocaleString() },
                  { label: 'Key', value: `${result.cert.keyAlgorithm}${result.cert.keyBits ? ` ${result.cert.keyBits}-bit` : ''}` },
                  { label: 'Signature algorithm', value: result.cert.signatureAlgorithm },
                  { label: 'SANs', value: result.cert.sans.slice(0, 6).join(', ') + (result.cert.sans.length > 6 ? ` +${result.cert.sans.length - 6} more` : ''), mono: true },
                  { label: 'Self-issued', value: result.cert.selfIssued ? 'Yes' : 'No' },
                ]}
              />
            </SectionCard>
          ) : null}

          <SectionCard title="Certificate chain" description="Leaf → intermediate(s) → root, as served by the server.">
            <DataTable
              columns={chainColumns}
              rows={result.chain.map((c, i) => ({
                _key: c.fingerprint256 || `cert-${i}`,
                depth: i === 0 ? 'leaf' : i === result.chain.length - 1 ? 'root?' : `intermediate ${i}`,
                subject: c.subjectCn,
                issuer: c.issuerCn,
                valid: new Date(c.validTo).toLocaleDateString(),
                bits: `${c.keyAlgorithm} ${c.keyBits ?? '?'}`,
                sig: c.signatureAlgorithm,
              }))}
              empty="No certificate retrieved"
            />
          </SectionCard>

          <SectionCard title="Protocol support" description="Each TLS version probed with a dedicated pinned handshake.">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {result.protocols.map((p) => (
                <div key={p.version} className="flex items-center justify-between rounded-lg border px-3 py-2">
                  <span className="font-mono text-[13px]">{p.version}</span>
                  <StatusBadge status={p.supported ? 'warning' : 'healthy'} />
                </div>
              ))}
            </div>
            <p className="mt-2 text-[11.5px] text-muted-foreground">
              A <span className="font-medium">green &ldquo;Healthy&rdquo;</span> badge means the protocol is <em>disabled</em> (good — TLS 1.0/1.1 are deprecated). Supported legacy versions are flagged amber.
            </p>
          </SectionCard>

          {result.errors.length ? (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs leading-relaxed text-amber-700 dark:text-amber-400">
              {result.errors.map((e, i) => (
                <p key={i}>{e}</p>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </ModuleShell>
  );
}
