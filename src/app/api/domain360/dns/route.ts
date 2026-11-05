import { NextRequest } from 'next/server';
import { z } from 'zod';
import { runApi } from '@/lib/domain360/api';
import { entitlement } from '@/lib/domain360/config';
import { toAsciiDomain } from '@/lib/domain360/validation';
import { lookupDns } from '@/lib/domain360/impl/dns';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const schema = z.object({
  domain: z.string().min(1).max(300),
  type: z.string().min(1).max(10).default('A'),
  resolver: z.string().max(100).optional(),
});

export async function GET(req: NextRequest) {
  return runApi({
    req,
    route: 'dns',
    limitPerMinute: entitlement('dnsPerMinute'),
    schema,
    handler: async ({ domain, type, resolver }) => {
      const ascii = toAsciiDomain(domain);
      return lookupDns({ ascii, display: domain.trim(), recordType: type, resolver: resolver || 'system' });
    },
  });
}
