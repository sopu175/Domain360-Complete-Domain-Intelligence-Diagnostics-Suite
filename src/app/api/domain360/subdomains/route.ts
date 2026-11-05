import { NextRequest } from 'next/server';
import { z } from 'zod';
import { runApi } from '@/lib/domain360/api';
import { entitlement } from '@/lib/domain360/config';
import { toAsciiDomain } from '@/lib/domain360/validation';
import { discoverSubdomains } from '@/lib/domain360/impl/subdomains';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const schema = z.object({
  domain: z.string().min(1).max(300),
  source: z.enum(['all', 'ct', 'dns']).default('all'),
});

export async function GET(req: NextRequest) {
  return runApi({
    req,
    route: 'subdomains',
    limitPerMinute: entitlement('subdomainsPerMinute'),
    schema,
    handler: async ({ domain, source }) => {
      const ascii = toAsciiDomain(domain);
      return discoverSubdomains({ ascii, source });
    },
  });
}
