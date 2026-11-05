import { NextRequest } from 'next/server';
import { z } from 'zod';
import { runApi } from '@/lib/domain360/api';
import { entitlement } from '@/lib/domain360/config';
import { toAsciiDomain } from '@/lib/domain360/validation';
import { scanSecurity } from '@/lib/domain360/impl/securityscan';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const schema = z.object({
  domain: z.string().min(1).max(300),
  authorize: z.string().max(4).optional(), // '1' = user explicitly authorized AXFR test
});

export async function GET(req: NextRequest) {
  return runApi({
    req,
    route: 'security',
    limitPerMinute: entitlement('securityPerMinute'),
    schema,
    handler: async ({ domain, authorize }) => {
      const ascii = toAsciiDomain(domain);
      return scanSecurity({ ascii, authorizeAxfr: authorize === '1' });
    },
  });
}
