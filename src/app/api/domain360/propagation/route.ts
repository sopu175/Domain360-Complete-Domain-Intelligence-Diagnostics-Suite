import { NextRequest } from 'next/server';
import { z } from 'zod';
import { runApi } from '@/lib/domain360/api';
import { entitlement } from '@/lib/domain360/config';
import { toAsciiDomain } from '@/lib/domain360/validation';
import { checkPropagation } from '@/lib/domain360/impl/propagation';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const schema = z.object({
  domain: z.string().min(1).max(300),
  type: z.string().min(1).max(10).default('A'),
});

export async function GET(req: NextRequest) {
  return runApi({
    req,
    route: 'propagation',
    limitPerMinute: entitlement('propagationPerMinute'),
    schema,
    handler: async ({ domain, type }) => {
      const ascii = toAsciiDomain(domain);
      return checkPropagation({ ascii, recordType: type });
    },
  });
}
