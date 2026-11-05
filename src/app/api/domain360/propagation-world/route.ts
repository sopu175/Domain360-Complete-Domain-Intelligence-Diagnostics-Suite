import { NextRequest } from 'next/server';
import { z } from 'zod';
import { runApi } from '@/lib/domain360/api';
import { entitlement } from '@/lib/domain360/config';
import { toAsciiDomain } from '@/lib/domain360/validation';
import { checkPropagationWorld } from '@/lib/domain360/impl/propagation-geo';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const schema = z.object({
  domain: z.string().min(1).max(300),
  type: z.string().min(1).max(10).default('A'),
  expected: z.string().max(200).optional(),
});

export async function GET(req: NextRequest) {
  return runApi({
    req,
    route: 'propagation-world',
    limitPerMinute: entitlement('propagationPerMinute'),
    schema,
    handler: async ({ domain, type, expected }) => {
      const ascii = toAsciiDomain(domain);
      return checkPropagationWorld({ ascii, recordType: type, expected });
    },
  });
}
