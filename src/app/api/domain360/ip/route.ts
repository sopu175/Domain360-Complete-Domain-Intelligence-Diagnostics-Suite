import { NextRequest } from 'next/server';
import { z } from 'zod';
import { runApi, ApiError } from '@/lib/domain360/api';
import { entitlement } from '@/lib/domain360/config';
import { toAsciiDomainOrIp } from '@/lib/domain360/validation';
import { lookupIpInfo } from '@/lib/domain360/impl/ipinfo';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const schema = z.object({
  domain: z.string().max(300).optional(),
  ip: z.string().max(100).optional(),
});

export async function GET(req: NextRequest) {
  return runApi({
    req,
    route: 'ip',
    limitPerMinute: entitlement('perModulePerMinute'),
    schema,
    handler: async ({ domain, ip }) => {
      const raw = ip || domain;
      if (!raw) throw new ApiError('INVALID_INPUT', 'Provide a domain or ip parameter.');
      const { value, isIp } = toAsciiDomainOrIp(raw);
      return lookupIpInfo({ query: value, isIp });
    },
  });
}
