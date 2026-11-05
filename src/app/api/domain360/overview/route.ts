import { NextRequest } from 'next/server';
import { z } from 'zod';
import { runApi } from '@/lib/domain360/api';
import { entitlement } from '@/lib/domain360/config';
import { toAsciiDomain } from '@/lib/domain360/validation';
import { buildOverview } from '@/lib/domain360/impl/overview';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const schema = z.object({ domain: z.string().min(1).max(300) });

export async function GET(req: NextRequest) {
  return runApi({
    req,
    route: 'overview',
    limitPerMinute: entitlement('overviewPerMinute'),
    schema,
    handler: async ({ domain }) => {
      const ascii = toAsciiDomain(domain);
      return buildOverview({ ascii, display: domain.trim() });
    },
  });
}
