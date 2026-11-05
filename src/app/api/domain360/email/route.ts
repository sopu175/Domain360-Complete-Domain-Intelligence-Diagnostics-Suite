import { NextRequest } from 'next/server';
import { z } from 'zod';
import { runApi } from '@/lib/domain360/api';
import { entitlement } from '@/lib/domain360/config';
import { toAsciiDomain } from '@/lib/domain360/validation';
import { analyzeEmail } from '@/lib/domain360/impl/email';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const schema = z.object({
  domain: z.string().min(1).max(300),
  selectors: z.string().max(500).optional(),
});

export async function GET(req: NextRequest) {
  return runApi({
    req,
    route: 'email',
    limitPerMinute: entitlement('securityPerMinute'),
    schema,
    handler: async ({ domain, selectors }) => {
      const ascii = toAsciiDomain(domain);
      const list = (selectors || '').split(',').map((s) => s.trim()).filter(Boolean);
      return analyzeEmail({ ascii, selectors: list });
    },
  });
}
