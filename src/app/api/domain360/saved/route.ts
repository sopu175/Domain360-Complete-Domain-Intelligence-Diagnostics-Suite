import { NextRequest } from 'next/server';
import { z } from 'zod';
import { db } from '@/lib/db';
import { runApi, jsonOk, jsonError } from '@/lib/domain360/api';
import { toAsciiDomain } from '@/lib/domain360/validation';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const items = await db.savedDomain.findMany({ orderBy: { createdAt: 'desc' }, take: 100 });
    return jsonOk({
      items: items.map((i) => ({ id: i.id, domain: i.domain, label: i.label, createdAt: i.createdAt.toISOString() })),
    });
  } catch (e) {
    console.error('[domain360:saved]', (e as Error).message);
    return jsonError('INTERNAL_ERROR', 'Could not load saved domains.', 500);
  }
}

const postSchema = z.object({ domain: z.string().min(1).max(300), label: z.string().max(100).optional() });

export async function POST(req: NextRequest) {
  return runApi({
    req,
    route: 'saved-add',
    limitPerMinute: 30,
    schema: postSchema,
    handler: async ({ domain, label }) => {
      const ascii = toAsciiDomain(domain);
      await db.savedDomain.upsert({
        where: { domain: ascii },
        create: { domain: ascii, label: label ?? null },
        update: { label: label ?? null },
      });
      return { saved: true };
    },
  });
}

const deleteSchema = z.object({ id: z.string().min(1).max(64) });

export async function DELETE(req: NextRequest) {
  return runApi({
    req,
    route: 'saved-delete',
    limitPerMinute: 60,
    schema: deleteSchema,
    handler: async ({ id }) => {
      await db.savedDomain.deleteMany({ where: { id } });
      return { deleted: true };
    },
  });
}
