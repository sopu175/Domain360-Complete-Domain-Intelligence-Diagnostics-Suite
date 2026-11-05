import { NextRequest } from 'next/server';
import { z } from 'zod';
import { db } from '@/lib/db';
import { runApi, jsonOk, jsonError } from '@/lib/domain360/api';
import { entitlement } from '@/lib/domain360/config';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const getSchema = z.object({
  domain: z.string().max(300).optional(),
  limit: z.string().max(4).optional(),
});

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const parsed = getSchema.safeParse(Object.fromEntries(url.searchParams));
  if (!parsed.success) return jsonError('INVALID_INPUT', 'Invalid query.', 400);
  const limit = Math.min(parseInt(parsed.data.limit || '30', 10) || 30, 100);
  try {
    const items = await db.scanHistory.findMany({
      where: parsed.data.domain ? { domain: parsed.data.domain } : undefined,
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
    return jsonOk({
      items: items.map((i) => ({
        id: i.id,
        domain: i.domain,
        score: i.score,
        grade: i.grade,
        createdAt: i.createdAt.toISOString(),
        summary: i.summaryJson,
      })),
    });
  } catch (e) {
    console.error('[domain360:history]', (e as Error).message);
    return jsonError('INTERNAL_ERROR', 'Could not load history.', 500);
  }
}

const postSchema = z.object({
  domain: z.string().min(1).max(300),
  score: z.number().int().min(0).max(100).nullable().optional(),
  grade: z.string().max(4).nullable().optional(),
  summary: z.string().max(8000).optional(),
});

export async function POST(req: NextRequest) {
  return runApi({
    req,
    route: 'history-save',
    limitPerMinute: 30,
    schema: postSchema,
    handler: async ({ domain, score, grade, summary }) => {
      await db.scanHistory.create({
        data: { domain, score: score ?? null, grade: grade ?? null, summaryJson: summary ?? null },
      });
      return { saved: true };
    },
  });
}

const deleteSchema = z.object({ id: z.string().min(1).max(64) });

export async function DELETE(req: NextRequest) {
  return runApi({
    req,
    route: 'history-delete',
    limitPerMinute: 60,
    schema: deleteSchema,
    handler: async ({ id }) => {
      await db.scanHistory.deleteMany({ where: { id } });
      return { deleted: true };
    },
  });
}
