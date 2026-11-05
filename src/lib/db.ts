// Ensure SQLite DATABASE_URL has correct file: protocol and path relative to prisma/
if (!process.env.DATABASE_URL || !process.env.DATABASE_URL.startsWith('file:')) {
  const raw = process.env.DATABASE_URL || './db/custom.db';
  process.env.DATABASE_URL = raw.startsWith('file:')
    ? raw
    : raw.startsWith('./')
      ? `file:../${raw.slice(2)}`
      : `file:../${raw}`;
}

import { PrismaClient } from '@prisma/client'

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
}

export const db =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: ['query'],
  })

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = db