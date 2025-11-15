import { PrismaClient } from '@prisma/client';

declare global {
  namespace globalThis {
    var prismaDb: PrismaClient;

  }
}

const prisma = new PrismaClient();

if (process.env.NODE_ENV === 'production') global.prismaDb = prisma;

export default prisma;
