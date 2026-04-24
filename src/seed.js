import 'dotenv/config';
import bcrypt from 'bcryptjs';
import { PrismaClient } from '@prisma/client';
import { nanoid } from 'nanoid';

const prisma = new PrismaClient();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'progettoadv1';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'owner@preadv.it';

const existing = await prisma.user.findUnique({ where: { email: ADMIN_EMAIL } });
if (!existing) {
  await prisma.user.create({
    data: {
      role: 'ADMIN',
      name: 'PRE ADV Owner',
      email: ADMIN_EMAIL,
      passwordHash: await bcrypt.hash(ADMIN_PASSWORD, 12),
      discountCode: `ADMIN-${nanoid(8).toUpperCase()}`
    }
  });
  console.log('Admin created:', ADMIN_EMAIL);
} else {
  console.log('Admin already exists:', ADMIN_EMAIL);
}
await prisma.$disconnect();
