import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { nanoid } from 'nanoid';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const prisma = new PrismaClient();
const app = express();

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'progettoadv1';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'owner@preadv.it';
const PUBLIC_BACKEND_URL = process.env.PUBLIC_BACKEND_URL || `http://localhost:${PORT}`;

const origins = (process.env.FRONTEND_ORIGIN || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.set('trust proxy', true);
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(morgan('tiny'));
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (!origins.length || origins.includes(origin)) return cb(null, true);
    return cb(new Error(`CORS blocked for ${origin}`));
  },
  credentials: true
}));

function isProduction() {
  return process.env.NODE_ENV === 'production';
}

function cookieOptions() {
  return {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 1000 * 60 * 60 * 24 * 14,
    path: '/'
  };
}

function getIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || null;
}

function signToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: '14d' }
  );
}

function setAuthCookie(res, user) {
  const token = signToken(user);
  res.cookie('preadv_token', token, cookieOptions());
  return token;
}

function clearAuthCookie(res) {
  res.clearCookie('preadv_token', { path: '/', sameSite: 'none', secure: true });
}

function generateDiscountCode() {
  return `PREADV-${nanoid(6).toUpperCase()}`;
}

async function logActivity(req, action, metadata = {}, userId = null, actor = null) {
  try {
    await prisma.activityLog.create({
      data: {
        userId,
        actor,
        action,
        metadata,
        ip: getIp(req),
        userAgent: req.headers['user-agent'] || null
      }
    });
  } catch (e) {
    console.error('activity log error', e.message);
  }
}

async function ensureAdmin() {
  const existing = await prisma.user.findUnique({ where: { email: ADMIN_EMAIL } });
  if (existing) return existing;
  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  return prisma.user.create({
    data: {
      role: 'ADMIN',
      name: 'PRE ADV Owner',
      email: ADMIN_EMAIL,
      passwordHash,
      discountCode: `ADMIN-${nanoid(8).toUpperCase()}`
    }
  });
}

function safeUser(user) {
  if (!user) return null;
  const { passwordHash, ...safe } = user;
  return safe;
}

async function authRequired(req, res, next) {
  try {
    const token = req.cookies.preadv_token || req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({ where: { id: payload.sub } });
    if (!user || !user.isActive) return res.status(401).json({ error: 'Invalid session' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid session' });
  }
}

function adminRequired(req, res, next) {
  if (req.user?.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  next();
}

const registerSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(8),
  phone: z.string().optional().nullable(),
  company: z.string().optional().nullable()
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'PRE ADV Backend', time: new Date().toISOString() });
});

/* AUTH */
app.post('/api/auth/client/register', async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid data', details: parsed.error.flatten() });

  const { name, email, password, phone, company } = parsed.data;
  const normalizedEmail = email.toLowerCase().trim();

  const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const passwordHash = await bcrypt.hash(password, 12);
  let discountCode = generateDiscountCode();
  while (await prisma.user.findUnique({ where: { discountCode } })) discountCode = generateDiscountCode();

  const user = await prisma.user.create({
    data: {
      role: 'CLIENT',
      name,
      email: normalizedEmail,
      phone: phone || null,
      company: company || null,
      passwordHash,
      discountCode
    }
  });

  setAuthCookie(res, user);
  await logActivity(req, 'client_registered', { email: normalizedEmail }, user.id, 'client');
  res.status(201).json({ user: safeUser(user) });
});

app.post('/api/auth/client/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid data' });

  const user = await prisma.user.findUnique({ where: { email: parsed.data.email.toLowerCase().trim() } });
  if (!user || user.role !== 'CLIENT') return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(parsed.data.password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  setAuthCookie(res, user);
  await logActivity(req, 'client_login', { email: user.email }, user.id, 'client');
  res.json({ user: safeUser(user) });
});

app.post('/api/auth/admin/login', async (req, res) => {
  await ensureAdmin();
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid data' });

  const user = await prisma.user.findUnique({ where: { email: parsed.data.email.toLowerCase().trim() } });
  if (!user || user.role !== 'ADMIN') return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(parsed.data.password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  setAuthCookie(res, user);
  await logActivity(req, 'admin_login', { email: user.email }, user.id, 'admin');
  res.json({ user: safeUser(user) });
});

app.post('/api/auth/logout', authRequired, async (req, res) => {
  clearAuthCookie(res);
  await logActivity(req, 'logout', {}, req.user.id, req.user.role.toLowerCase());
  res.json({ ok: true });
});

app.get('/api/me', authRequired, (req, res) => {
  res.json({ user: safeUser(req.user) });
});

/* TRACKING */
app.post('/api/track/visit', async (req, res) => {
  const body = z.object({
    visitorId: z.string().optional(),
    path: z.string().default('/'),
    title: z.string().optional(),
    referrer: z.string().optional(),
    utmSource: z.string().optional(),
    utmMedium: z.string().optional(),
    utmCampaign: z.string().optional()
  }).parse(req.body);

  const visit = await prisma.visit.create({
    data: {
      visitorId: body.visitorId || nanoid(),
      ip: getIp(req),
      userAgent: req.headers['user-agent'] || null,
      referrer: body.referrer || null,
      path: body.path,
      title: body.title || null,
      utmSource: body.utmSource || null,
      utmMedium: body.utmMedium || null,
      utmCampaign: body.utmCampaign || null
    }
  });

  res.status(201).json({ ok: true, visitId: visit.id });
});

app.post('/api/track/click', async (req, res) => {
  const body = z.object({
    visitorId: z.string().optional(),
    path: z.string().optional(),
    label: z.string().optional(),
    href: z.string().optional(),
    type: z.string().optional()
  }).parse(req.body);

  const click = await prisma.click.create({
    data: {
      visitorId: body.visitorId || null,
      ip: getIp(req),
      userAgent: req.headers['user-agent'] || null,
      path: body.path || null,
      label: body.label || null,
      href: body.href || null,
      type: body.type || null
    }
  });

  res.status(201).json({ ok: true, clickId: click.id });
});

/* LEADS */
app.post('/api/leads', async (req, res) => {
  const body = z.object({
    name: z.string().optional(),
    email: z.string().email().optional(),
    phone: z.string().optional(),
    projectType: z.string().optional(),
    budget: z.string().optional(),
    message: z.string().optional(),
    source: z.string().optional()
  }).parse(req.body);

  const lead = await prisma.lead.create({ data: body });
  await logActivity(req, 'lead_created', { leadId: lead.id, email: lead.email }, null, 'public');
  res.status(201).json({ ok: true, lead });
});

/* CLIENT AREA */
app.get('/api/client/dashboard', authRequired, async (req, res) => {
  if (req.user.role !== 'CLIENT') return res.status(403).json({ error: 'Client only' });

  const [projects, requests, deliveries, messages] = await Promise.all([
    prisma.project.findMany({ where: { clientId: req.user.id }, orderBy: { createdAt: 'desc' } }),
    prisma.clientRequest.findMany({ where: { clientId: req.user.id }, orderBy: { createdAt: 'desc' } }),
    prisma.delivery.findMany({ where: { clientId: req.user.id, isPublished: true }, orderBy: { createdAt: 'desc' } }),
    prisma.chatMessage.findMany({ where: { clientId: req.user.id }, orderBy: { createdAt: 'asc' } })
  ]);

  res.json({
    user: safeUser(req.user),
    projects,
    requests,
    deliveries,
    messages
  });
});

app.post('/api/client/requests', authRequired, async (req, res) => {
  if (req.user.role !== 'CLIENT') return res.status(403).json({ error: 'Client only' });

  const body = z.object({
    type: z.string().min(2),
    title: z.string().min(2),
    message: z.string().optional(),
    projectId: z.string().optional()
  }).parse(req.body);

  const request = await prisma.clientRequest.create({
    data: {
      clientId: req.user.id,
      projectId: body.projectId || null,
      type: body.type,
      title: body.title,
      message: body.message || null
    }
  });

  await logActivity(req, 'client_request_created', { requestId: request.id }, req.user.id, 'client');
  res.status(201).json({ request });
});

app.get('/api/client/messages', authRequired, async (req, res) => {
  if (req.user.role !== 'CLIENT') return res.status(403).json({ error: 'Client only' });
  const messages = await prisma.chatMessage.findMany({
    where: { clientId: req.user.id },
    orderBy: { createdAt: 'asc' }
  });
  res.json({ messages });
});

app.post('/api/client/messages', authRequired, async (req, res) => {
  if (req.user.role !== 'CLIENT') return res.status(403).json({ error: 'Client only' });
  const body = z.object({ text: z.string().min(1).max(5000) }).parse(req.body);

  const message = await prisma.chatMessage.create({
    data: {
      clientId: req.user.id,
      sender: 'CLIENT',
      text: body.text
    }
  });

  await logActivity(req, 'client_message_sent', { messageId: message.id }, req.user.id, 'client');
  res.status(201).json({ message });
});

app.get('/api/client/deliveries', authRequired, async (req, res) => {
  if (req.user.role !== 'CLIENT') return res.status(403).json({ error: 'Client only' });
  const deliveries = await prisma.delivery.findMany({
    where: { clientId: req.user.id, isPublished: true },
    orderBy: { createdAt: 'desc' }
  });
  res.json({ deliveries });
});

/* ADMIN */
app.get('/api/admin/dashboard', authRequired, adminRequired, async (req, res) => {
  const since7 = new Date(Date.now() - 1000 * 60 * 60 * 24 * 7);

  const [
    visitsCount, uniqueVisitors, clicksCount, whatsappClicks, clientsCount,
    requestsCount, projectsCount, deliveriesCount, leadsCount,
    latestVisits, latestClicks, latestRequests, latestMessages
  ] = await Promise.all([
    prisma.visit.count(),
    prisma.visit.groupBy({ by: ['visitorId'] }),
    prisma.click.count(),
    prisma.click.count({ where: { OR: [{ href: { contains: 'wa.me' } }, { label: { contains: 'WhatsApp', mode: 'insensitive' } }] } }),
    prisma.user.count({ where: { role: 'CLIENT' } }),
    prisma.clientRequest.count(),
    prisma.project.count(),
    prisma.delivery.count(),
    prisma.lead.count(),
    prisma.visit.findMany({ orderBy: { createdAt: 'desc' }, take: 10 }),
    prisma.click.findMany({ orderBy: { createdAt: 'desc' }, take: 10 }),
    prisma.clientRequest.findMany({ orderBy: { createdAt: 'desc' }, take: 10, include: { client: true } }),
    prisma.chatMessage.findMany({ orderBy: { createdAt: 'desc' }, take: 10, include: { client: true } })
  ]);

  const dailyVisitsRaw = await prisma.visit.groupBy({
    by: ['createdAt'],
    where: { createdAt: { gte: since7 } },
    _count: true
  });

  // Simple aggregation by date in JS for compatibility.
  const dailyMap = {};
  const visits7 = await prisma.visit.findMany({
    where: { createdAt: { gte: since7 } },
    select: { createdAt: true }
  });
  for (const v of visits7) {
    const key = v.createdAt.toISOString().slice(0, 10);
    dailyMap[key] = (dailyMap[key] || 0) + 1;
  }

  res.json({
    stats: {
      visits: visitsCount,
      visitors: uniqueVisitors.length,
      clicks: clicksCount,
      whatsappClicks,
      clients: clientsCount,
      requests: requestsCount,
      projects: projectsCount,
      deliveries: deliveriesCount,
      leads: leadsCount
    },
    dailyVisits: Object.entries(dailyMap).map(([date, count]) => ({ date, count })),
    latest: { visits: latestVisits, clicks: latestClicks, requests: latestRequests, messages: latestMessages }
  });
});

app.get('/api/admin/clients', authRequired, adminRequired, async (req, res) => {
  const clients = await prisma.user.findMany({
    where: { role: 'CLIENT' },
    orderBy: { createdAt: 'desc' },
    include: {
      projects: true,
      requests: true,
      deliveries: true
    }
  });
  res.json({ clients: clients.map(c => ({ ...safeUser(c), projects: c.projects, requests: c.requests, deliveries: c.deliveries })) });
});

app.post('/api/admin/clients', authRequired, adminRequired, async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid data', details: parsed.error.flatten() });

  const { name, email, password, phone, company } = parsed.data;
  const normalizedEmail = email.toLowerCase().trim();
  const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const user = await prisma.user.create({
    data: {
      role: 'CLIENT',
      name,
      email: normalizedEmail,
      phone: phone || null,
      company: company || null,
      passwordHash: await bcrypt.hash(password, 12),
      discountCode: generateDiscountCode()
    }
  });

  await logActivity(req, 'admin_client_created', { clientId: user.id }, req.user.id, 'admin');
  res.status(201).json({ client: safeUser(user) });
});

app.get('/api/admin/visits', authRequired, adminRequired, async (req, res) => {
  const visits = await prisma.visit.findMany({ orderBy: { createdAt: 'desc' }, take: 500 });
  res.json({ visits });
});

app.get('/api/admin/clicks', authRequired, adminRequired, async (req, res) => {
  const clicks = await prisma.click.findMany({ orderBy: { createdAt: 'desc' }, take: 500 });
  res.json({ clicks });
});

app.get('/api/admin/leads', authRequired, adminRequired, async (req, res) => {
  const leads = await prisma.lead.findMany({ orderBy: { createdAt: 'desc' }, take: 500 });
  res.json({ leads });
});

app.get('/api/admin/requests', authRequired, adminRequired, async (req, res) => {
  const requests = await prisma.clientRequest.findMany({
    orderBy: { createdAt: 'desc' },
    include: { client: true, project: true }
  });
  res.json({ requests });
});

app.patch('/api/admin/requests/:id', authRequired, adminRequired, async (req, res) => {
  const body = z.object({
    status: z.enum(['NEW', 'IN_PROGRESS', 'WAITING', 'COMPLETED', 'ARCHIVED']).optional(),
    adminNote: z.string().optional()
  }).parse(req.body);

  const request = await prisma.clientRequest.update({
    where: { id: req.params.id },
    data: body
  });

  res.json({ request });
});

app.post('/api/admin/projects', authRequired, adminRequired, async (req, res) => {
  const body = z.object({
    clientId: z.string(),
    title: z.string().min(2),
    type: z.string().optional(),
    description: z.string().optional(),
    dueDate: z.string().optional()
  }).parse(req.body);

  const project = await prisma.project.create({
    data: {
      clientId: body.clientId,
      title: body.title,
      type: body.type || null,
      description: body.description || null,
      dueDate: body.dueDate ? new Date(body.dueDate) : null
    }
  });

  await logActivity(req, 'admin_project_created', { projectId: project.id }, req.user.id, 'admin');
  res.status(201).json({ project });
});

app.get('/api/admin/projects', authRequired, adminRequired, async (req, res) => {
  const projects = await prisma.project.findMany({
    orderBy: { createdAt: 'desc' },
    include: { client: true, deliveries: true, requests: true }
  });
  res.json({ projects });
});

app.post('/api/admin/messages', authRequired, adminRequired, async (req, res) => {
  const body = z.object({
    clientId: z.string(),
    text: z.string().min(1).max(5000)
  }).parse(req.body);

  const message = await prisma.chatMessage.create({
    data: {
      clientId: body.clientId,
      sender: 'ADMIN',
      text: body.text
    }
  });

  await logActivity(req, 'admin_message_sent', { clientId: body.clientId, messageId: message.id }, req.user.id, 'admin');
  res.status(201).json({ message });
});

app.get('/api/admin/messages/:clientId', authRequired, adminRequired, async (req, res) => {
  const messages = await prisma.chatMessage.findMany({
    where: { clientId: req.params.clientId },
    orderBy: { createdAt: 'asc' }
  });
  res.json({ messages });
});

app.post('/api/admin/deliveries', authRequired, adminRequired, async (req, res) => {
  const body = z.object({
    clientId: z.string(),
    projectId: z.string().optional(),
    title: z.string().min(2),
    type: z.enum(['PHOTO', 'VIDEO', 'GALLERY', 'DOWNLOAD', 'OTHER']).default('OTHER'),
    notes: z.string().optional(),
    previewUrl: z.string().optional(),
    downloadUrl: z.string().optional(),
    storageKey: z.string().optional(),
    fileName: z.string().optional(),
    fileSize: z.number().optional(),
    mimeType: z.string().optional()
  }).parse(req.body);

  const delivery = await prisma.delivery.create({
    data: {
      ...body,
      projectId: body.projectId || null,
      notes: body.notes || null,
      previewUrl: body.previewUrl || null,
      downloadUrl: body.downloadUrl || null,
      storageKey: body.storageKey || null,
      fileName: body.fileName || null,
      fileSize: body.fileSize ? BigInt(body.fileSize) : null,
      mimeType: body.mimeType || null
    }
  });

  await logActivity(req, 'admin_delivery_created', { deliveryId: delivery.id, clientId: body.clientId }, req.user.id, 'admin');
  res.status(201).json({ delivery: serializeBigInt(delivery) });
});

app.get('/api/admin/deliveries', authRequired, adminRequired, async (req, res) => {
  const deliveries = await prisma.delivery.findMany({
    orderBy: { createdAt: 'desc' },
    include: { client: true, project: true }
  });
  res.json({ deliveries: serializeBigInt(deliveries) });
});

/* S3/R2 SIGNED URLS */
function s3Configured() {
  return process.env.S3_ENDPOINT && process.env.S3_BUCKET && process.env.S3_ACCESS_KEY_ID && process.env.S3_SECRET_ACCESS_KEY;
}

function s3Client() {
  return new S3Client({
    region: process.env.S3_REGION || 'auto',
    endpoint: process.env.S3_ENDPOINT,
    credentials: {
      accessKeyId: process.env.S3_ACCESS_KEY_ID,
      secretAccessKey: process.env.S3_SECRET_ACCESS_KEY
    }
  });
}

app.post('/api/admin/storage/presign-upload', authRequired, adminRequired, async (req, res) => {
  if (!s3Configured()) return res.status(400).json({ error: 'Storage not configured' });

  const body = z.object({
    fileName: z.string().min(1),
    mimeType: z.string().min(1),
    clientId: z.string().optional()
  }).parse(req.body);

  const key = `preadv/${body.clientId || 'general'}/${Date.now()}-${nanoid(8)}-${body.fileName}`;
  const command = new PutObjectCommand({
    Bucket: process.env.S3_BUCKET,
    Key: key,
    ContentType: body.mimeType
  });

  const uploadUrl = await getSignedUrl(s3Client(), command, { expiresIn: 60 * 15 });
  res.json({ uploadUrl, key });
});

app.get('/api/client/download/:deliveryId', authRequired, async (req, res) => {
  const delivery = await prisma.delivery.findUnique({ where: { id: req.params.deliveryId } });
  if (!delivery) return res.status(404).json({ error: 'Delivery not found' });

  const isOwner = req.user.role === 'CLIENT' && delivery.clientId === req.user.id;
  const isAdmin = req.user.role === 'ADMIN';
  if (!isOwner && !isAdmin) return res.status(403).json({ error: 'Forbidden' });

  if (delivery.downloadUrl) return res.json({ url: delivery.downloadUrl });

  if (!delivery.storageKey || !s3Configured()) return res.status(404).json({ error: 'No downloadable file' });

  const command = new GetObjectCommand({
    Bucket: process.env.S3_BUCKET,
    Key: delivery.storageKey
  });
  const url = await getSignedUrl(s3Client(), command, { expiresIn: 60 * 30 });
  res.json({ url });
});

function serializeBigInt(value) {
  return JSON.parse(JSON.stringify(value, (_, v) => typeof v === 'bigint' ? Number(v) : v));
}

app.use((err, req, res, next) => {
  console.error(err);
  if (err?.name === 'ZodError') return res.status(400).json({ error: 'Invalid data', details: err.flatten() });
  res.status(500).json({ error: 'Server error' });
});

ensureAdmin()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`PRE ADV backend running on ${PORT}`);
      console.log(`Health: ${PUBLIC_BACKEND_URL}/api/health`);
    });
  })
  .catch(err => {
    console.error('Startup error', err);
    process.exit(1);
  });
