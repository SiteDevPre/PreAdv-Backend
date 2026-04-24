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

import { v2 as cloudinary } from 'cloudinary';
const prisma = new PrismaClient();
const app = express();

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'progettoadv1';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'owner@preadv.it';
const PUBLIC_BACKEND_URL = process.env.PUBLIC_BACKEND_URL || `http://localhost:${PORT}`;

const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || '';
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY || '';
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET || '';
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 500);
const AUTO_DELETE_AFTER_DAYS = Number(process.env.AUTO_DELETE_AFTER_DAYS || 15);

cloudinary.config({
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key: CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET,
  secure: true
});

function assertCloudinaryReady() {
  if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
    const error = new Error('Cloudinary is not configured');
    error.statusCode = 503;
    throw error;
  }
}

function safeFileKind(mimeType = '') {
  const mime = String(mimeType).toLowerCase();
  if (mime.startsWith('image/')) return 'image';
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/')) return 'video';
  return 'raw';
}

function cleanFileName(name = 'file') {
  return String(name || 'file')
    .replace(/[^\w.\- ()]+/g, '_')
    .slice(0, 140);
}

function clientVisibleAttachmentWhere() {
  return { deletedForAll: false, deletedForClient: false };
}

function adminVisibleAttachmentWhere() {
  return { deletedForAll: false, deletedForAdmin: false };
}

async function destroyCloudinaryAsset(att) {
  if (!att || !att.publicId) return;
  try {
    await cloudinary.uploader.destroy(att.publicId, {
      resource_type: att.resourceType || 'auto',
      invalidate: true
    });
  } catch (error) {
    console.warn('Cloudinary destroy failed', att.publicId, error.message);
  }
}

function formatAttachment(att) {
  if (!att) return null;
  return {
    id: att.id,
    fileName: att.fileName,
    mimeType: att.mimeType,
    fileSize: att.fileSize,
    resourceType: att.resourceType,
    secureUrl: att.secureUrl,
    format: att.format,
    bytes: att.bytes,
    duration: att.duration,
    width: att.width,
    height: att.height,
    allowClientDownload: att.allowClientDownload || att.uploaderRole === 'CLIENT',
    createdAt: att.createdAt
  };
}

function formatMessage(m) {
  return {
    id: m.id,
    clientId: m.clientId,
    sender: m.sender,
    text: m.text,
    createdAt: m.createdAt,
    attachments: (m.attachments || []).map(formatAttachment).filter(Boolean)
  };
}


const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'PRE ADV STUDIO <noreply@preadv.it>';

function verificationCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashCode(code) {
  return crypto
    .createHash('sha256')
    .update(String(code) + ':' + JWT_SECRET)
    .digest('hex');
}

async function sendEmail({ to, subject, html, text }) {
  if (!RESEND_API_KEY) {
    console.warn('RESEND_API_KEY missing: email not sent to', to);
    return { skipped: true };
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: EMAIL_FROM,
      to,
      subject,
      html,
      text
    })
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error('Resend error', response.status, data);
    throw new Error(data?.message || 'Email send failed');
  }

  return data;
}

function verificationEmailHtml({ name, code }) {
  const safeName = String(name || 'cliente').replace(/[<>]/g, '');
  return `
    <div style="margin:0;padding:0;background:#050505;color:#ffffff;font-family:Arial,Helvetica,sans-serif">
      <div style="max-width:620px;margin:0 auto;padding:36px 22px">
        <div style="border:1px solid rgba(255,255,255,.14);border-radius:24px;padding:28px;background:linear-gradient(145deg,#0b1020,#050505)">
          <p style="margin:0 0 14px;color:#9ca3af;font-size:12px;letter-spacing:3px;text-transform:uppercase">PRE ADV STUDIO</p>
          <h1 style="margin:0;color:#ffffff;font-size:34px;line-height:1.05;font-weight:400">Conferma il tuo accesso</h1>
          <p style="margin:18px 0 0;color:#cbd5e1;font-size:15px;line-height:1.7">
            Ciao ${safeName}, usa questo codice per completare la registrazione della tua area clienti PRE ADV.
          </p>
          <div style="margin:26px 0;padding:20px;border-radius:18px;background:rgba(255,255,255,.08);text-align:center">
            <div style="font-size:36px;letter-spacing:8px;font-weight:700;color:#ffffff">${code}</div>
          </div>
          <p style="margin:0;color:#94a3b8;font-size:13px;line-height:1.6">
            Il codice è valido per 15 minuti. Se non hai richiesto tu questa registrazione, puoi ignorare questa email.
          </p>
        </div>
      </div>
    </div>
  `;
}

async function sendVerificationCode({ user, req }) {
  const code = verificationCode();
  const expiresAt = new Date(Date.now() + 1000 * 60 * 15).toISOString();

  await prisma.activityLog.create({
    data: {
      userId: user.id,
      actor: 'client',
      action: 'email_verification_code',
      metadata: {
        email: user.email,
        codeHash: hashCode(code),
        expiresAt
      },
      ip: getIp(req),
      userAgent: req.headers['user-agent'] || null
    }
  });

  await sendEmail({
    to: user.email,
    subject: 'Il tuo codice di conferma PRE ADV',
    text: `Il tuo codice di conferma PRE ADV è ${code}. È valido per 15 minuti.`,
    html: verificationEmailHtml({ name: user.name, code })
  });

  return { expiresAt };
}

async function findValidVerificationLog(user, code) {
  const logs = await prisma.activityLog.findMany({
    where: {
      userId: user.id,
      action: 'email_verification_code'
    },
    orderBy: { createdAt: 'desc' },
    take: 20
  });

  const codeHash = hashCode(code);
  const nowMs = Date.now();

  return logs.find(log => {
    const meta = log.metadata || {};
    return meta.codeHash === codeHash && meta.expiresAt && new Date(meta.expiresAt).getTime() > nowMs;
  });
}


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
      discountCode: `ADMIN-${nanoid(8).toUpperCase()}`,
      isActive: true
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

const verifyEmailSchema = z.object({
  email: z.string().email(),
  code: z.string().regex(/^\d{6}$/)
});

const resendCodeSchema = z.object({
  email: z.string().email()
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

  const passwordHash = await bcrypt.hash(password, 12);
  let user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  if (user && user.isActive) {
    return res.status(409).json({ error: 'Account already verified' });
  }

  if (user && user.role !== 'CLIENT') {
    return res.status(409).json({ error: 'Email not available' });
  }

  if (user && !user.isActive) {
    user = await prisma.user.update({
      where: { id: user.id },
      data: {
        name,
        phone: phone || null,
        company: company || null,
        passwordHash,
        isActive: false
      }
    });
  } else {
    let discountCode = generateDiscountCode();
    while (await prisma.user.findUnique({ where: { discountCode } })) discountCode = generateDiscountCode();

    user = await prisma.user.create({
      data: {
        role: 'CLIENT',
        name,
        email: normalizedEmail,
        phone: phone || null,
        company: company || null,
        passwordHash,
        discountCode,
        isActive: false
      }
    });
  }

  try {
    await sendVerificationCode({ user, req });
  } catch (error) {
    console.error('verification email failed', error.message);
    return res.status(503).json({ error: 'Verification code could not be sent' });
  }

  await logActivity(req, 'client_registration_pending', { email: normalizedEmail }, user.id, 'client');

  res.status(202).json({
    ok: true,
    requiresVerification: true,
    email: user.email,
    message: 'Verification code sent'
  });
});

app.post('/api/auth/client/verify-email', async (req, res) => {
  const parsed = verifyEmailSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid verification code' });

  const email = parsed.data.email.toLowerCase().trim();
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user || user.role !== 'CLIENT') {
    return res.status(404).json({ error: 'Account not found' });
  }

  if (user.isActive) {
    const token = setAuthCookie(res, user);
    return res.json({ user: safeUser(user), alreadyVerified: true, token });
  }

  const validLog = await findValidVerificationLog(user, parsed.data.code);
  if (!validLog) {
    await logActivity(req, 'client_email_verification_failed', { email }, user.id, 'client');
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  const activeUser = await prisma.user.update({
    where: { id: user.id },
    data: { isActive: true }
  });

  const token = setAuthCookie(res, activeUser);
  await logActivity(req, 'client_email_verified', { email }, activeUser.id, 'client');

  res.json({ user: safeUser(activeUser), verified: true, token });
});

app.post('/api/auth/client/resend-code', async (req, res) => {
  const parsed = resendCodeSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid email' });

  const email = parsed.data.email.toLowerCase().trim();
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user || user.role !== 'CLIENT') {
    return res.status(404).json({ error: 'Account not found' });
  }

  if (user.isActive) {
    return res.json({ ok: true, alreadyVerified: true });
  }

  try {
    await sendVerificationCode({ user, req });
  } catch (error) {
    console.error('verification resend failed', error.message);
    return res.status(503).json({ error: 'Verification code could not be sent' });
  }

  await logActivity(req, 'client_verification_code_resent', { email }, user.id, 'client');
  res.json({ ok: true, requiresVerification: true, email: user.email });
});

app.post('/api/auth/client/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid data' });

  const user = await prisma.user.findUnique({ where: { email: parsed.data.email.toLowerCase().trim() } });
  if (!user || user.role !== 'CLIENT') return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(parsed.data.password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  if (!user.isActive) {
    return res.status(403).json({
      error: 'Email not verified',
      requiresVerification: true,
      email: user.email
    });
  }

  const token = setAuthCookie(res, user);
  await logActivity(req, 'client_login', { email: user.email }, user.id, 'client');
  res.json({ user: safeUser(user), token });
});

app.post('/api/auth/admin/login', async (req, res) => {
  await ensureAdmin();
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid data' });

  const user = await prisma.user.findUnique({ where: { email: parsed.data.email.toLowerCase().trim() } });
  if (!user || user.role !== 'ADMIN') return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(parsed.data.password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = setAuthCookie(res, user);
  await logActivity(req, 'admin_login', { email: user.email }, user.id, 'admin');
  res.json({ user: safeUser(user), token });
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
    orderBy: { createdAt: 'asc' },
    include: { attachments: { where: clientVisibleAttachmentWhere(), orderBy: { createdAt: 'asc' } } }
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
  if (existing) return res.status(409).json({ error: 'Account already verified' });

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




function requireAuth(role) {
  return [
    authRequired,
    (req, res, next) => {
      if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
      if (role && req.user.role !== role) return res.status(403).json({ error: 'Forbidden' });
      next();
    }
  ];
}



const attachmentSchema = z.object({
  fileName: z.string().min(1).max(180),
  mimeType: z.string().min(1).max(120),
  fileSize: z.number().int().positive().max(MAX_UPLOAD_MB * 1024 * 1024),
  resourceType: z.string().min(1).max(30),
  publicId: z.string().min(1).max(260),
  secureUrl: z.string().url(),
  format: z.string().max(30).optional().nullable(),
  bytes: z.number().int().positive().optional().nullable(),
  duration: z.number().optional().nullable(),
  width: z.number().int().positive().optional().nullable(),
  height: z.number().int().positive().optional().nullable(),
  allowClientDownload: z.boolean().optional().default(false)
});

const messageWithAttachmentsSchema = z.object({
  text: z.string().max(5000).optional().default(''),
  attachments: z.array(attachmentSchema).max(12).optional().default([])
});

// ---------- Cloudinary signed uploads + chat attachments ----------

app.post('/api/client/uploads/signature', requireAuth('CLIENT'), async (req, res) => {
  try {
    assertCloudinaryReady();
    const fileName = cleanFileName(req.body?.fileName || 'client-file');
    const mimeType = String(req.body?.mimeType || 'application/octet-stream');
    const fileSize = Number(req.body?.fileSize || 0);

    if (!fileSize || fileSize > MAX_UPLOAD_MB * 1024 * 1024) {
      return res.status(413).json({ error: `File too large. Max ${MAX_UPLOAD_MB} MB.` });
    }

    const timestamp = Math.round(Date.now() / 1000);
    const resourceType = safeFileKind(mimeType);
    const folder = `preadv/clients/${req.user.id}/chat`;
    const publicId = `${folder}/${Date.now()}-${nanoid(10)}-${fileName.replace(/\.[^.]+$/, '')}`;

    const params = {
      timestamp,
      folder,
      public_id: publicId,
      overwrite: false,
      resource_type: resourceType,
      context: `client_id=${req.user.id}|uploader=client`
    };

    const signature = cloudinary.utils.api_sign_request(params, CLOUDINARY_API_SECRET);

    res.json({
      cloudName: CLOUDINARY_CLOUD_NAME,
      apiKey: CLOUDINARY_API_KEY,
      timestamp,
      signature,
      folder,
      publicId,
      resourceType,
      maxUploadMb: MAX_UPLOAD_MB
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({ error: error.message || 'Upload signature failed' });
  }
});

app.post('/api/admin/uploads/signature', requireAuth('ADMIN'), async (req, res) => {
  try {
    assertCloudinaryReady();
    const clientId = String(req.body?.clientId || '');
    const fileName = cleanFileName(req.body?.fileName || 'admin-file');
    const mimeType = String(req.body?.mimeType || 'application/octet-stream');
    const fileSize = Number(req.body?.fileSize || 0);

    const client = await prisma.user.findUnique({ where: { id: clientId } });
    if (!client || client.role !== 'CLIENT') return res.status(404).json({ error: 'Client not found' });

    if (!fileSize || fileSize > MAX_UPLOAD_MB * 1024 * 1024) {
      return res.status(413).json({ error: `File too large. Max ${MAX_UPLOAD_MB} MB.` });
    }

    const timestamp = Math.round(Date.now() / 1000);
    const resourceType = safeFileKind(mimeType);
    const folder = `preadv/clients/${clientId}/chat`;
    const publicId = `${folder}/${Date.now()}-${nanoid(10)}-${fileName.replace(/\.[^.]+$/, '')}`;

    const params = {
      timestamp,
      folder,
      public_id: publicId,
      overwrite: false,
      resource_type: resourceType,
      context: `client_id=${clientId}|uploader=admin`
    };

    const signature = cloudinary.utils.api_sign_request(params, CLOUDINARY_API_SECRET);

    res.json({
      cloudName: CLOUDINARY_CLOUD_NAME,
      apiKey: CLOUDINARY_API_KEY,
      timestamp,
      signature,
      folder,
      publicId,
      resourceType,
      maxUploadMb: MAX_UPLOAD_MB
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({ error: error.message || 'Upload signature failed' });
  }
});

async function createMessageWithAttachments({ req, clientId, sender, text, attachments }) {
  const cleanText = String(text || '').trim();
  const cleanAttachments = Array.isArray(attachments) ? attachments : [];

  if (!cleanText && !cleanAttachments.length) {
    const error = new Error('Message or attachment required');
    error.statusCode = 400;
    throw error;
  }

  return prisma.chatMessage.create({
    data: {
      clientId,
      sender,
      text: cleanText || (cleanAttachments.length ? 'Allegato condiviso' : ''),
      attachments: {
        create: cleanAttachments.map(att => ({
          clientId,
          uploaderId: req.user.id,
          uploaderRole: sender,
          fileName: cleanFileName(att.fileName),
          mimeType: att.mimeType,
          fileSize: att.fileSize,
          resourceType: att.resourceType || 'auto',
          publicId: att.publicId,
          secureUrl: att.secureUrl,
          format: att.format || null,
          bytes: att.bytes || att.fileSize || null,
          duration: att.duration || null,
          width: att.width || null,
          height: att.height || null,
          allowClientDownload: sender === 'CLIENT' ? true : !!att.allowClientDownload
        }))
      }
    },
    include: { attachments: { orderBy: { createdAt: 'asc' } } }
  });
}

app.post('/api/client/messages-with-files', requireAuth('CLIENT'), async (req, res) => {
  const parsed = messageWithAttachmentsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid message', details: parsed.error.flatten() });

  try {
    const message = await createMessageWithAttachments({
      req,
      clientId: req.user.id,
      sender: 'CLIENT',
      text: parsed.data.text,
      attachments: parsed.data.attachments
    });

    await logActivity(req, 'client_message_files', { attachments: parsed.data.attachments.length }, req.user.id, 'client');
    res.status(201).json({ message: formatMessage(message) });
  } catch (error) {
    res.status(error.statusCode || 500).json({ error: error.message || 'Message failed' });
  }
});

app.post('/api/admin/messages-with-files', requireAuth('ADMIN'), async (req, res) => {
  const parsed = messageWithAttachmentsSchema.extend({ clientId: z.string().min(1) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid message', details: parsed.error.flatten() });

  const client = await prisma.user.findUnique({ where: { id: parsed.data.clientId } });
  if (!client || client.role !== 'CLIENT') return res.status(404).json({ error: 'Client not found' });

  try {
    const message = await createMessageWithAttachments({
      req,
      clientId: parsed.data.clientId,
      sender: 'ADMIN',
      text: parsed.data.text,
      attachments: parsed.data.attachments
    });

    await logActivity(req, 'admin_message_files', { clientId: parsed.data.clientId, attachments: parsed.data.attachments.length }, req.user.id, 'admin');
    res.status(201).json({ message: formatMessage(message) });
  } catch (error) {
    res.status(error.statusCode || 500).json({ error: error.message || 'Message failed' });
  }
});


app.patch('/api/admin/attachments/:id/download', requireAuth('ADMIN'), async (req, res) => {
  const attachment = await prisma.chatAttachment.findUnique({ where: { id: req.params.id } });
  if (!attachment) return res.status(404).json({ error: 'Attachment not found' });

  const allow = !!req.body?.allowClientDownload;
  const updated = await prisma.chatAttachment.update({
    where: { id: attachment.id },
    data: { allowClientDownload: allow }
  });

  await logActivity(req, 'admin_toggle_attachment_download', { attachmentId: attachment.id, allow }, req.user.id, 'admin');
  res.json({ attachment: formatAttachment(updated) });
});


app.delete('/api/admin/attachments/:id', requireAuth('ADMIN'), async (req, res) => {
  const scope = String(req.query.scope || 'admin');
  const attachment = await prisma.chatAttachment.findUnique({ where: { id: req.params.id } });
  if (!attachment) return res.status(404).json({ error: 'Attachment not found' });

  if (scope === 'both') {
    await destroyCloudinaryAsset(attachment);
    await prisma.chatAttachment.update({
      where: { id: attachment.id },
      data: { deletedForAll: true, deletedForAdmin: true, deletedForClient: true }
    });
  } else {
    await prisma.chatAttachment.update({
      where: { id: attachment.id },
      data: { deletedForAdmin: true }
    });
  }

  await logActivity(req, 'admin_delete_attachment', { attachmentId: attachment.id, scope }, req.user.id, 'admin');
  res.json({ ok: true });
});

app.delete('/api/admin/conversations/:clientId/reset', requireAuth('ADMIN'), async (req, res) => {
  const scope = String(req.query.scope || 'both');
  const clientId = req.params.clientId;

  const client = await prisma.user.findUnique({ where: { id: clientId } });
  if (!client || client.role !== 'CLIENT') return res.status(404).json({ error: 'Client not found' });

  const attachments = await prisma.chatAttachment.findMany({
    where: { clientId, deletedForAll: false }
  });

  if (scope === 'both') {
    for (const att of attachments) await destroyCloudinaryAsset(att);
    await prisma.chatAttachment.updateMany({
      where: { clientId },
      data: { deletedForAll: true, deletedForAdmin: true, deletedForClient: true }
    });
    await prisma.chatMessage.deleteMany({ where: { clientId } });
  } else {
    await prisma.chatAttachment.updateMany({
      where: { clientId },
      data: { deletedForAdmin: true }
    });
  }

  await logActivity(req, 'admin_reset_conversation', { clientId, scope }, req.user.id, 'admin');
  res.json({ ok: true, deletedAttachments: attachments.length });
});
