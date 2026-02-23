const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const xss = require('xss');
const helmet = require('helmet');
const hpp = require('hpp');
const rateLimit = require('express-rate-limit');
const validator = require('validator');

const app = express();
app.set('trust proxy', 1);

// -- Middleware keamanan --
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));

// Blok MongoDB injection ($, .)
const mongoSanitize = (req, _res, next) => {
  const sanitize = (obj) => {
    if (!obj || typeof obj !== 'object') return obj;
    return Object.fromEntries(
      Object.entries(obj)
        .filter(([key]) => !key.startsWith('$') && !key.includes('.'))
        .map(([key, val]) => [
          key,
          Array.isArray(val)
            ? val.map(i => typeof i === 'object' ? sanitize(i) : i)
            : typeof val === 'object' ? sanitize(val) : val
        ])
    );
  };
  if (req.body) req.body = sanitize(req.body);
  if (req.params) req.params = sanitize(req.params);
  next();
};
app.use(mongoSanitize);
app.use(hpp());

// -- Rate limiter --
const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, max: 15,
  standardHeaders: true, legacyHeaders: false,
  skip: req => req.method === 'GET',
  handler: (_req, res) => res.status(429).json({ status: 'error', message: 'Terlalu banyak request. Tunggu 10 menit.' })
});

const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5,
  skipSuccessfulRequests: false,
  handler: (_req, res) => res.status(429).json({ status: 'error', message: 'Anda sudah mengirim 5 pesan dalam 1 jam.' })
});

// -- Database (idempoten, aman dipanggil berkali-kali) --
const connectDB = async () => {
  if (mongoose.connection.readyState >= 1) return;
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI tidak dikonfigurasi');
  await mongoose.connect(process.env.MONGODB_URI, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 30000,
    socketTimeoutMS: 45000,
  });
  console.log(`[DB] Connected: ${mongoose.connection.db.databaseName}`);
};
mongoose.connection.on('error', err => console.error('[DB] Error:', err.message));
mongoose.connection.on('disconnected', () => console.warn('[DB] Disconnected'));

// -- Schema (auto-delete 30 hari) --
const InquirySchema = new mongoose.Schema({
  email:     { type: String, required: true, maxlength: 100, trim: true, lowercase: true, index: true },
  whatsapp:  { type: String, required: true, maxlength: 20, trim: true },
  pesan:     { type: String, required: true, maxlength: 1000, trim: true },
  ipAddress: { type: String },
  createdAt: { type: Date, default: Date.now }
});
InquirySchema.index({ createdAt: 1 }, { expireAfterSeconds: 2592000 });
const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', InquirySchema);

// -- Email transporter (pool agar koneksi SMTP di-reuse) --
const transporter = nodemailer.createTransport({
  service: 'gmail', pool: true, maxConnections: 3,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// -- Verify reCAPTCHA --
const verifyRecaptcha = async (token, remoteIp) => {
  if (!token) return { success: false };
  const secretKey = process.env.RECAPTCHA_SECRET_KEY;
  if (!secretKey) { console.error('[reCAPTCHA] Secret key tidak dikonfigurasi'); return { success: false }; }
  const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `secret=${secretKey}&response=${token}&remoteip=${remoteIp}`
  });
  if (!response.ok) throw new Error(`reCAPTCHA API error: ${response.status}`);
  return response.json();
};

// -- Sanitasi & validasi input --
const sanitizeAndValidate = (email, whatsapp, pesan) => {
  const cleanEmail = xss(email?.toString() || '').trim();
  let   cleanWa    = xss(whatsapp?.toString() || '').trim();
  const cleanPesan = xss(pesan?.toString() || '').trim();

  if (!validator.isEmail(cleanEmail)) throw new Error('Format email tidak valid');

  cleanWa = cleanWa.replace(/[\s\-\(\)]/g, '');
  if      (cleanWa.startsWith('08'))                               cleanWa = '+62' + cleanWa.slice(1);
  else if (cleanWa.startsWith('62') && !cleanWa.startsWith('+'))  cleanWa = '+' + cleanWa;
  else if (!cleanWa.startsWith('+') && !cleanWa.startsWith('62')) cleanWa = '+62' + cleanWa;

  if (!/^\+?[1-9]\d{7,14}$/.test(cleanWa)) throw new Error('Format WhatsApp tidak valid');
  if (cleanPesan.length < 10 || cleanPesan.length > 1000) throw new Error('Pesan harus 10-1000 karakter');

  return { email: cleanEmail, whatsapp: cleanWa, pesan: cleanPesan };
};

// -- Kirim email notifikasi (fire-and-forget) --
const sendEmailNotification = (validated, clientIp, recaptchaScore) => {
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">
      <h2 style="color:#2563eb">Detail Inquiry Baru</h2>
      <table style="width:100%;border-collapse:collapse">
        <tr style="background:#f3f4f6">
          <td style="padding:12px;border:1px solid #ddd;font-weight:bold">Email</td>
          <td style="padding:12px;border:1px solid #ddd">${validator.escape(validated.email)}</td>
        </tr>
        <tr>
          <td style="padding:12px;border:1px solid #ddd;font-weight:bold">WhatsApp</td>
          <td style="padding:12px;border:1px solid #ddd">
            <a href="https://wa.me/${validated.whatsapp.replace(/\D/g, '')}">${validator.escape(validated.whatsapp)}</a>
          </td>
        </tr>
        <tr style="background:#f3f4f6">
          <td style="padding:12px;border:1px solid #ddd;font-weight:bold">Pesan</td>
          <td style="padding:12px;border:1px solid #ddd">${validator.escape(validated.pesan)}</td>
        </tr>
        <tr>
          <td style="padding:12px;border:1px solid #ddd;font-weight:bold">IP</td>
          <td style="padding:12px;border:1px solid #ddd">${validator.escape(clientIp)}</td>
        </tr>
        <tr style="background:#f3f4f6">
          <td style="padding:12px;border:1px solid #ddd;font-weight:bold">reCAPTCHA Score</td>
          <td style="padding:12px;border:1px solid #ddd">${recaptchaScore ?? 'N/A'}</td>
        </tr>
        <tr>
          <td style="padding:12px;border:1px solid #ddd;font-weight:bold">Waktu</td>
          <td style="padding:12px;border:1px solid #ddd">${new Date().toLocaleString('id-ID')}</td>
        </tr>
      </table>
    </div>`;
  transporter.sendMail({
    from: `"MARZ SYSTEM" <${process.env.EMAIL_USER}>`,
    to: process.env.EMAIL_USER,
    subject: `KONSULTASI BARU: ${validated.email}`,
    html
  }.then(info => console.log('[Email] Terkirim:', info.messageId))
    .catch(err => console.error('[Email] Gagal - code:', err.code, '| msg:', err.message));
};

// -- Routes --
app.get('/api/index', (_req, res) => {
  res.json({ status: 'ok', message: 'Server Marz Store Running', timestamp: new Date().toISOString() });
});

app.post('/api/index', apiLimiter, emailLimiter, async (req, res) => {
  const startTime = Date.now();
  try {
    await connectDB(); // Vercel serverless: connect per-request

    const { email: rawEmail, whatsapp: rawWa, pesan: rawPesan, captchaToken } = req.body;
    const clientIp =
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.headers['x-real-ip'] ||
      req.socket?.remoteAddress ||
      req.ip;

    // Validasi & reCAPTCHA paralel
    let validated, recaptchaResult;
    try {
      [validated, recaptchaResult] = await Promise.all([
        Promise.resolve().then(() => sanitizeAndValidate(rawEmail, rawWa, rawPesan)),
        verifyRecaptcha(captchaToken, clientIp)
      ]);
    } catch (err) {
      if (err.message.includes('tidak valid') || err.message.includes('karakter'))
        return res.status(400).json({ status: 'error', message: err.message });
      throw err;
    }

    if (!recaptchaResult.success || (recaptchaResult.score != null && recaptchaResult.score < 0.5)) {
      console.warn(`[Security] reCAPTCHA gagal | score: ${recaptchaResult.score}`);
      return res.status(403).json({ status: 'error', message: 'Verifikasi keamanan gagal. Silakan refresh halaman dan coba lagi.' });
    }

    // Cek duplikat dalam 1 jam
    const recentInquiry = await Inquiry.findOne({
      email: validated.email,
      createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
    }).lean();

    if (recentInquiry)
      return res.status(429).json({ status: 'error', message: 'Anda sudah mengirim inquiry dalam 1 jam terakhir.' });

    await Inquiry.create({ ...validated, ipAddress: clientIp });
    sendEmailNotification(validated, clientIp, recaptchaResult.score);

    console.log(`[OK] Inquiry saved in ${Date.now() - startTime}ms`);
    return res.status(200).json({ status: 'success', message: 'Terima kasih! Pesan Anda sudah diterima. Tim kami akan segera menghubungi Anda.' });

  } catch (err) {
    console.error('[Error]', err.message);
    return res.status(500).json({
      status: 'error',
      message: 'Sistem sedang sibuk. Silakan coba lagi dalam beberapa saat.',
      ...(process.env.NODE_ENV === 'development' && { detail: err.message })
    });
  }
});

// -- Global error handler --
app.use((err, _req, res, _next) => {
  console.error('[Unhandled]', err.message);
  res.status(500).json({ status: 'error', message: 'Internal server error' });
});

module.exports = app;
