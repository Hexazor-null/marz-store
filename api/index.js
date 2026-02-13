const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const xss = require('xss');
const helmet = require('helmet');
const hpp = require('hpp');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const validator = require('validator');

const app = express();

// 1. SECURITY MIDDLEWARE
app.use(helmet());

// CORS - Whitelist domain Anda
app.use(cors({ 
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com'],
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));

// ✅ FIX UNTUK ERROR: TypeError: Cannot set property query
// Konfigurasi khusus untuk serverless environment (Vercel/Lambda)
app.use(mongoSanitize({
  replaceWith: '_',
  allowDots: true,
  onSanitize: ({ req, key }) => {
    console.warn(`⚠️ Sanitized dangerous key: ${key}`);
  }
}));

app.use(hpp());

// 2. ✅ RATE LIMITING - UDAH DIBENERIN (LEBIH LONGGAR)
const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 menit
  max: 15, // 15 request per 10 menit
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limit untuk GET request (health check)
    if (req.method === 'GET') return true;
    
    // Optional: Skip untuk IP trusted
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    const trustedIps = process.env.TRUSTED_IPS?.split(',') || [];
    return trustedIps.includes(clientIp);
  },
  handler: (req, res) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    console.warn(`🚫 API Rate limit exceeded: ${clientIp}`);
    
    res.status(429).json({
      status: 'error',
      message: 'Terlalu banyak request dari IP Anda. Silakan tunggu 10 menit.'
    });
  }
});

const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 jam
  max: 5, // 5 email per jam (naik dari 3)
  skipSuccessfulRequests: false,
  handler: (req, res) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    console.warn(`📧 Email rate limit exceeded: ${clientIp}`);
    
    res.status(429).json({
      status: 'error',
      message: 'Anda sudah mengirim 5 pesan dalam 1 jam. Hubungi WhatsApp kami untuk respon cepat.',
      whatsapp: process.env.WHATSAPP_NUMBER || '+628xxxx'
    });
  }
});

// 3. DB CONNECTION dengan error handling
const connectDB = async () => {
  if (mongoose.connection.readyState >= 1) return;
  
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log("✅ MongoDB Connected");
  } catch (err) {
    console.error("❌ DB Error:", err.message);
    throw err;
  }
};

// 4. DATABASE MODEL dengan validasi ketat
const InquirySchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true,
    maxlength: 100,
    trim: true,
    lowercase: true
  },
  whatsapp: { 
    type: String, 
    required: true,
    maxlength: 20,
    trim: true
  },
  pesan: { 
    type: String, 
    required: true,
    maxlength: 1000, 
    trim: true
  },
  ipAddress: { 
    type: String,
    required: false
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    expires: 2592000 // 30 hari auto-delete
  }
});

// Index untuk performa
InquirySchema.index({ email: 1 });
InquirySchema.index({ createdAt: 1 });

const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', InquirySchema);

// 5. HELPER FUNCTIONS
const verifyRecaptcha = async (token, remoteIp) => {
  if (!token) return { success: false, error: 'Token missing', score: 0 };
  
  const secretKey = process.env.RECAPTCHA_SECRET_KEY; 
  
  if (!secretKey) {
    console.error('❌ RECAPTCHA_SECRET_KEY not configured!');
    return { success: false, error: 'Server misconfiguration', score: 0 };
  }

  try {
    const verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
    const response = await fetch(verifyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${secretKey}&response=${token}&remoteip=${remoteIp}`
    });
    
    if (!response.ok) {
      throw new Error('reCAPTCHA verification failed');
    }
    
    const result = await response.json();
    console.log(`🔐 reCAPTCHA Score: ${result.score || 'N/A'}`);
    return result;
  } catch (error) {
    console.error('❌ reCAPTCHA Error:', error);
    return { success: false, error: 'Verification failed', score: 0 };
  }
};

const sanitizeAndValidate = (email, whatsapp, pesan) => {
  // Sanitasi XSS
  const cleanEmail = xss(email?.toString() || '').trim();
  const cleanWhatsapp = xss(whatsapp?.toString() || '').trim();
  const cleanPesan = xss(pesan?.toString() || '').trim();
  
  // Validasi Email
  if (!validator.isEmail(cleanEmail)) {
    throw new Error('Format email tidak valid');
  }
  
  // Validasi WhatsApp (international format)
  const phoneRegex = /^\+?[1-9]\d{7,14}$/;
  if (!phoneRegex.test(cleanWhatsapp)) {
    throw new Error('Format nomor WhatsApp tidak valid (contoh: +628123456789)');
  }
  
  // Validasi Panjang
  if (cleanPesan.length < 10 || cleanPesan.length > 1000) {
    throw new Error('Pesan harus 10-1000 karakter');
  }
  
  return { email: cleanEmail, whatsapp: cleanWhatsapp, pesan: cleanPesan };
};

// 6. ROUTES
app.get('/api/index', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    message: 'Server Marz Store Running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// POST dengan FULL PROTECTION
app.post('/api/index', apiLimiter, emailLimiter, async (req, res) => {
  try {
    const { email: rawEmail, whatsapp: rawWhatsapp, pesan: rawPesan, captchaToken } = req.body;
    
    // A. GET CLIENT IP
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || 
                     req.headers['x-real-ip'] ||
                     req.socket.remoteAddress || 
                     req.ip;
    
    console.log(`📨 New request from IP: ${clientIp}`);
    
    // B. VERIFIKASI RECAPTCHA
    const recaptchaResult = await verifyRecaptcha(captchaToken, clientIp);
    
    if (!recaptchaResult.success || (recaptchaResult.score && recaptchaResult.score < 0.5)) {
      console.warn(`🤖 Bot detected from IP: ${clientIp}, Score: ${recaptchaResult.score || 'N/A'}`);
      return res.status(403).json({ 
        status: 'error', 
        message: 'Verifikasi keamanan gagal. Silakan refresh halaman dan coba lagi.' 
      });
    }
    
    // C. VALIDASI & SANITASI
    let validated;
    try {
      validated = sanitizeAndValidate(rawEmail, rawWhatsapp, rawPesan);
    } catch (validationError) {
      console.warn(`⚠️ Validation failed: ${validationError.message}`);
      return res.status(400).json({ 
        status: 'error', 
        message: validationError.message 
      });
    }
    
    // D. CONNECT DB
    await connectDB();
    
    // E. CHECK DUPLICATE (prevent spam dari user yang sama)
    const recentInquiry = await Inquiry.findOne({
      email: validated.email,
      createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // 1 jam terakhir
    });
    
    if (recentInquiry) {
      console.warn(`🔄 Duplicate inquiry from: ${validated.email}`);
      return res.status(429).json({
        status: 'error',
        message: 'Anda sudah mengirim inquiry dalam 1 jam terakhir. Mohon tunggu sebentar.'
      });
    }
    
    // F. SIMPAN KE DATABASE
    const newLead = new Inquiry({ 
      ...validated,
      ipAddress: clientIp
    });
    await newLead.save();
    console.log(`✅ New inquiry saved: ${validated.email}`);
    
    // G. KIRIM EMAIL (dengan error handling - tidak blocking response)
    try {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      });
      
      await transporter.sendMail({
        from: `"MARZ SYSTEM" <${process.env.EMAIL_USER}>`,
        to: process.env.EMAIL_USER,
        subject: `🔔 KONSULTASI BARU: ${validated.email}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9fafb;">
            <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
              <h2 style="color: #2563eb; margin-top: 0;">📩 Detail Inquiry Baru</h2>
              <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr style="background: #f3f4f6;">
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold; width: 150px;">Email:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">${validated.email}</td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">WhatsApp:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">
                    <a href="https://wa.me/${validated.whatsapp.replace(/[^0-9]/g, '')}" style="color: #2563eb; text-decoration: none;">
                      ${validated.whatsapp}
                    </a>
                  </td>
                </tr>
                <tr style="background: #f3f4f6;">
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold; vertical-align: top;">Pesan:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">${validated.pesan}</td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">IP Address:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">${clientIp}</td>
                </tr>
                <tr style="background: #f3f4f6;">
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">Bot Score:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">
                    <span style="color: ${recaptchaResult.score >= 0.7 ? '#10b981' : recaptchaResult.score >= 0.5 ? '#f59e0b' : '#ef4444'}; font-weight: bold;">
                      ${recaptchaResult.score || 'N/A'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">Waktu:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}</td>
                </tr>
              </table>
              <div style="margin-top: 20px; padding: 15px; background-color: #dbeafe; border-left: 4px solid #2563eb; border-radius: 4px;">
                <p style="margin: 0; color: #1e40af; font-weight: bold;">⚡ Action Required:</p>
                <p style="margin: 5px 0 0 0; color: #1e3a8a;">Segera follow up lead ini dalam 1 jam untuk conversion rate maksimal!</p>
              </div>
            </div>
          </div>
        `
      });
      console.log(`📧 Email sent successfully to ${process.env.EMAIL_USER}`);
    } catch (emailError) {
      console.error('❌ Email Error:', emailError.message);
      // TIDAK BLOCKING RESPONSE - Email gagal tapi data tetap tersimpan
    }
    
    // H. RESPONSE SUCCESS
    res.status(200).json({ 
      status: 'success', 
      message: 'Terima kasih! Pesan Anda sudah diterima. Tim kami akan segera menghubungi Anda.' 
    });
    
  } catch (err) {
    console.error("❌ Backend Error:", err);
    res.status(500).json({ 
      status: 'error', 
      message: 'Terjadi kesalahan sistem. Silakan coba lagi atau hubungi kami via WhatsApp.' 
    });
  }
});

// 7. ERROR HANDLER
app.use((err, req, res, next) => {
  console.error('❌ Unhandled Error:', err);
  
  // Jangan expose error detail ke user
  res.status(500).json({ 
    status: 'error', 
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

// 8. GRACEFUL SHUTDOWN (untuk production)
process.on('SIGTERM', async () => {
  console.log('⚠️ SIGTERM received, closing MongoDB connection...');
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('⚠️ SIGINT received, closing MongoDB connection...');
  await mongoose.connection.close();
  process.exit(0);
});

// 9. HANDLE UNCAUGHT EXCEPTIONS
process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
});

module.exports = app;
