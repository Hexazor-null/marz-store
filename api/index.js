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

// 2. RATE LIMITING (CRITICAL!)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 5, // 5 request per IP
  message: 'Terlalu banyak request, coba lagi nanti',
  standardHeaders: true,
  legacyHeaders: false,
});

const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 jam
  max: 3, // 3 email per IP per jam
  skipSuccessfulRequests: false
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
    throw err; // Jangan biarkan app jalan tanpa DB
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

const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', InquirySchema);

// 5. HELPER FUNCTIONS
const verifyRecaptcha = async (token, remoteIp) => {
  if (!token) return { success: false, error: 'Token missing' };
  
  const secretKey = process.env.RECAPTCHA_SECRET_KEY; 
  
  if (!secretKey) {
    console.error('❌ RECAPTCHA_SECRET_KEY not configured!');
    return { success: false, error: 'Server misconfiguration' };
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
    console.log(`🔐 reCAPTCHA Score: ${result.score}`);
    return result;
  } catch (error) {
    console.error('❌ reCAPTCHA Error:', error);
    return { success: false, error: 'Verification failed' };
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
    throw new Error('Format nomor WhatsApp tidak valid (gunakan format: +628xxx)');
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
    
    // A. VERIFIKASI RECAPTCHA
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || 
                     req.socket.remoteAddress || 
                     req.ip;
    
    const recaptchaResult = await verifyRecaptcha(captchaToken, clientIp);
    
    if (!recaptchaResult.success || recaptchaResult.score < 0.5) {
      console.warn(`🤖 Bot detected from IP: ${clientIp}, Score: ${recaptchaResult.score}`);
      return res.status(403).json({ 
        status: 'error', 
        message: 'Verifikasi keamanan gagal. Silakan refresh dan coba lagi.' 
      });
    }
    
    // B. VALIDASI & SANITASI
    let validated;
    try {
      validated = sanitizeAndValidate(rawEmail, rawWhatsapp, rawPesan);
    } catch (validationError) {
      return res.status(400).json({ 
        status: 'error', 
        message: validationError.message 
      });
    }
    
    // C. CONNECT DB
    await connectDB();
    
    // D. CHECK DUPLICATE (prevent spam dari user yang sama)
    const recentInquiry = await Inquiry.findOne({
      email: validated.email,
      createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // 1 jam terakhir
    });
    
    if (recentInquiry) {
      return res.status(429).json({
        status: 'error',
        message: 'Anda sudah mengirim inquiry. Mohon tunggu 1 jam.'
      });
    }
    
    // E. SIMPAN KE DATABASE
    const newLead = new Inquiry({ 
      ...validated,
      ipAddress: clientIp
    });
    await newLead.save();
    console.log(`✅ New inquiry saved: ${validated.email}`);
    
    // F. KIRIM EMAIL (dengan error handling)
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
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #2563eb;">📩 Detail Inquiry Baru</h2>
            <table style="width: 100%; border-collapse: collapse;">
              <tr style="background: #f3f4f6;">
                <td style="padding: 12px; border: 1px solid #e5e7eb;"><strong>Email:</strong></td>
                <td style="padding: 12px; border: 1px solid #e5e7eb;">${validated.email}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #e5e7eb;"><strong>WhatsApp:</strong></td>
                <td style="padding: 12px; border: 1px solid #e5e7eb;">${validated.whatsapp}</td>
              </tr>
              <tr style="background: #f3f4f6;">
                <td style="padding: 12px; border: 1px solid #e5e7eb;"><strong>Pesan:</strong></td>
                <td style="padding: 12px; border: 1px solid #e5e7eb;">${validated.pesan}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #e5e7eb;"><strong>IP Address:</strong></td>
                <td style="padding: 12px; border: 1px solid #e5e7eb;">${clientIp}</td>
              </tr>
              <tr style="background: #f3f4f6;">
                <td style="padding: 12px; border: 1px solid #e5e7eb;"><strong>Bot Score:</strong></td>
                <td style="padding: 12px; border: 1px solid #e5e7eb;">${recaptchaResult.score}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #e5e7eb;"><strong>Waktu:</strong></td>
                <td style="padding: 12px; border: 1px solid #e5e7eb;">${new Date().toLocaleString('id-ID')}</td>
              </tr>
            </table>
            <p style="margin-top: 20px; color: #6b7280;">Segera follow up lead ini! 🚀</p>
          </div>
        `
      });
      console.log(`📧 Email sent successfully to ${process.env.EMAIL_USER}`);
    } catch (emailError) {
      console.error('❌ Email Error:', emailError.message);
      // Jangan block response meskipun email gagal
    }
    
    res.status(200).json({ 
      status: 'success', 
      message: 'Terima kasih! Kami akan segera menghubungi Anda.' 
    });
    
  } catch (err) {
    console.error("❌ Backend Error:", err);
    res.status(500).json({ 
      status: 'error', 
      message: 'Terjadi kesalahan sistem. Silakan coba lagi.' 
    });
  }
});

// 7. ERROR HANDLER
app.use((err, req, res, next) => {
  console.error('❌ Unhandled Error:', err);
  res.status(500).json({ 
    status: 'error', 
    message: 'Internal server error' 
  });
});

// 8. GRACEFUL SHUTDOWN (untuk production)
process.on('SIGTERM', async () => {
  console.log('⚠️ SIGTERM received, closing MongoDB connection...');
  await mongoose.connection.close();
  process.exit(0);
});

module.exports = app;
