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

// ========================================
// 1. SECURITY MIDDLEWARE
// ========================================
app.use(helmet());

app.use(cors({ 
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com'],
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));

const mongoSanitize = (req, res, next) => {
  const sanitize = (obj) => {
    if (!obj || typeof obj !== 'object') return obj;
    const sanitized = {};
    for (const key in obj) {
      if (key.startsWith('$') || key.includes('.')) {
        console.warn(`⚠️ Blocked: ${key}`);
        continue;
      }
      const value = obj[key];
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        sanitized[key] = sanitize(value);
      } else if (Array.isArray(value)) {
        sanitized[key] = value.map(item => 
          typeof item === 'object' ? sanitize(item) : item
        );
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  };
  
  if (req.body) req.body = sanitize(req.body);
  if (req.params) req.params = sanitize(req.params);
  next();
};

app.use(mongoSanitize);
app.use(hpp());

// ========================================
// 2. RATE LIMITING
// ========================================
const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'GET',
  handler: (req, res) => {
    console.warn(`🚫 Rate limit exceeded`);
    res.status(429).json({
      status: 'error',
      message: 'Terlalu banyak request. Tunggu 10 menit.'
    });
  }
});

const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: false,
  handler: (req, res) => {
    console.warn(`📧 Email limit exceeded`);
    res.status(429).json({
      status: 'error',
      message: 'Anda sudah mengirim 5 pesan dalam 1 jam.'
    });
  }
});

// ========================================
// 3. DATABASE CONNECTION
// ========================================
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

// ========================================
// 4. DATABASE MODEL ✅ FIXED
// ========================================
const InquirySchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true,
    maxlength: 100,
    trim: true,
    lowercase: true,
    index: true
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
    default: Date.now
  }
});

// ✅ SATU INDEX AJA UNTUK createdAt dengan TTL
InquirySchema.index({ createdAt: 1 }, { expireAfterSeconds: 2592000 });

const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', InquirySchema);

// ========================================
// 5. HELPER FUNCTIONS
// ========================================
const verifyRecaptcha = async (token, remoteIp) => {
  if (!token) {
    console.warn('⚠️ No reCAPTCHA token');
    return { success: false, error: 'Token missing', score: 0 };
  }
  
  const secretKey = process.env.RECAPTCHA_SECRET_KEY; 
  if (!secretKey) {
    console.error('❌ RECAPTCHA_SECRET_KEY not set!');
    return { success: false, error: 'Server misconfiguration', score: 0 };
  }

  try {
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${secretKey}&response=${token}&remoteip=${remoteIp}`
    });
    
    if (!response.ok) throw new Error(`reCAPTCHA API: ${response.status}`);
    
    const result = await response.json();
    console.log(`🔐 reCAPTCHA - Success: ${result.success}, Score: ${result.score || 'N/A'}`);
    return result;
  } catch (error) {
    console.error('❌ reCAPTCHA Error:', error.message);
    return { success: false, error: error.message, score: 0 };
  }
};

const sanitizeAndValidate = (email, whatsapp, pesan) => {
  const cleanEmail = xss(email?.toString() || '').trim();
  let cleanWhatsapp = xss(whatsapp?.toString() || '').trim();
  const cleanPesan = xss(pesan?.toString() || '').trim();
  
  if (!validator.isEmail(cleanEmail)) {
    throw new Error('Format email tidak valid');
  }
  
  cleanWhatsapp = cleanWhatsapp.replace(/[\s\-\(\)]/g, '');
  
  if (cleanWhatsapp.startsWith('08')) {
    cleanWhatsapp = '+62' + cleanWhatsapp.substring(1);
  } else if (cleanWhatsapp.startsWith('62') && !cleanWhatsapp.startsWith('+')) {
    cleanWhatsapp = '+' + cleanWhatsapp;
  } else if (!cleanWhatsapp.startsWith('+') && !cleanWhatsapp.startsWith('62')) {
    cleanWhatsapp = '+62' + cleanWhatsapp;
  }
  
  if (!/^\+?[1-9]\d{7,14}$/.test(cleanWhatsapp)) {
    throw new Error('Format WhatsApp tidak valid. Contoh: 08123456789');
  }
  
  if (cleanPesan.length < 10 || cleanPesan.length > 1000) {
    throw new Error('Pesan harus 10-1000 karakter');
  }
  
  return { email: cleanEmail, whatsapp: cleanWhatsapp, pesan: cleanPesan };
};

// ========================================
// 6. ROUTES
// ========================================
app.get('/api/index', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    message: 'Server Marz Store Running',
    timestamp: new Date().toISOString()
  });
});

app.post('/api/index', apiLimiter, emailLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { email: rawEmail, whatsapp: rawWhatsapp, pesan: rawPesan, captchaToken } = req.body;
    
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                     req.headers['x-real-ip'] || req.ip;
    
    console.log(`📨 [${new Date().toISOString()}] From: ${clientIp}`);
    console.log(`📝 ${rawEmail}, ${rawWhatsapp}`);
    
    const recaptchaResult = await verifyRecaptcha(captchaToken, clientIp);
    
    if (!recaptchaResult.success) {
      console.error(`❌ reCAPTCHA failed:`, recaptchaResult.error);
      return res.status(403).json({ 
        status: 'error', 
        message: 'Verifikasi gagal. Refresh dan coba lagi.'
      });
    }
    
    if (recaptchaResult.score && recaptchaResult.score < 0.5) {
      console.warn(`🤖 Low score: ${recaptchaResult.score}`);
      return res.status(403).json({ 
        status: 'error', 
        message: 'Verifikasi gagal. Refresh dan coba lagi.' 
      });
    }
    
    let validated;
    try {
      validated = sanitizeAndValidate(rawEmail, rawWhatsapp, rawPesan);
      console.log(`✅ Valid: ${validated.email}, ${validated.whatsapp}`);
    } catch (validationError) {
      console.warn(`⚠️ Invalid: ${validationError.message}`);
      return res.status(400).json({ 
        status: 'error', 
        message: validationError.message 
      });
    }
    
    await connectDB();
    
    const recentInquiry = await Inquiry.findOne({
      email: validated.email,
      createdAt: { $gte: new Date(Date.now() - 3600000) }
    });
    
    if (recentInquiry) {
      console.warn(`🔄 Duplicate: ${validated.email}`);
      return res.status(429).json({
        status: 'error',
        message: 'Anda sudah mengirim dalam 1 jam terakhir.'
      });
    }
    
    const newLead = new Inquiry({ ...validated, ipAddress: clientIp });
    await newLead.save();
    console.log(`✅ Saved: ${validated.email}`);
    
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
        subject: `🔔 KONSULTASI: ${validated.email}`,
        html: `
          <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #2563eb; border-bottom: 3px solid #2563eb; padding-bottom: 10px;">📩 Inquiry Baru</h2>
            <table style="width: 100%; border-collapse: collapse;">
              <tr style="background: #f3f4f6;">
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Email:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">${validated.email}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">WhatsApp:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">
                  <a href="https://wa.me/${validated.whatsapp.replace(/\D/g, '')}" style="color: #2563eb; font-weight: bold;">
                    ${validated.whatsapp} 📱
                  </a>
                </td>
              </tr>
              <tr style="background: #f3f4f6;">
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold; vertical-align: top;">Pesan:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">${validated.pesan}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">IP:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">${clientIp}</td>
              </tr>
              <tr style="background: #f3f4f6;">
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Score:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">
                  <span style="color: ${recaptchaResult.score >= 0.7 ? '#10b981' : '#f59e0b'}; font-weight: bold;">
                    ${recaptchaResult.score || 'N/A'} ${recaptchaResult.score >= 0.7 ? '✅' : '⚠️'}
                  </span>
                </td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Waktu:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">
                  ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}
                </td>
              </tr>
            </table>
            <div style="margin-top: 20px; padding: 20px; background: linear-gradient(135deg, #667eea, #764ba2); border-radius: 8px; text-align: center;">
              <p style="margin: 0; color: white; font-size: 18px; font-weight: bold;">⚡ FOLLOW UP SEKARANG!</p>
              <a href="https://wa.me/${validated.whatsapp.replace(/\D/g, '')}" 
                 style="display: inline-block; margin-top: 15px; padding: 12px 24px; background: #25D366; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">
                💬 Chat WhatsApp
              </a>
            </div>
          </div>
        `
      });
      console.log(`✅ Email sent`);
    } catch (emailError) {
      console.error('❌ Email:', emailError.message);
    }
    
    console.log(`✅ Done in ${Date.now() - startTime}ms`);
    res.status(200).json({ 
      status: 'success', 
      message: 'Terima kasih! Kami akan segera menghubungi Anda.' 
    });
    
  } catch (err) {
    console.error("❌ Error:", err.message);
    res.status(500).json({ 
      status: 'error', 
      message: 'Sistem sibuk. Coba lagi.'
    });
  }
});

app.use((err, req, res, next) => {
  console.error('❌ Unhandled:', err.message);
  res.status(500).json({ status: 'error', message: 'Internal error' });
});

process.on('SIGTERM', async () => {
  console.log('⚠️ SIGTERM');
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('⚠️ SIGINT');
  await mongoose.connection.close();
  process.exit(0);
});

module.exports = app;
