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

// ========================================
// 1. SECURITY MIDDLEWARE
// ========================================
app.use(helmet());

app.use(cors({ 
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com'],
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));

// ✅ CUSTOM MONGO SANITIZATION (Pengganti express-mongo-sanitize)
const mongoSanitize = (req, res, next) => {
  const sanitize = (obj) => {
    if (!obj || typeof obj !== 'object') return obj;
    
    const sanitized = {};
    
    for (const key in obj) {
      // Blokir key berbahaya yang mengandung $ atau .
      if (key.startsWith('$') || key.includes('.')) {
        console.warn(`⚠️ Blocked dangerous key: ${key}`);
        continue;
      }
      
      const value = obj[key];
      
      // Recursive sanitization untuk nested objects
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
  
  // Sanitize req.body
  if (req.body) {
    req.body = sanitize(req.body);
  }
  
  // Sanitize req.params
  if (req.params) {
    req.params = sanitize(req.params);
  }
  
  // Skip req.query untuk avoid error di serverless
  
  next();
};

app.use(mongoSanitize);
app.use(hpp());

// ========================================
// 2. RATE LIMITING
// ========================================
const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 menit
  max: 15, // 15 request per 10 menit
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limit untuk GET request
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
  max: 5, // 5 email per jam
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

// ========================================
// 3. DATABASE CONNECTION
// ========================================
const connectDB = async () => {
  if (mongoose.connection.readyState >= 1) {
    return;
  }
  
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log("✅ MongoDB Connected");
  } catch (err) {
    console.error("❌ DB Connection Error:", err.message);
    throw err;
  }
};

// ========================================
// 4. DATABASE MODEL
// ========================================
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

// Index untuk performa query
InquirySchema.index({ email: 1 });
InquirySchema.index({ createdAt: 1 });

const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', InquirySchema);

// ========================================
// 5. HELPER FUNCTIONS
// ========================================

// Verify reCAPTCHA v3
const verifyRecaptcha = async (token, remoteIp) => {
  if (!token) {
    console.warn('⚠️ No reCAPTCHA token provided');
    return { success: false, error: 'Token missing', score: 0 };
  }
  
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
      throw new Error(`reCAPTCHA API returned ${response.status}`);
    }
    
    const result = await response.json();
    console.log(`🔐 reCAPTCHA - Success: ${result.success}, Score: ${result.score || 'N/A'}`);
    
    return result;
  } catch (error) {
    console.error('❌ reCAPTCHA Error:', error.message);
    return { success: false, error: error.message, score: 0 };
  }
};

// Sanitize & Validate Input
const sanitizeAndValidate = (email, whatsapp, pesan) => {
  // Sanitasi XSS
  const cleanEmail = xss(email?.toString() || '').trim();
  const cleanWhatsapp = xss(whatsapp?.toString() || '').trim();
  const cleanPesan = xss(pesan?.toString() || '').trim();
  
  // Validasi Email
  if (!validator.isEmail(cleanEmail)) {
    throw new Error('Format email tidak valid');
  }
  
  // Validasi WhatsApp (format internasional)
  const phoneRegex = /^\+?[1-9]\d{7,14}$/;
  if (!phoneRegex.test(cleanWhatsapp)) {
    throw new Error('Format nomor WhatsApp tidak valid (contoh: +628123456789)');
  }
  
  // Validasi Panjang Pesan
  if (cleanPesan.length < 10 || cleanPesan.length > 1000) {
    throw new Error('Pesan harus 10-1000 karakter');
  }
  
  return { 
    email: cleanEmail, 
    whatsapp: cleanWhatsapp, 
    pesan: cleanPesan 
  };
};

// ========================================
// 6. ROUTES
// ========================================

// Health Check Endpoint
app.get('/api/index', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    message: 'Server Marz Store Running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Main POST Endpoint dengan Full Protection
app.post('/api/index', apiLimiter, emailLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { email: rawEmail, whatsapp: rawWhatsapp, pesan: rawPesan, captchaToken } = req.body;
    
    // Get Client IP
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || 
                     req.headers['x-real-ip'] ||
                     req.socket.remoteAddress || 
                     req.ip;
    
    console.log(`📨 [${new Date().toISOString()}] New request from IP: ${clientIp}`);
    console.log(`📝 Data: ${rawEmail}, ${rawWhatsapp}`);
    
    // A. VERIFIKASI RECAPTCHA
    const recaptchaResult = await verifyRecaptcha(captchaToken, clientIp);
    
    if (!recaptchaResult.success) {
      console.error(`❌ reCAPTCHA verification failed:`, recaptchaResult.error);
      return res.status(403).json({ 
        status: 'error', 
        message: 'Verifikasi keamanan gagal. Silakan refresh halaman dan coba lagi.'
      });
    }
    
    // Check reCAPTCHA score (untuk v3)
    if (recaptchaResult.score && recaptchaResult.score < 0.5) {
      console.warn(`🤖 Bot detected - Low score: ${recaptchaResult.score} from ${clientIp}`);
      return res.status(403).json({ 
        status: 'error', 
        message: 'Verifikasi keamanan gagal. Silakan refresh halaman dan coba lagi.' 
      });
    }
    
    // B. VALIDASI & SANITASI INPUT
    let validated;
    try {
      validated = sanitizeAndValidate(rawEmail, rawWhatsapp, rawPesan);
      console.log(`✅ Validation passed for: ${validated.email}`);
    } catch (validationError) {
      console.warn(`⚠️ Validation failed: ${validationError.message}`);
      return res.status(400).json({ 
        status: 'error', 
        message: validationError.message 
      });
    }
    
    // C. CONNECT TO DATABASE
    console.log(`🔌 Connecting to MongoDB...`);
    await connectDB();
    console.log(`✅ MongoDB connected`);
    
    // D. CHECK DUPLICATE INQUIRY (Anti-spam)
    const recentInquiry = await Inquiry.findOne({
      email: validated.email,
      createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // 1 jam terakhir
    });
    
    if (recentInquiry) {
      console.warn(`🔄 Duplicate inquiry detected from: ${validated.email}`);
      return res.status(429).json({
        status: 'error',
        message: 'Anda sudah mengirim inquiry dalam 1 jam terakhir. Mohon tunggu sebentar.'
      });
    }
    
    // E. SAVE TO DATABASE
    console.log(`💾 Saving inquiry to database...`);
    const newLead = new Inquiry({ 
      ...validated,
      ipAddress: clientIp
    });
    await newLead.save();
    console.log(`✅ Inquiry saved successfully: ${validated.email}`);
    
    // F. SEND EMAIL NOTIFICATION
    try {
      console.log(`📧 Sending email notification...`);
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
              <h2 style="color: #2563eb; margin-top: 0; border-bottom: 3px solid #2563eb; padding-bottom: 10px;">
                📩 Detail Inquiry Baru
              </h2>
              
              <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr style="background: #f3f4f6;">
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold; width: 150px;">Email:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">${validated.email}</td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">WhatsApp:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">
                    <a href="https://wa.me/${validated.whatsapp.replace(/[^0-9]/g, '')}" 
                       style="color: #2563eb; text-decoration: none; font-weight: bold;">
                      ${validated.whatsapp} 📱
                    </a>
                  </td>
                </tr>
                <tr style="background: #f3f4f6;">
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold; vertical-align: top;">Pesan:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; white-space: pre-wrap;">${validated.pesan}</td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">IP Address:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-family: monospace;">${clientIp}</td>
                </tr>
                <tr style="background: #f3f4f6;">
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">Bot Score:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">
                    <span style="
                      color: ${recaptchaResult.score >= 0.7 ? '#10b981' : recaptchaResult.score >= 0.5 ? '#f59e0b' : '#ef4444'}; 
                      font-weight: bold;
                      padding: 4px 8px;
                      border-radius: 4px;
                      background: ${recaptchaResult.score >= 0.7 ? '#d1fae5' : recaptchaResult.score >= 0.5 ? '#fef3c7' : '#fee2e2'};
                    ">
                      ${recaptchaResult.score || 'N/A'} ${recaptchaResult.score >= 0.7 ? '✅' : recaptchaResult.score >= 0.5 ? '⚠️' : '❌'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">Waktu:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">
                    ${new Date().toLocaleString('id-ID', { 
                      timeZone: 'Asia/Jakarta',
                      dateStyle: 'full',
                      timeStyle: 'long'
                    })}
                  </td>
                </tr>
              </table>
              
              <div style="margin-top: 30px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px; text-align: center;">
                <p style="margin: 0; color: white; font-size: 18px; font-weight: bold;">
                  ⚡ ACTION REQUIRED
                </p>
                <p style="margin: 10px 0 0 0; color: #e0e7ff; font-size: 14px;">
                  Segera follow up lead ini dalam 1 jam untuk conversion rate maksimal!
                </p>
                <a href="https://wa.me/${validated.whatsapp.replace(/[^0-9]/g, '')}" 
                   style="
                     display: inline-block;
                     margin-top: 15px;
                     padding: 12px 24px;
                     background-color: #25D366;
                     color: white;
                     text-decoration: none;
                     border-radius: 6px;
                     font-weight: bold;
                   ">
                  💬 Chat via WhatsApp
                </a>
              </div>
            </div>
            
            <div style="text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px;">
              <p>MARZ STORE - Automated Inquiry System</p>
            </div>
          </div>
        `
      });
      console.log(`✅ Email sent successfully to ${process.env.EMAIL_USER}`);
    } catch (emailError) {
      console.error('❌ Email sending failed:', emailError.message);
      // Email gagal tidak blocking response - data sudah tersimpan
    }
    
    // G. SEND SUCCESS RESPONSE
    const duration = Date.now() - startTime;
    console.log(`✅ Request completed successfully in ${duration}ms for ${validated.email}`);
    
    res.status(200).json({ 
      status: 'success', 
      message: 'Terima kasih! Pesan Anda sudah diterima. Tim kami akan segera menghubungi Anda.' 
    });
    
  } catch (err) {
    console.error("❌ Backend Error:", err.message);
    console.error("Stack trace:", err.stack);
    
    res.status(500).json({ 
      status: 'error', 
      message: 'Sistem sedang sibuk. Silakan coba lagi dalam beberapa saat.',
      ...(process.env.NODE_ENV === 'development' && { 
        error: err.message,
        stack: err.stack 
      })
    });
  }
});

// ========================================
// 7. ERROR HANDLER
// ========================================
app.use((err, req, res, next) => {
  console.error('❌ Unhandled Error:', err.message);
  console.error('Stack:', err.stack);
  
  res.status(500).json({ 
    status: 'error', 
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

// ========================================
// 8. GRACEFUL SHUTDOWN
// ========================================
process.on('SIGTERM', async () => {
  console.log('⚠️ SIGTERM signal received: closing MongoDB connection...');
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('⚠️ SIGINT signal received: closing MongoDB connection...');
  await mongoose.connection.close();
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
});

// ========================================
// 9. EXPORT
// ========================================
module.exports = app;
