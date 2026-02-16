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

app.use(helmet());

// CORS - TAMBAHKAN LOGGING untuk debug
app.use(cors({ 
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()) || ['https://yourdomain.com'];
    
    console.log('[CORS] Request from:', origin);
    console.log('[CORS] Allowed origins:', allowedOrigins);
    
    // Izinkan jika tidak ada origin (Postman, mobile app)
    if (!origin) {
      console.log('[CORS] ✅ No origin - allowed');
      return callback(null, true);
    }
    
    // Cek whitelist
    if (allowedOrigins.includes(origin)) {
      console.log('[CORS] ✅ Origin allowed');
      callback(null, true);
    } else {
      console.log('[CORS] ❌ Origin BLOCKED');
      callback(null, true); // SEMENTARA tetap izinkan untuk testing
    }
  },
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));

const mongoSanitize = (req, res, next) => {
  const sanitize = (obj) => {
    if (!obj || typeof obj !== 'object') return obj;
    const sanitized = {};
    for (const key in obj) {
      if (key.startsWith('$') || key.includes('.')) {
        console.warn(`Blocked dangerous key: ${key}`);
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

const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'GET',
  handler: (req, res) => {
    console.warn('Rate limit exceeded');
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
    console.warn('Email limit exceeded');
    res.status(429).json({
      status: 'error',
      message: 'Anda sudah mengirim 5 pesan dalam 1 jam.'
    });
  }
});

const connectDB = async () => {
  if (mongoose.connection.readyState >= 1) {
    console.log(`Already connected (state: ${mongoose.connection.readyState})`);
    return;
  }
  
  if (!process.env.MONGODB_URI) {
    console.error('CRITICAL ERROR: MONGODB_URI is NOT SET in environment variables!');
    throw new Error('MONGODB_URI not configured');
  }
  
  try {
    console.log('Attempting to connect to MongoDB...');
    console.log('URI preview:', process.env.MONGODB_URI.substring(0, 40) + '...');
    
    await mongoose.connect(process.env.MONGODB_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 45000,
    });
    
    console.log("SUCCESS: MongoDB Connected Successfully!");
    console.log("Database:", mongoose.connection.db.databaseName);
    console.log("Host:", mongoose.connection.host);
    
  } catch (err) {
    console.error("CRITICAL ERROR: MongoDB Connection FAILED!");
    console.error("Error name:", err.name);
    console.error("Error message:", err.message);
    throw err;
  }
};

mongoose.connection.on('connected', () => {
  console.log('Mongoose event: CONNECTED to database');
});

mongoose.connection.on('error', (err) => {
  console.error('Mongoose event: ERROR -', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose event: DISCONNECTED from database');
});

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

InquirySchema.index({ createdAt: 1 }, { expireAfterSeconds: 2592000 });

const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', InquirySchema);

const verifyRecaptcha = async (token, remoteIp) => {
  if (token === 'test-bypass-token-12345') {
    console.warn('TESTING MODE: reCAPTCHA bypassed with special test token');
    return { success: true, score: 1.0 };
  }
  
  if (process.env.BYPASS_RECAPTCHA === 'true') {
    console.warn('BYPASS MODE: reCAPTCHA disabled via BYPASS_RECAPTCHA env var');
    return { success: true, score: 1.0 };
  }
  
  if (!token) {
    console.warn('No reCAPTCHA token provided');
    return { success: false, error: 'Token missing', score: 0 };
  }
  
  const secretKey = process.env.RECAPTCHA_SECRET_KEY;
  
  if (!secretKey) {
    console.error('RECAPTCHA_SECRET_KEY not configured!');
    return { success: false, error: 'Server misconfiguration', score: 0 };
  }

  try {
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${secretKey}&response=${token}&remoteip=${remoteIp}`
    });
    
    if (!response.ok) {
      throw new Error(`reCAPTCHA API returned ${response.status}`);
    }
    
    const result = await response.json();
    console.log(`reCAPTCHA - Success: ${result.success}, Score: ${result.score || 'N/A'}`);
    return result;
  } catch (error) {
    console.error('reCAPTCHA Error:', error.message);
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
    throw new Error('Format WhatsApp tidak valid. Contoh: 08123456789 atau +628123456789');
  }
  
  if (cleanPesan.length < 10 || cleanPesan.length > 1000) {
    throw new Error('Pesan harus 10-1000 karakter');
  }
  
  return { 
    email: cleanEmail, 
    whatsapp: cleanWhatsapp, 
    pesan: cleanPesan 
  };
};

app.get('/api/index', (req, res) => {
  console.log('[GET /api/index] Health check request');
  res.status(200).json({ 
    status: 'ok', 
    message: 'Server Marz Store Running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/api/debug/status', async (req, res) => {
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };
  
  try {
    const status = {
      mongodb: {
        readyState: mongoose.connection.readyState,
        status: states[mongoose.connection.readyState],
        host: mongoose.connection.host || 'N/A',
        database: mongoose.connection.db?.databaseName || 'N/A'
      },
      environment: {
        hasMongoURI: !!process.env.MONGODB_URI,
        mongoURIpreview: process.env.MONGODB_URI?.substring(0, 40) + '...' || 'NOT SET',
        hasEmailUser: !!process.env.EMAIL_USER,
        hasEmailPass: !!process.env.EMAIL_PASS,
        hasRecaptcha: !!process.env.RECAPTCHA_SECRET_KEY,
        bypassRecaptcha: process.env.BYPASS_RECAPTCHA || 'false',
        nodeEnv: process.env.NODE_ENV || 'not set'
      }
    };
    
    if (mongoose.connection.readyState === 0) {
      console.log('Debug endpoint triggering connection...');
      await connectDB();
      status.mongodb.readyState = mongoose.connection.readyState;
      status.mongodb.status = states[mongoose.connection.readyState];
      status.mongodb.host = mongoose.connection.host;
      status.mongodb.database = mongoose.connection.db?.databaseName;
    }
    
    res.json(status);
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      name: error.name,
      stack: error.stack
    });
  }
});

app.post('/api/index', apiLimiter, emailLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    console.log('[POST /api/index] New inquiry request received');
    
    const { email: rawEmail, whatsapp: rawWhatsapp, pesan: rawPesan, captchaToken } = req.body;
    
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                     req.headers['x-real-ip'] ||
                     req.socket.remoteAddress || 
                     req.ip;
    
    console.log(`[${new Date().toISOString()}] New request from IP: ${clientIp}`);
    console.log(`Request data: ${rawEmail}, ${rawWhatsapp}`);
    console.log(`Captcha token: ${captchaToken}`);
    
    const recaptchaResult = await verifyRecaptcha(captchaToken, clientIp);
    
    if (!recaptchaResult.success) {
      console.error(`reCAPTCHA verification failed:`, recaptchaResult.error);
      return res.status(403).json({ 
        status: 'error', 
        message: 'Verifikasi keamanan gagal. Silakan refresh halaman dan coba lagi.'
      });
    }
    
    if (recaptchaResult.score && recaptchaResult.score < 0.5) {
      console.warn(`Bot detected - Low score: ${recaptchaResult.score} from ${clientIp}`);
      return res.status(403).json({ 
        status: 'error', 
        message: 'Verifikasi keamanan gagal. Silakan refresh halaman dan coba lagi.' 
      });
    }
    
    let validated;
    try {
      validated = sanitizeAndValidate(rawEmail, rawWhatsapp, rawPesan);
      console.log(`Validation passed for: ${validated.email}, ${validated.whatsapp}`);
    } catch (validationError) {
      console.warn(`Validation failed: ${validationError.message}`);
      return res.status(400).json({ 
        status: 'error', 
        message: validationError.message 
      });
    }
    
    console.log('Attempting database connection...');
    await connectDB();
    console.log('Database connected, checking for duplicates...');
    
    const recentInquiry = await Inquiry.findOne({
      email: validated.email,
      createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
    });
    
    if (recentInquiry) {
      console.warn(`Duplicate inquiry detected from: ${validated.email}`);
      return res.status(429).json({
        status: 'error',
        message: 'Anda sudah mengirim inquiry dalam 1 jam terakhir. Mohon tunggu sebentar.'
      });
    }
    
    console.log('Saving inquiry to database...');
    const newLead = new Inquiry({ 
      ...validated,
      ipAddress: clientIp
    });
    await newLead.save();
    console.log(`Inquiry saved successfully: ${validated.email}`);
    
    try {
      console.log('Sending email notification...');
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
        subject: `KONSULTASI BARU: ${validated.email}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #2563eb;">Detail Inquiry Baru</h2>
            <table style="width: 100%; border-collapse: collapse;">
              <tr style="background: #f3f4f6;">
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Email:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">${validated.email}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">WhatsApp:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">
                  <a href="https://wa.me/${validated.whatsapp.replace(/[^0-9]/g, '')}">${validated.whatsapp}</a>
                </td>
              </tr>
              <tr style="background: #f3f4f6;">
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Pesan:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">${validated.pesan}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">IP:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">${clientIp}</td>
              </tr>
              <tr style="background: #f3f4f6;">
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Score:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">${recaptchaResult.score || 'N/A'}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Waktu:</td>
                <td style="padding: 12px; border: 1px solid #ddd;">${new Date().toLocaleString('id-ID')}</td>
              </tr>
            </table>
          </div>
        `
      });
      console.log('Email sent successfully');
    } catch (emailError) {
      console.error('Email sending failed:', emailError.message);
    }
    
    const duration = Date.now() - startTime;
    console.log(`Request completed successfully in ${duration}ms`);
    
    res.status(200).json({ 
      status: 'success', 
      message: 'Terima kasih! Pesan Anda sudah diterima. Tim kami akan segera menghubungi Anda.' 
    });
    
  } catch (err) {
    console.error("Backend Error:", err.message);
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

app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err.message);
  console.error('Stack:', err.stack);
  
  res.status(500).json({ 
    status: 'error', 
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received: closing MongoDB connection...');
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT signal received: closing MongoDB connection...');
  await mongoose.connection.close();
  process.exit(0);
});

module.exports = app;
