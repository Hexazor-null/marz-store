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

// ============================================================================
// SECURITY: Helmet Configuration
// ============================================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://www.google.com", "https://www.gstatic.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https:", "data:"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["https://www.google.com"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// ============================================================================
// SECURITY: CORS Configuration with Validation
// ============================================================================

// Validasi origins saat startup
const validateAndGetOrigins = () => {
  const originsEnv = process.env.ALLOWED_ORIGINS;
  
  if (!originsEnv) {
    console.error('⚠️  WARNING: ALLOWED_ORIGINS not set in environment variables!');
    if (process.env.NODE_ENV === 'production') {
      throw new Error('CRITICAL: ALLOWED_ORIGINS must be set in production');
    }
    return ['http://localhost:3000', 'http://localhost:5173']; // Development fallback
  }
  
  const origins = originsEnv.split(',').map(o => o.trim()).filter(Boolean);
  
  // Validasi setiap origin
  origins.forEach(origin => {
    // Harus menggunakan HTTPS di production (kecuali localhost)
    if (process.env.NODE_ENV === 'production') {
      if (!origin.startsWith('https://')) {
        throw new Error(`CRITICAL: Production origin must use HTTPS: ${origin}`);
      }
    } else {
      // Development: izinkan http://localhost
      if (!origin.startsWith('https://') && !origin.startsWith('http://localhost')) {
        console.warn(`⚠️  Warning: Non-HTTPS origin detected: ${origin}`);
      }
    }
    
    // Cek format URL valid
    try {
      new URL(origin);
    } catch (e) {
      throw new Error(`Invalid origin URL format: ${origin}`);
    }
  });
  
  console.log('✅ Validated CORS origins:', origins);
  return origins;
};

const ALLOWED_ORIGINS = validateAndGetOrigins();

// CORS Options dengan validasi ketat
const corsOptions = {
  origin: (origin, callback) => {
    // Log setiap request origin untuk monitoring
    console.log(`[CORS] Request from origin: ${origin || 'NO ORIGIN'}`);
    
    // Izinkan request tanpa origin (server-to-server, Postman, mobile apps)
    // Di production, pertimbangkan untuk membatasi ini
    if (!origin) {
      if (process.env.NODE_ENV === 'production' && process.env.REQUIRE_ORIGIN === 'true') {
        console.warn('[CORS] Blocked: No origin header in production mode');
        return callback(new Error('Origin header required'));
      }
      return callback(null, true);
    }
    
    // Cek apakah origin ada dalam whitelist
    if (ALLOWED_ORIGINS.includes(origin)) {
      console.log(`[CORS] ✅ Allowed: ${origin}`);
      callback(null, true);
    } else {
      console.warn(`[CORS] ❌ Blocked: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Izinkan cookies dan authorization headers
  methods: ['GET', 'POST', 'OPTIONS'], // Hanya method yang diperlukan
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Requested-With',
    'Accept'
  ],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 86400, // Cache preflight request 24 jam
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

// Handle preflight requests explicitly
app.options('*', cors(corsOptions));

// ============================================================================
// SECURITY: Request Size Limit
// ============================================================================
app.use(express.json({ 
  limit: '10kb',
  strict: true
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '10kb' 
}));

// ============================================================================
// SECURITY: MongoDB Injection Protection
// ============================================================================
const mongoSanitize = (req, res, next) => {
  const sanitize = (obj) => {
    if (!obj || typeof obj !== 'object') return obj;
    const sanitized = {};
    for (const key in obj) {
      // Blokir operator MongoDB dan key berbahaya
      if (key.startsWith('$') || key.includes('.')) {
        console.warn(`[SECURITY] Blocked dangerous key: ${key} from IP: ${req.ip}`);
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
  if (req.query) req.query = sanitize(req.query);
  next();
};

app.use(mongoSanitize);

// ============================================================================
// SECURITY: HTTP Parameter Pollution Protection
// ============================================================================
app.use(hpp());

// ============================================================================
// SECURITY: Rate Limiting
// ============================================================================
const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 menit
  max: 15, // 15 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'GET' && !req.path.includes('/api/index'),
  handler: (req, res) => {
    console.warn(`[RATE LIMIT] IP ${req.ip} exceeded API limit`);
    res.status(429).json({
      status: 'error',
      message: 'Terlalu banyak request. Tunggu 10 menit.'
    });
  },
  // Skip rate limit untuk health check
  skipSuccessfulRequests: false,
  skipFailedRequests: false
});

const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 jam
  max: 5, // 5 email per jam
  skipSuccessfulRequests: false,
  handler: (req, res) => {
    console.warn(`[EMAIL LIMIT] IP ${req.ip} exceeded email limit`);
    res.status(429).json({
      status: 'error',
      message: 'Anda sudah mengirim 5 pesan dalam 1 jam terakhir. Silakan tunggu sebentar.'
    });
  }
});

// ============================================================================
// DATABASE: MongoDB Connection
// ============================================================================
const connectDB = async () => {
  if (mongoose.connection.readyState >= 1) {
    console.log(`Already connected (state: ${mongoose.connection.readyState})`);
    return;
  }
  
  if (!process.env.MONGODB_URI) {
    console.error('❌ CRITICAL ERROR: MONGODB_URI is NOT SET in environment variables!');
    throw new Error('MONGODB_URI not configured');
  }
  
  try {
    console.log('🔄 Attempting to connect to MongoDB...');
    console.log('URI preview:', process.env.MONGODB_URI.substring(0, 40) + '...');
    
    await mongoose.connect(process.env.MONGODB_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 45000,
      family: 4 // Force IPv4
    });
    
    console.log("✅ SUCCESS: MongoDB Connected Successfully!");
    console.log("Database:", mongoose.connection.db.databaseName);
    console.log("Host:", mongoose.connection.host);
    
  } catch (err) {
    console.error("❌ CRITICAL ERROR: MongoDB Connection FAILED!");
    console.error("Error name:", err.name);
    console.error("Error message:", err.message);
    throw err;
  }
};

// MongoDB connection event listeners
mongoose.connection.on('connected', () => {
  console.log('✅ Mongoose event: CONNECTED to database');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ Mongoose event: ERROR -', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️  Mongoose event: DISCONNECTED from database');
});

// ============================================================================
// DATABASE: Schema Definition
// ============================================================================
const InquirySchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    maxlength: [100, 'Email too long'],
    trim: true,
    lowercase: true,
    index: true
  },
  whatsapp: { 
    type: String, 
    required: [true, 'WhatsApp is required'],
    maxlength: [20, 'WhatsApp number too long'],
    trim: true
  },
  pesan: { 
    type: String, 
    required: [true, 'Message is required'],
    maxlength: [1000, 'Message too long'], 
    trim: true
  },
  ipAddress: { 
    type: String,
    required: false
  },
  userAgent: {
    type: String,
    required: false
  },
  recaptchaScore: {
    type: Number,
    required: false
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Auto-delete after 30 days
InquirySchema.index({ createdAt: 1 }, { expireAfterSeconds: 2592000 });

// Compound index untuk duplicate check
InquirySchema.index({ email: 1, createdAt: 1 });

const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', InquirySchema);

// ============================================================================
// SECURITY: reCAPTCHA Verification
// ============================================================================
const verifyRecaptcha = async (token, remoteIp) => {
  // BYPASS untuk testing (HANYA untuk development!)
  if (process.env.NODE_ENV !== 'production' && token === 'test-bypass-token-12345') {
    console.warn('⚠️  TESTING MODE: reCAPTCHA bypassed with special test token');
    return { success: true, score: 1.0 };
  }
  
  // BYPASS via environment variable (HAPUS di production!)
  if (process.env.NODE_ENV !== 'production' && process.env.BYPASS_RECAPTCHA === 'true') {
    console.warn('⚠️  BYPASS MODE: reCAPTCHA disabled via BYPASS_RECAPTCHA env var');
    return { success: true, score: 1.0 };
  }
  
  if (!token) {
    console.warn('[RECAPTCHA] No token provided');
    return { success: false, error: 'Token missing', score: 0 };
  }
  
  const secretKey = process.env.RECAPTCHA_SECRET_KEY;
  
  if (!secretKey) {
    console.error('❌ RECAPTCHA_SECRET_KEY not configured!');
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
    console.log(`[RECAPTCHA] Success: ${result.success}, Score: ${result.score || 'N/A'}`);
    
    return result;
  } catch (error) {
    console.error('[RECAPTCHA] Error:', error.message);
    return { success: false, error: error.message, score: 0 };
  }
};

// ============================================================================
// VALIDATION: Input Sanitization
// ============================================================================
const sanitizeAndValidate = (email, whatsapp, pesan) => {
  // XSS Protection
  const cleanEmail = xss(email?.toString() || '').trim();
  let cleanWhatsapp = xss(whatsapp?.toString() || '').trim();
  const cleanPesan = xss(pesan?.toString() || '').trim();
  
  // Email validation
  if (!validator.isEmail(cleanEmail)) {
    throw new Error('Format email tidak valid');
  }
  
  // Validate email domain (optional - uncomment if needed)
  // const emailDomain = cleanEmail.split('@')[1];
  // if (validator.isEmail(cleanEmail) && !validator.isFQDN(emailDomain)) {
  //   throw new Error('Domain email tidak valid');
  // }
  
  // WhatsApp normalization
  cleanWhatsapp = cleanWhatsapp.replace(/[\s\-\(\)]/g, '');
  
  if (cleanWhatsapp.startsWith('08')) {
    cleanWhatsapp = '+62' + cleanWhatsapp.substring(1);
  } else if (cleanWhatsapp.startsWith('62') && !cleanWhatsapp.startsWith('+')) {
    cleanWhatsapp = '+' + cleanWhatsapp;
  } else if (!cleanWhatsapp.startsWith('+') && !cleanWhatsapp.startsWith('62')) {
    cleanWhatsapp = '+62' + cleanWhatsapp;
  }
  
  // WhatsApp validation
  if (!/^\+?[1-9]\d{7,14}$/.test(cleanWhatsapp)) {
    throw new Error('Format WhatsApp tidak valid. Contoh: 08123456789 atau +628123456789');
  }
  
  // Message length validation
  if (cleanPesan.length < 10) {
    throw new Error('Pesan terlalu pendek. Minimal 10 karakter.');
  }
  
  if (cleanPesan.length > 1000) {
    throw new Error('Pesan terlalu panjang. Maksimal 1000 karakter.');
  }
  
  // Check for spam patterns (optional)
  const spamPatterns = [
    /\b(viagra|casino|lottery|winner)\b/i,
    /http[s]?:\/\//gi // Block URLs in message
  ];
  
  for (const pattern of spamPatterns) {
    if (pattern.test(cleanPesan)) {
      throw new Error('Pesan mengandung konten yang tidak diizinkan');
    }
  }
  
  return { 
    email: cleanEmail, 
    whatsapp: cleanWhatsapp, 
    pesan: cleanPesan 
  };
};

// ============================================================================
// ROUTES: Health Check
// ============================================================================
app.get('/api/index', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    message: 'Server Marz Store Running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: '2.0.0'
  });
});

// ============================================================================
// ROUTES: Debug Status (DISABLE di production!)
// ============================================================================
app.get('/api/debug/status', async (req, res) => {
  // Disable di production untuk security
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ 
      error: 'Debug endpoint disabled in production' 
    });
  }
  
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
        nodeEnv: process.env.NODE_ENV || 'not set',
        allowedOrigins: ALLOWED_ORIGINS
      },
      security: {
        corsEnabled: true,
        rateLimitEnabled: true,
        helmetEnabled: true
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
      name: error.name
    });
  }
});

// ============================================================================
// ROUTES: Main Inquiry Endpoint
// ============================================================================
app.post('/api/index', apiLimiter, emailLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { email: rawEmail, whatsapp: rawWhatsapp, pesan: rawPesan, captchaToken } = req.body;
    
    // Get client IP
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                     req.headers['x-real-ip'] ||
                     req.socket.remoteAddress || 
                     req.ip;
    
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    console.log(`[${new Date().toISOString()}] New request from IP: ${clientIp}`);
    console.log(`User-Agent: ${userAgent}`);
    console.log(`Request data: ${rawEmail}, ${rawWhatsapp?.substring(0, 5)}...`);
    
    // reCAPTCHA verification
    const recaptchaResult = await verifyRecaptcha(captchaToken, clientIp);
    
    if (!recaptchaResult.success) {
      console.error(`[RECAPTCHA] Verification failed:`, recaptchaResult.error);
      return res.status(403).json({ 
        status: 'error', 
        message: 'Verifikasi keamanan gagal. Silakan refresh halaman dan coba lagi.'
      });
    }
    
    // Check reCAPTCHA score (v3 only)
    if (recaptchaResult.score !== undefined && recaptchaResult.score < 0.5) {
      console.warn(`[SECURITY] Bot detected - Low score: ${recaptchaResult.score} from ${clientIp}`);
      return res.status(403).json({ 
        status: 'error', 
        message: 'Verifikasi keamanan gagal. Silakan refresh halaman dan coba lagi.' 
      });
    }
    
    // Input validation
    let validated;
    try {
      validated = sanitizeAndValidate(rawEmail, rawWhatsapp, rawPesan);
      console.log(`✅ Validation passed for: ${validated.email}`);
    } catch (validationError) {
      console.warn(`[VALIDATION] Failed: ${validationError.message}`);
      return res.status(400).json({ 
        status: 'error', 
        message: validationError.message 
      });
    }
    
    // Connect to database
    console.log('Connecting to database...');
    await connectDB();
    console.log('✅ Database connected, checking for duplicates...');
    
    // Check for duplicate submissions (1 hour window)
    const recentInquiry = await Inquiry.findOne({
      email: validated.email,
      createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
    });
    
    if (recentInquiry) {
      console.warn(`[DUPLICATE] Inquiry detected from: ${validated.email}`);
      return res.status(429).json({
        status: 'error',
        message: 'Anda sudah mengirim inquiry dalam 1 jam terakhir. Mohon tunggu sebentar.'
      });
    }
    
    // Save to database
    console.log('Saving inquiry to database...');
    const newLead = new Inquiry({ 
      ...validated,
      ipAddress: clientIp,
      userAgent: userAgent,
      recaptchaScore: recaptchaResult.score || null
    });
    
    await newLead.save();
    console.log(`✅ Inquiry saved successfully: ${validated.email}`);
    
    // Send email notification (async, don't block response)
    setImmediate(async () => {
      try {
        console.log('Sending email notification...');
        
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
          console.warn('⚠️  Email credentials not configured, skipping email...');
          return;
        }
        
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
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f9fafb; border-radius: 8px;">
              <h2 style="color: #2563eb; border-bottom: 3px solid #2563eb; padding-bottom: 10px;">📨 Detail Inquiry Baru</h2>
              <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                <tr style="background: #f3f4f6;">
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold; width: 30%;">📧 Email:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">${validated.email}</td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">📱 WhatsApp:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">
                    <a href="https://wa.me/${validated.whatsapp.replace(/[^0-9]/g, '')}" style="color: #25D366; text-decoration: none; font-weight: bold;">${validated.whatsapp}</a>
                  </td>
                </tr>
                <tr style="background: #f3f4f6;">
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold; vertical-align: top;">💬 Pesan:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">${validated.pesan}</td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">🌐 IP Address:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">${clientIp}</td>
                </tr>
                <tr style="background: #f3f4f6;">
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">🤖 User Agent:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-size: 11px;">${userAgent}</td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">🛡️ reCAPTCHA Score:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">
                    <span style="background: ${recaptchaResult.score >= 0.7 ? '#10b981' : recaptchaResult.score >= 0.5 ? '#f59e0b' : '#ef4444'}; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold;">
                      ${recaptchaResult.score || 'N/A'}
                    </span>
                  </td>
                </tr>
                <tr style="background: #f3f4f6;">
                  <td style="padding: 12px; border: 1px solid #e5e7eb; font-weight: bold;">🕐 Waktu:</td>
                  <td style="padding: 12px; border: 1px solid #e5e7eb;">${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}</td>
                </tr>
              </table>
              <div style="margin-top: 20px; padding: 15px; background: #eff6ff; border-left: 4px solid #2563eb; border-radius: 4px;">
                <p style="margin: 0; color: #1e40af; font-weight: bold;">💡 Quick Actions:</p>
                <p style="margin: 5px 0 0 0;">
                  <a href="https://wa.me/${validated.whatsapp.replace(/[^0-9]/g, '')}" 
                     style="display: inline-block; margin-right: 10px; padding: 8px 16px; background: #25D366; color: white; text-decoration: none; border-radius: 4px; font-weight: bold;">
                    💬 Balas via WhatsApp
                  </a>
                  <a href="mailto:${validated.email}" 
                     style="display: inline-block; padding: 8px 16px; background: #2563eb; color: white; text-decoration: none; border-radius: 4px; font-weight: bold;">
                    📧 Balas via Email
                  </a>
                </p>
              </div>
            </div>
          `
        });
        
        console.log('✅ Email sent successfully');
      } catch (emailError) {
        console.error('❌ Email sending failed:', emailError.message);
        // Don't throw - email failure shouldn't fail the request
      }
    });
    
    const duration = Date.now() - startTime;
    console.log(`✅ Request completed successfully in ${duration}ms`);
    
    res.status(200).json({ 
      status: 'success', 
      message: 'Terima kasih! Pesan Anda sudah diterima. Tim kami akan segera menghubungi Anda.' 
    });
    
  } catch (err) {
    console.error("❌ Backend Error:", err.message);
    console.error("Stack trace:", err.stack);
    
    const duration = Date.now() - startTime;
    console.log(`❌ Request failed after ${duration}ms`);
    
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

// ============================================================================
// ERROR HANDLING: 404 Handler
// ============================================================================
app.use((req, res) => {
  console.warn(`[404] Route not found: ${req.method} ${req.path}`);
  res.status(404).json({ 
    status: 'error', 
    message: 'Endpoint tidak ditemukan'
  });
});

// ============================================================================
// ERROR HANDLING: Global Error Handler
// ============================================================================
app.use((err, req, res, next) => {
  console.error('❌ Unhandled Error:', err.message);
  console.error('Stack:', err.stack);
  
  // CORS errors
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ 
      status: 'error', 
      message: 'Access denied: CORS policy violation'
    });
  }
  
  res.status(500).json({ 
    status: 'error', 
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { 
      details: err.message,
      stack: err.stack 
    })
  });
});

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================
const gracefulShutdown = async (signal) => {
  console.log(`\n${signal} signal received: closing HTTP server and MongoDB connection...`);
  
  try {
    await mongoose.connection.close();
    console.log('✅ MongoDB connection closed successfully');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error during graceful shutdown:', err);
    process.exit(1);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('❌ UNCAUGHT EXCEPTION! Shutting down...');
  console.error(err.name, err.message);
  console.error(err.stack);
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  console.error('❌ UNHANDLED REJECTION! Shutting down...');
  console.error(err);
  gracefulShutdown('UNHANDLED_REJECTION');
});

// ============================================================================
// EXPORT
// ============================================================================
module.exports = app;
