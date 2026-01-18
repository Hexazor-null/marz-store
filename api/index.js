const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const xss = require('xss');
const helmet = require('helmet');
const hpp = require('hpp');

const app = express();

// 1. Middleware Keamanan & CORS
app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10kb' }));
app.use(hpp());

// 2. DB Connection
const connectDB = async () => {
  if (mongoose.connection.readyState >= 1) return;
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB Connected");
  } catch (err) {
    console.error("DB Error:", err.message);
  }
};

// 3. Database Model
const InquirySchema = new mongoose.Schema({
  email: { type: String, required: true },
  whatsapp: { type: String, required: true },
  pesan: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', InquirySchema);

// 4. Routes
app.get('/api/index', (req, res) => {
  res.status(200).send('Server Marz Store Aman Terkendali');
});

// Endpoint POST dengan PROTEKSI RECAPTCHA
app.post('/api/index', async (req, res) => {
  try {
    const { email: rawEmail, whatsapp: rawWhatsapp, pesan: rawPesan, captchaToken } = req.body;

    // --- A. VERIFIKASI RECAPTCHA (PENGHALANG BOT) ---
    if (!captchaToken) {
      return res.status(400).json({
        status: 'error',
        message: 'Captcha token is missing!'
      });
    }

    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${captchaToken}`;
    const recaptchaRes = await fetch(verifyUrl, { method: 'POST' });
    const recaptchaJson = await recaptchaRes.json();

    // Jika Google bilang ini Bot (score biasanya di bawah 0.5)
    if (!recaptchaJson.success || recaptchaJson.score < 0.5) {
      return res.status(403).json({
        status: 'error',
        message: 'Aktivitas bot terdeteksi! Silakan coba lagi.'
      });
    }

    // --- B. LANJUT KE PROSES DATA ---
    await connectDB();

    // Sanitasi Input
    const email = xss(rawEmail);
    const whatsapp = xss(rawWhatsapp);
    const pesan = xss(rawPesan);

    // Validasi Nomor WA
    const internationalPhoneRegex = /^\+?[0-9]{7,15}$/;
    if (!internationalPhoneRegex.test(whatsapp)) {
      return res.status(400).json({
        status: 'error',
        message: 'Format nomor telepon tidak valid!'
      });
    }

    // Simpan ke MongoDB
    const newLead = new Inquiry({ email, whatsapp, pesan });
    await newLead.save();

    // Nodemailer
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    // Kirim Email
    await transporter.sendMail({
      from: `"MARZ SYSTEM" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER,
      subject: `KONSULTASI BARU: ${email}`,
      text: `Detail Inquiry:\n\nEmail: ${email}\nWhatsApp: ${whatsapp}\nPesan: ${pesan}\n\nSkor Bot: ${recaptchaJson.score}`
    });

    res.status(200).json({
      status: 'success',
      message: 'Data berhasil disimpan dan email terkirim'
    });

  } catch (err) {
    console.error("Backend Error Detail:", err.message);
    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
      detail: err.message
    });
  }
});

module.exports = app;
