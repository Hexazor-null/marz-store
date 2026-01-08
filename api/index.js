const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const xss = require('xss');
const helmet = require('helmet');
const hpp = require('hpp');

const app = express();

// Middleware Keamanan & CORS
app.use(helmet());
app.use(cors({ origin: '*' })); 
app.use(express.json({ limit: '10kb' }));
app.use(hpp());

// DB Connection (Serverless Optimized)
const connectDB = async () => {
    if (mongoose.connection.readyState >= 1) return;
    try {
        await mongoose.connect(process.env.MONGODB_URI);
    } catch (err) {
        console.error("DB Error:", err.message);
    }
};

// Model
const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', new mongoose.Schema({
    email: { type: String, required: true },
    whatsapp: { type: String, required: true },
    pesan: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
}));

// Routes
app.get('/api/index', (req, res) => {
    res.status(200).send('Server Marz Store Aman Terkendali');
});

app.post('/api/index', async (req, res) => {
    try {
        await connectDB();
        
        // 1. Sanitasi Dasar
        const email = xss(req.body.email);
        const whatsapp = xss(req.body.whatsapp);
        const pesan = xss(req.body.pesan);

        // 2. Validasi Angka Saja untuk WA
        const phoneRegex = /^[0-9]{10,15}$/;
        if (!phoneRegex.test(whatsapp)) {
            return res.status(400).json({ status: 'error', message: 'Nomor WA harus berupa angka!' });
        }

        // 3. Simpan ke MongoDB
        const newLead = new Inquiry({ email, whatsapp, pesan });
        await newLead.save();

        // 4. Konfigurasi Nodemailer
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { 
                user: process.env.EMAIL_USER, 
                pass: process.env.EMAIL_PASS 
            }
        });

        // 5. Kirim Email Notifikasi
        await transporter.sendMail({
            from: `"MARZ SYSTEM" <${process.env.EMAIL_USER}>`,
            to: process.env.EMAIL_USER,
            subject: `KONSULTASI BARU: ${email}`,
            text: `Nomor WhatsApp: ${whatsapp}\nPesan: ${pesan}`
        });

        res.status(200).json({ status: 'success' });
    } catch (err) {
        console.error("Backend Error:", err.message);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});

// Export untuk Vercel
module.exports = app;
