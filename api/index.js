const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const xss = require('xss');
const helmet = require('helmet');
const hpp = require('hpp');

const app = express();

// 1. Middleware Keamanan & CORS
// Helmet membantu mengamankan header HTTP
app.use(helmet()); 
// Mengizinkan frontend dari domain mana pun untuk mengakses API ini
app.use(cors({ origin: '*' })); 
// Membatasi ukuran body agar server tidak overload (proteksi DDoS ringan)
app.use(express.json({ limit: '10kb' })); 
// Proteksi terhadap HTTP Parameter Pollution
app.use(hpp()); 

// 2. DB Connection (Optimasi untuk Vercel Serverless)
const connectDB = async () => {
    // Jika koneksi sudah ada, jangan buat koneksi baru (menghemat kuota koneksi MongoDB)
    if (mongoose.connection.readyState >= 1) return;
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log("MongoDB Connected");
    } catch (err) {
        console.error("DB Error:", err.message);
        // Jangan throw error di sini agar serverless function tidak langsung mati
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
// Endpoint GET untuk cek kesehatan server (Health Check)
app.get('/api/index', (req, res) => {
    res.status(200).send('Server Marz Store Aman Terkendali');
});

// Endpoint POST untuk menerima data form
app.post('/api/index', async (req, res) => {
    try {
        // Pastikan koneksi DB nyala
        await connectDB();
        
        // A. Sanitasi Input (Cegah serangan XSS/Script Injection)
        const email = xss(req.body.email);
        const whatsapp = xss(req.body.whatsapp);
        const pesan = xss(req.body.pesan);

        // B. Validasi Nomor WA Internasional
        // Mendukung tanda '+' di awal dan angka 7-15 digit
        const internationalPhoneRegex = /^\+?[0-9]{7,15}$/;
        if (!internationalPhoneRegex.test(whatsapp)) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Format nomor telepon internasional tidak valid (Gunakan angka atau +)!' 
            });
        }

        // C. Simpan ke MongoDB
        const newLead = new Inquiry({ email, whatsapp, pesan });
        await newLead.save();

        // D. Konfigurasi Nodemailer (Kirim Email Notifikasi)
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { 
                user: process.env.EMAIL_USER, 
                pass: process.env.EMAIL_PASS 
            }
        });

        // E. Kirim Email
        await transporter.sendMail({
            from: `"MARZ SYSTEM" <${process.env.EMAIL_USER}>`,
            to: process.env.EMAIL_USER, // Notifikasi dikirim ke email lu sendiri
            subject: `KONSULTASI BARU: ${email}`,
            text: `Detail Inquiry:\n\nEmail: ${email}\nWhatsApp: ${whatsapp}\nPesan: ${pesan}\n\nCek dashboard MongoDB untuk detail lengkap.`
        });

        // Berikan respon sukses ke frontend
        res.status(200).json({ status: 'success', message: 'Data berhasil disimpan dan email terkirim' });

    } catch (err) {
        console.error("Backend Error Detail:", err.message);
        res.status(500).json({ 
            status: 'error', 
            message: 'Internal Server Error',
            detail: err.message 
        });
    }
});

// 5. Export untuk Vercel (Express dideteksi sebagai Serverless Function)
module.exports = app;
