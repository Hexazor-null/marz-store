const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const xss = require('xss');
const helmet = require('helmet');
const hpp = require('hpp');

const app = express();

// --- LAYER KEAMANAN ---
app.use(helmet()); 
app.use(cors({ origin: '*' })); 
app.use(express.json({ limit: '10kb' })); 
app.use(hpp()); 

// --- DATABASE SCHEMA ---
const InquirySchema = new mongoose.Schema({
    email: { type: String, required: true },
    whatsapp: { type: String, required: true },
    pesan: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', InquirySchema);

// --- KONEKSI DATABASE ---
const connectDB = async () => {
    if (mongoose.connection.readyState >= 1) return;
    try {
        await mongoose.connect(process.env.MONGODB_URI);
    } catch (err) {
        console.error("MongoDB Error:", err.message);
    }
};

// --- ROUTES ---

// Cek status server
app.get('/', (req, res) => {
    res.status(200).send('Server Marz Store Aman Terkendali');
});

// Endpoint POST Konsultasi
app.post('/api/marz/consult', async (req, res) => {
    try {
        await connectDB();

        // 1. Sanitasi Input
        const email = xss(req.body.email);
        const whatsapp = xss(req.body.whatsapp);
        const pesan = xss(req.body.pesan);

        // 2. Validasi Server-Side
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ status: 'error', message: 'Format email tidak valid' });
        }
        if (whatsapp.length < 10 || whatsapp.length > 15) {
            return res.status(400).json({ status: 'error', message: 'Nomor WhatsApp tidak valid' });
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
            from: `"MARZ STORE SECURITY" <${process.env.EMAIL_USER}>`,
            to: process.env.EMAIL_USER,
            subject: `KONSULTASI BARU: ${email}`,
            html: `
                <div style="font-family: sans-serif; padding: 20px; border: 2px solid #2563eb; border-radius: 10px;">
                    <h2 style="color: #2563eb;">Inquiry Baru Diterima</h2>
                    <p><strong>Email Pengirim:</strong> ${email}</p>
                    <p><strong>WhatsApp:</strong> ${whatsapp}</p>
                    <p><strong>Isi Pesan:</strong> ${pesan}</p>
                    <hr>
                    <p style="font-size: 12px; color: #666;">Data telah diamankan di sistem.</p>
                </div>
            `
        });

        return res.status(200).json({ status: 'success', message: 'Data aman terkirim' });

    } catch (err) {
        console.error("System Failure:", err.message);
        return res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});

module.exports = app;
