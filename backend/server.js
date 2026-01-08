const express = require('express');
const mongoose = require('mongoose');
const xss = require('xss');
const hpp = require('hpp');
const cors = require('cors');
const nodemailer = require('nodemailer');
const helmet = require('helmet');

const app = express();

app.use(helmet());
app.use(cors({ origin: '*' })); 
app.use(express.json({ limit: '10kb' }));
app.use(hpp());

const InquirySchema = new mongoose.Schema({
    email: { type: String, required: true },
    whatsapp: { type: String, required: true },
    pesan: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', InquirySchema);

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { 
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS 
    }
});

let isConnected = false;
const connectDB = async () => {
    if (isConnected) return;
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        isConnected = true;
    } catch (err) {
        console.error("MongoDB Connection Error:", err);
    }
};

app.post('/api/marz/consult', async (req, res) => {
    await connectDB();
    try {
        const { email, whatsapp, pesan } = req.body;

        const newLead = new Inquiry({ 
            email: xss(email), 
            whatsapp: xss(whatsapp), 
            pesan: xss(pesan) 
        });
        await newLead.save();

        await transporter.sendMail({
            from: '"MARZ STORE" <noreply@marzstore.com>',
            to: process.env.EMAIL_USER,
            subject: `KONSULTASI BARU: ${email}`,
            html: `
                <div style="font-family: sans-serif; border: 1px solid #ddd; padding: 20px;">
                    <h2>Ada Inquiry Baru Masuk</h2>
                    <p><strong>Email:</strong> ${email}</p>
                    <p><strong>WhatsApp:</strong> ${whatsapp}</p>
                    <p><strong>Pesan:</strong> ${pesan}</p>
                    <hr>
                    <p style="font-size: 12px; color: #888;">Data ini sudah tersimpan di Database MongoDB.</p>
                </div>
            `
        });

        res.status(200).json({ status: "success", message: "Data terkirim" });
    } catch (err) {
        res.status(500).json({ status: "error", message: "Gagal memproses data" });
    }
});

module.exports = app;
