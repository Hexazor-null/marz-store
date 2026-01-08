const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const helmet = require('helmet');
const xss = require('xss');
const hpp = require('hpp');
const cors = require('cors');
const nodemailer = require('nodemailer');

require('dotenv').config({ path: path.join(__dirname, '../.env') });

const app = express();

app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10kb' }));
app.use(hpp());

const Inquiry = mongoose.model('Inquiry', new mongoose.Schema({
    email: String,
    whatsapp: String,
    pesan: String,
    createdAt: { type: Date, default: Date.now }
}));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { 
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS 
    }
});

app.post('/api/marz/consult', async (req, res) => {
    try {
        const email = xss(req.body.email);
        const whatsapp = xss(req.body.whatsapp);
        const pesan = xss(req.body.pesan);

        const newLead = new Inquiry({ email, whatsapp, pesan });
        await newLead.save();

        await transporter.sendMail({
            from: '"MARZ STORE" <noreply@marzstore.com>',
            to: process.env.EMAIL_USER,
            subject: `INQUIRY KONSULTASI: ${email}`,
            html: `
                <div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee;">
                    <h2>Detail Masuk</h2>
                    <p><strong>Email:</strong> ${email}</p>
                    <p><strong>WhatsApp:</strong> ${whatsapp}</p>
                    <p><strong>Pesan:</strong> ${pesan}</p>
                </div>
            `
        });

        res.status(200).json({ status: "success" });
    } catch (err) {
        res.status(500).json({ status: "error", msg: "Gagal memproses permintaan" });
    }
});

const PORT = process.env.PORT || 3000;
mongoose.connect(process.env.MONGODB_URI)
    .then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
    .catch(err => console.error("Database connection error:", err));
