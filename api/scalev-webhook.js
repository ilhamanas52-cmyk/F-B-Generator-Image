// ============================================================
// /api/scalev-webhook.js — Vercel Serverless Function
//
// Menerima webhook dari Scalev saat status pembayaran sebuah order
// berubah. Kalau order itu adalah pembelian "Upgrade Pro" dan sudah
// berstatus "paid", otomatis ubah field `plan` milik user yang
// bersangkutan (dicocokkan lewat EMAIL) di Firestore jadi 'reseller'
// — sehingga user TIDAK PERLU login ulang / bikin akun baru, cukup
// pakai email & password yang sama seperti sebelumnya, dan status
// Pro-nya langsung aktif begitu pembayaran berhasil.
//
// ============================================================
// ENVIRONMENT VARIABLES — WAJIB diset di Vercel Dashboard
// (Project → Settings → Environment Variables), JANGAN PERNAH
// ditulis langsung di file ini atau di index.html:
//
//   SCALEV_SIGNING_SECRET   → dari Scalev: Settings > Developers
//   FIREBASE_PROJECT_ID     → dari file service-account.json
//   FIREBASE_CLIENT_EMAIL   → dari file service-account.json
//   FIREBASE_PRIVATE_KEY    → dari file service-account.json, SALIN
//                             APA ADANYA termasuk semua "\n" di
//                             dalamnya, TANPA tanda kutip pembungkus
// ============================================================

import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';
import { getAuth } from 'firebase-admin/auth';
import crypto from 'crypto';

// Inisialisasi Firebase Admin SEKALI SAJA per instance function —
// Vercel bisa "recycle" (memakai ulang) instance yang sama untuk
// beberapa request berturut-turut, jadi kalau tidak dicek getApps()
// dulu, initializeApp() akan dipanggil berkali-kali dan error.
if (!getApps().length) {
  initializeApp({
    credential: cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      // Environment Variable di Vercel menyimpan "\n" sebagai TEKS
      // LITERAL 2 karakter (backslash + n), bukan baris baru
      // sungguhan — baris ini yang mengembalikannya jadi baris baru
      // asli, sesuai format PEM yang dibutuhkan private key.
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n')
    })
  });
}

const db = getFirestore();
const auth = getAuth();

// Nama produk PERSIS seperti yang dikirim Scalev di dalam payload
// (data.pg_paid_info.items[].name) — kalau nanti nama produk di
// Scalev diganti, cukup ubah 1 baris ini, tidak perlu ubah logika lain.
const UPGRADE_PRODUCT_NAME = 'Upgrade Pro';

// Vercel butuh RAW BODY (bukan hasil parse otomatis) untuk verifikasi
// HMAC — signature dihitung dari byte PERSIS yang dikirim Scalev,
// bukan dari hasil JSON.stringify ulang (urutan key bisa berbeda dan
// bikin signature tidak pernah cocok).
export const config = {
  api: {
    bodyParser: false
  }
};

const readRawBody = req => new Promise((resolve, reject) => {
  let data = '';
  req.on('data', chunk => {
    data += chunk;
  });
  req.on('end', () => resolve(data));
  req.on('error', reject);
});

// Perbandingan waktu-konstan (bukan `===` biasa) — mencegah "timing
// attack", praktik standar untuk verifikasi signature apa pun.
const verifySignature = (rawBody, signatureHeader) => {
  if (!signatureHeader) return false;
  const expected = crypto.createHmac('sha256', process.env.SCALEV_SIGNING_SECRET).update(rawBody).digest('base64');
  const a = Buffer.from(expected);
  const b = Buffer.from(signatureHeader);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({
      error: 'Method not allowed'
    });
    return;
  }
  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (e) {
    res.status(400).json({
      error: 'Gagal membaca request body'
    });
    return;
  }
  const signature = req.headers['x-scalev-hmac-sha256'];
  if (!verifySignature(rawBody, signature)) {
    res.status(401).json({
      error: 'Signature tidak valid'
    });
    return;
  }
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (e) {
    res.status(400).json({
      error: 'Body bukan JSON valid'
    });
    return;
  }

  // Kiriman uji koneksi awal dari Scalev (saat pertama kali toggle
  // Active + Save) — WAJIB dibalas 200, kalau tidak pengaturan
  // webhook di dashboard Scalev tidak akan pernah tersimpan.
  if (payload.event === 'business.test_event') {
    res.status(200).json({
      received: true
    });
    return;
  }
  try {
    const data = payload.data || {};
    const isPaymentEvent = payload.event === 'order.payment_status_changed';
    const isPaid = data.payment_status === 'paid';
    const items = data.pg_paid_info && data.pg_paid_info.items || [];
    const isUpgradeProduct = items.some(item => item.name === UPGRADE_PRODUCT_NAME);
    const buyerEmail = data.customer && data.customer.email;
    if (isPaymentEvent && isPaid && isUpgradeProduct && buyerEmail) {
      const userRecord = await auth.getUserByEmail(buyerEmail).catch(() => null);
      if (userRecord) {
        await db.collection('users').doc(userRecord.uid).set({
          plan: 'reseller'
        }, {
          merge: true
        });
        console.log(`[scalev-webhook] Berhasil upgrade ke Pro: ${buyerEmail} (uid: ${userRecord.uid})`);
      } else {
        // Email pembeli tidak ketemu di akun Firebase manapun —
        // kemungkinan dia beli pakai email berbeda dari yang dipakai
        // login aplikasi. Bukan error sementara (diulang pun hasilnya
        // akan sama), jadi tetap balas 200 ke Scalev supaya tidak
        // dikirim ulang terus-menerus — tapi dicatat di log Vercel
        // supaya bisa ditindaklanjuti manual oleh pemilik aplikasi.
        console.warn(`[scalev-webhook] Email pembeli tidak ditemukan di akun manapun: ${buyerEmail}`);
      }
    }
    res.status(200).json({
      received: true
    });
  } catch (e) {
    // Error yang benar-benar tidak terduga (misal Firestore/Firebase
    // Admin sedang bermasalah) — balas 500 (bukan 200) supaya KALAU
    // Scalev punya mekanisme retry otomatis, masih ada kesempatan
    // berhasil di percobaan berikutnya, bukan langsung dianggap sukses
    // padahal upgrade user itu gagal tersimpan.
    console.error('[scalev-webhook] Error tak terduga:', e);
    res.status(500).json({
      error: 'Internal error, cek log server'
    });
  }
}
