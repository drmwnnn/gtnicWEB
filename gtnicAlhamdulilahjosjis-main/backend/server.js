require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const ADMIN_KEY = ADMIN_USERNAME.toLowerCase();
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;

const STATUSES = ['Menunggu', 'Diproses', 'Selesai', 'Diambil'];
const PICKUPS = ['antar-jemput', 'antar-sendiri'];

/* ---------- Koneksi MySQL (connection pool) ---------- */
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'laundry_akbar',
  waitForConnections: true,
  connectionLimit: 10,
  charset: 'utf8mb4'
});

async function tx(fn) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await fn(conn);
    await conn.commit();
    return result;
  } catch (e) {
    await conn.rollback().catch(() => {});
    throw e;
  } finally {
    conn.release();
  }
}

/* ---------- Helper keamanan ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const a = Buffer.from(hash, 'hex');
  const b = crypto.scryptSync(pw, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const attempts = new Map();
const blocked = k => { const a = attempts.get(k); return a && a.count >= 8 && Date.now() - a.first < 15 * 60 * 1000; };
function failed(k) {
  const now = Date.now(), a = attempts.get(k);
  if (!a || now - a.first > 15 * 60 * 1000) attempts.set(k, { count: 1, first: now }); else a.count++;
}

/* ---------- Fungsi database ---------- */
let adminId = null;

async function ensureAdmin() {
  const hash = hashPassword(ADMIN_PASSWORD);
  const [rows] = await pool.execute('SELECT id FROM users WHERE user_key = ?', [ADMIN_KEY]);
  if (rows.length) {
    await pool.execute("UPDATE users SET password_hash = ?, role = 'admin' WHERE id = ?", [hash, rows[0].id]);
    adminId = rows[0].id;
  } else {
    const [r] = await pool.execute(
      "INSERT INTO users (user_key, username, password_hash, role) VALUES (?, ?, ?, 'admin')",
      [ADMIN_KEY, ADMIN_USERNAME, hash]
    );
    adminId = r.insertId;
  }
}

async function notify(exec, userId, message) {
  await exec.execute(
    'INSERT INTO notifications (id, user_id, message, is_read, created_at) VALUES (?, ?, ?, 0, ?)',
    [crypto.randomUUID(), userId, message.slice(0, 600), Date.now()]
  );
}

async function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.execute('DELETE FROM sessions WHERE expires_at < ?', [Date.now()]);
  await pool.execute('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
    [sha(token), user.id, Date.now() + SESSION_TTL]);
  return token;
}

async function getPricing(exec = pool) {
  const [svc] = await exec.execute('SELECT name, price FROM services ORDER BY sort_order, name');
  const [set] = await exec.execute("SELECT value FROM settings WHERE name = 'pickup_fee'");
  const prices = {};
  svc.forEach(s => { prices[s.name] = Number(s.price); });
  return { prices, pickupFee: set.length ? Number(set[0].value) : 0 };
}

const ORDER_COLS = `seq, customer_name, service, weight, pickup, address, total_price,
  status, payment_status, DATE_FORMAT(order_date, '%Y-%m-%d') AS order_date, user_id`;

// Format sama persis dengan versi sebelumnya
const publicOrder = r => ({
  id: `ORD-${r.seq}`,
  customerName: r.customer_name,
  service: r.service,
  weight: Number(r.weight),
  pickup: r.pickup,
  address: r.address,
  totalPrice: Number(r.total_price),
  status: r.status,
  paymentStatus: r.payment_status,
  date: r.order_date
});
const publicUser = u => ({ username: u.username, role: u.role });
const rp = n => 'Rp ' + Number(n).toLocaleString('id-ID');
const parseOrderSeq = id => { const m = /^ORD-(\d{1,10})$/.exec(String(id)); return m ? Number(m[1]) : null; };
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/* ---------- App ---------- */
const app = express();
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, '..', 'frontend')));

const auth = wrap(async (req, res, next) => {
  const m = (req.headers.authorization || '').match(/^Bearer (.+)$/);
  if (!m) return res.status(401).json({ error: 'Silakan masuk terlebih dahulu.' });
  const h = sha(m[1]);
  const [rows] = await pool.execute(
    `SELECT u.id, u.user_key, u.username, u.role, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`, [h]);
  const s = rows[0];
  if (!s || Number(s.expires_at) < Date.now()) {
    if (s) await pool.execute('DELETE FROM sessions WHERE token_hash = ?', [h]);
    return res.status(401).json({ error: 'Sesi berakhir, silakan masuk kembali.' });
  }
  req.user = { id: s.id, key: s.user_key, username: s.username, role: s.role };
  req.tokenHash = h;
  next();
});
const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Hanya untuk admin.' });

/* ---------- Auth ---------- */
app.post('/api/auth/register', wrap(async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!/^[A-Za-z0-9_.-]{3,30}$/.test(username))
    return res.status(400).json({ error: 'Nama pengguna 3-30 karakter (huruf, angka, _ . -).' });
  if (password.length < 6) return res.status(400).json({ error: 'Kata sandi minimal 6 karakter.' });
  const key = username.toLowerCase();
  if (key === ADMIN_KEY) return res.status(400).json({ error: 'Nama pengguna "admin" tidak dapat digunakan!' });
  let id;
  try {
    const [r] = await pool.execute(
      "INSERT INTO users (user_key, username, password_hash, role) VALUES (?, ?, ?, 'user')",
      [key, username, hashPassword(password)]);
    id = r.insertId;
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Nama pengguna sudah terdaftar! Silakan masuk.' });
    throw e;
  }
  const user = { id, username, role: 'user' };
  res.status(201).json({ token: await createSession(user), user: publicUser(user) });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const limitKey = req.ip + ':' + username.toLowerCase();
  if (blocked(limitKey)) return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.' });
  const [rows] = await pool.execute(
    'SELECT id, username, password_hash, role FROM users WHERE user_key = ?', [username.toLowerCase()]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'Akun tidak ditemukan. Silakan daftar akun terlebih dahulu.' });
  if (!verifyPassword(password, user.password_hash)) {
    failed(limitKey);
    return res.status(401).json({ error: 'Kata sandi salah! Silakan coba lagi.' });
  }
  attempts.delete(limitKey);
  res.json({ token: await createSession(user), user: publicUser(user) });
}));

app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/auth/logout', auth, wrap(async (req, res) => {
  await pool.execute('DELETE FROM sessions WHERE token_hash = ?', [req.tokenHash]);
  res.json({ ok: true });
}));

/* ---------- Harga ---------- */
app.get('/api/pricing', wrap(async (req, res) => {
  const { prices, pickupFee } = await getPricing();
  res.json({ prices, pickupFee, statuses: STATUSES });
}));

/* ---------- Pesanan ---------- */
app.get('/api/orders', auth, wrap(async (req, res) => {
  const [rows] = req.user.role === 'admin'
    ? await pool.execute(`SELECT ${ORDER_COLS} FROM orders ORDER BY seq DESC`)
    : await pool.execute(`SELECT ${ORDER_COLS} FROM orders WHERE user_id = ? ORDER BY seq DESC`, [req.user.id]);
  res.json({ orders: rows.map(publicOrder) });
}));

app.post('/api/orders', auth, wrap(async (req, res) => {
  if (req.user.role === 'admin') return res.status(403).json({ error: 'Admin tidak dapat membuat pesanan.' });
  const service = String(req.body.service || '');
  const pickup = req.body.pickup;
  const weight = Math.round(Number(req.body.weight) * 100) / 100;
  let address = String(req.body.address || '').trim().slice(0, 300);

  const { prices, pickupFee } = await getPricing();
  if (!Object.prototype.hasOwnProperty.call(prices, service)) return res.status(400).json({ error: 'Layanan tidak valid.' });
  if (!PICKUPS.includes(pickup)) return res.status(400).json({ error: 'Opsi pengambilan tidak valid.' });
  if (!(weight > 0 && weight <= 100)) return res.status(400).json({ error: 'Berat harus antara 0.1 - 100 kg.' });
  if (pickup === 'antar-jemput' && !address) return res.status(400).json({ error: 'Alamat penjemputan wajib diisi.' });
  if (!address) address = 'Ambil di outlet';

  const totalPrice = Math.round(prices[service] * weight + (pickup === 'antar-jemput' ? pickupFee : 0));
  const date = new Date().toISOString().split('T')[0];

  const order = await tx(async conn => {
    const [r] = await conn.execute(
      `INSERT INTO orders (user_id, customer_name, service, weight, pickup, address, total_price, order_date)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.id, req.user.username, service, weight, pickup, address, totalPrice, date]);
    const o = {
      id: `ORD-${r.insertId}`, customerName: req.user.username, service, weight, pickup, address,
      totalPrice, status: 'Menunggu', paymentStatus: 'Menunggu Pembayaran', date
    };
    await notify(conn, adminId,
      `Pesanan baru ${o.id} dari ${o.customerName} (${service}, ${weight} kg, ${rp(totalPrice)}).`);
    return o;
  });
  res.status(201).json(order);
}));

app.patch('/api/orders/:id/status', auth, adminOnly, wrap(async (req, res) => {
  const seq = parseOrderSeq(req.params.id);
  const status = req.body.status;
  const [rows] = seq ? await pool.execute(`SELECT ${ORDER_COLS} FROM orders WHERE seq = ?`, [seq]) : [[]];
  if (!rows.length) return res.status(404).json({ error: 'Pesanan tidak ditemukan.' });
  if (!STATUSES.includes(status)) return res.status(400).json({ error: 'Status tidak valid.' });
  const order = rows[0];
  await tx(async conn => {
    await conn.execute('UPDATE orders SET status = ? WHERE seq = ?', [status, seq]);
    await notify(conn, order.user_id, `Status pesanan ORD-${seq} diperbarui menjadi "${status}".`);
  });
  order.status = status;
  res.json(publicOrder(order));
}));

// Simulasi pembayaran QRIS (lihat README untuk integrasi payment gateway sungguhan)
app.post('/api/orders/:id/pay', auth, wrap(async (req, res) => {
  const seq = parseOrderSeq(req.params.id);
  const [rows] = seq ? await pool.execute(`SELECT ${ORDER_COLS} FROM orders WHERE seq = ?`, [seq]) : [[]];
  const order = rows[0];
  if (!order || (req.user.role !== 'admin' && order.user_id !== req.user.id))
    return res.status(404).json({ error: 'Pesanan tidak ditemukan.' });
  if (order.payment_status !== 'Lunas') {
    await tx(async conn => {
      const [r] = await conn.execute(
        "UPDATE orders SET payment_status = 'Lunas' WHERE seq = ? AND payment_status <> 'Lunas'", [seq]);
      if (r.affectedRows) {
        const msg = `Pembayaran QRIS untuk pesanan ORD-${seq} (${rp(order.total_price)}) telah Lunas.`;
        await notify(conn, order.user_id, msg);
        await notify(conn, adminId, `${msg} Pelanggan: ${order.customer_name}.`);
      }
    });
    order.payment_status = 'Lunas';
  }
  res.json(publicOrder(order));
}));

/* ---------- Notifikasi ---------- */
app.get('/api/notifications', auth, wrap(async (req, res) => {
  const [rows] = await pool.execute(
    'SELECT id, message, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
    [req.user.id]);
  res.json({
    notifications: rows.map(n => ({
      id: n.id, message: n.message, read: !!n.is_read, createdAt: new Date(Number(n.created_at)).toISOString()
    }))
  });
}));

app.post('/api/notifications/read', auth, wrap(async (req, res) => {
  await pool.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [req.user.id]);
  res.json({ ok: true });
}));

/* ---------- Form kontak ---------- */
app.post('/api/contact', wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 100);
  const phone = String(req.body.phone || '').trim().slice(0, 30);
  const message = String(req.body.message || '').trim().slice(0, 1000);
  if (!name || !phone || !message) return res.status(400).json({ error: 'Semua kolom wajib diisi.' });
  await tx(async conn => {
    await conn.execute('INSERT INTO messages (id, name, phone, message, created_at) VALUES (?, ?, ?, ?, ?)',
      [crypto.randomUUID(), name, phone, message, Date.now()]);
    await notify(conn, adminId, `Pesan baru dari ${name} (${phone}): ${message.slice(0, 120)}`);
  });
  res.status(201).json({ ok: true });
}));

app.get('/api/admin/messages', auth, adminOnly, wrap(async (req, res) => {
  const [rows] = await pool.execute(
    'SELECT id, name, phone, message, created_at FROM messages ORDER BY created_at DESC');
  res.json({
    messages: rows.map(m => ({
      id: m.id, name: m.name, phone: m.phone, message: m.message,
      createdAt: new Date(Number(m.created_at)).toISOString()
    }))
  });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan.' }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Format data tidak valid.' });
  console.error(err);
  res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
});

/* ---------- Start ---------- */
(async () => {
  try {
    await pool.query('SELECT 1');
    await ensureAdmin();
  } catch (e) {
    console.error('Gagal menyiapkan database:', e.message);
    console.error('Periksa DB_* di file .env, lalu jalankan: npm run db:init');
    process.exit(1);
  }
  // Bersih-bersih berkala: sesi kedaluwarsa & notifikasi > 90 hari
  setInterval(() => {
    pool.execute('DELETE FROM sessions WHERE expires_at < ?', [Date.now()]).catch(() => {});
    pool.execute('DELETE FROM notifications WHERE created_at < ?', [Date.now() - 90 * 24 * 3600 * 1000]).catch(() => {});
  }, 60 * 60 * 1000).unref();
  app.listen(PORT, () => console.log(`Laundry Akbar berjalan di http://localhost:${PORT}`));
})();
