// Membuat database (jika belum ada) lalu menjalankan schema.sql
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

(async () => {
  const name = process.env.DB_NAME || 'laundry_akbar';
  if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error('DB_NAME hanya boleh huruf, angka, dan underscore.');
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    multipleStatements: true
  });
  await conn.query(`CREATE DATABASE IF NOT EXISTS \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  await conn.changeUser({ database: name });
  await conn.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
  await conn.end();
  console.log(`Database "${name}" siap digunakan.`);
})().catch(e => { console.error('Gagal menyiapkan database:', e.message); process.exit(1); });
