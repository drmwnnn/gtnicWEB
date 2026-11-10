-- Skema database Laundry Akbar (MySQL 5.7+ / 8.x / MariaDB 10.3+)
-- Jalankan lewat:  npm run db:init   (otomatis membuat database + tabel)
-- atau manual:     mysql -u root -p laundry_akbar < schema.sql

-- Akun admin & pelanggan
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_key      VARCHAR(30)  NOT NULL,            -- username huruf kecil (unik)
  username      VARCHAR(30)  NOT NULL,
  password_hash VARCHAR(255) NOT NULL,            -- salt:scrypt
  role          ENUM('admin','user') NOT NULL DEFAULT 'user',
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_user_key (user_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sesi login (token disimpan dalam bentuk hash SHA-256)
CREATE TABLE IF NOT EXISTS sessions (
  token_hash CHAR(64) NOT NULL,
  user_id    INT UNSIGNED NOT NULL,
  expires_at BIGINT NOT NULL,                     -- epoch milidetik
  PRIMARY KEY (token_hash),
  KEY idx_sessions_user (user_id),
  KEY idx_sessions_expires (expires_at),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Daftar layanan & harga per kg
CREATE TABLE IF NOT EXISTS services (
  name       VARCHAR(30) NOT NULL,
  price      INT UNSIGNED NOT NULL,
  sort_order TINYINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Pengaturan (mis. biaya antar-jemput)
CREATE TABLE IF NOT EXISTS settings (
  name  VARCHAR(50)  NOT NULL,
  value VARCHAR(255) NOT NULL,
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Pesanan (id tampil sebagai ORD-<seq>, dimulai dari ORD-1001)
CREATE TABLE IF NOT EXISTS orders (
  seq            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id        INT UNSIGNED NOT NULL,
  customer_name  VARCHAR(30)  NOT NULL,
  service        VARCHAR(30)  NOT NULL,
  weight         DECIMAL(6,2) NOT NULL,
  pickup         ENUM('antar-jemput','antar-sendiri') NOT NULL,
  address        VARCHAR(300) NOT NULL,
  total_price    INT UNSIGNED NOT NULL,
  status         ENUM('Menunggu','Diproses','Selesai','Diambil') NOT NULL DEFAULT 'Menunggu',
  payment_status ENUM('Menunggu Pembayaran','Lunas') NOT NULL DEFAULT 'Menunggu Pembayaran',
  order_date     DATE NOT NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (seq),
  KEY idx_orders_user (user_id),
  KEY idx_orders_status (status),
  CONSTRAINT fk_orders_user    FOREIGN KEY (user_id) REFERENCES users (id),
  CONSTRAINT fk_orders_service FOREIGN KEY (service) REFERENCES services (name)
) ENGINE=InnoDB AUTO_INCREMENT=1001 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Notifikasi per akun
CREATE TABLE IF NOT EXISTS notifications (
  id         CHAR(36) NOT NULL,
  user_id    INT UNSIGNED NOT NULL,
  message    VARCHAR(600) NOT NULL,
  is_read    TINYINT(1) NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,                     -- epoch milidetik
  PRIMARY KEY (id),
  KEY idx_notif_user_time (user_id, created_at),
  CONSTRAINT fk_notif_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Pesan dari form "Hubungi Kami"
CREATE TABLE IF NOT EXISTS messages (
  id         CHAR(36) NOT NULL,
  name       VARCHAR(100) NOT NULL,
  phone      VARCHAR(30)  NOT NULL,
  message    VARCHAR(1000) NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (id),
  KEY idx_messages_time (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data awal (aman dijalankan berulang)
INSERT IGNORE INTO services (name, price, sort_order) VALUES
  ('Reguler', 6000, 1), ('Kering', 12000, 2), ('Basah', 4000, 3), ('Express', 10000, 4);
INSERT IGNORE INTO settings (name, value) VALUES ('pickup_fee', '5000');
