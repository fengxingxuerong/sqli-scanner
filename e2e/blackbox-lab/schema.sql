-- ============================================================================
-- blackbox-lab / schema.sql —— 外部视角独立评测靶场的库表
--
-- [独立评测] 不复用项目自带靶场（redteam-lab / real-mysql-lab 等），
-- 由评测方另起一套，避免「作者自证」。
-- 库名 blackbox_lab 与项目的 sqli_lab 隔离。
-- ============================================================================

DROP DATABASE IF EXISTS blackbox_lab;
CREATE DATABASE blackbox_lab DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE blackbox_lab;

-- 主业务表：数值/字符串/LIKE 注入的落点
CREATE TABLE users (
  id        INT PRIMARY KEY AUTO_INCREMENT,
  username  VARCHAR(64) NOT NULL,
  passwd    VARCHAR(128) NOT NULL,
  email     VARCHAR(128),
  role      VARCHAR(32) DEFAULT 'user',
  balance   DECIMAL(10,2) DEFAULT 0.00
) ENGINE=InnoDB;

INSERT INTO users (id, username, passwd, email, role, balance) VALUES
  (1, 'alice',  '5f4dcc3b5aa765d61d8327deb882cf99', 'alice@blackbox.test',  'admin', 12800.50),
  (2, 'bob',    'e10adc3949ba59abbe56e057f20f883e', 'bob@blackbox.test',    'user',   3400.00),
  (3, 'carol',  '25d55ad283aa400af464c76d713c07ad', 'carol@blackbox.test',  'user',    120.75),
  (4, 'dave',   'd8578edf8458ce06fbc5bb76a58c5ca4', 'dave@blackbox.test',   'editor', 9900.00),
  (5, 'eve',    'e99a18c428cb38d5f260853678922e03', 'eve@blackbox.test',    'user',     88.88);

-- 商品表：ORDER BY / 报错型的落点
CREATE TABLE products (
  id       INT PRIMARY KEY AUTO_INCREMENT,
  name     VARCHAR(96) NOT NULL,
  category VARCHAR(48),
  price    DECIMAL(10,2),
  stock    INT DEFAULT 0
) ENGINE=InnoDB;

INSERT INTO products (id, name, category, price, stock) VALUES
  (1, 'Mechanical Keyboard', 'peripherals',  499.00, 12),
  (2, 'Noise Cancel Headphone', 'audio',     1299.00, 5),
  (3, 'USB-C Hub',          'peripherals',    199.00, 40),
  (4, '27 inch Monitor',    'display',      1899.00, 3),
  (5, 'Webcam 1080p',       'video',         289.00, 18),
  (6, 'Laptop Stand',       'accessories',    89.00, 60);

-- 订单表：二阶注入的「存储」落点（写入方低权，触发页高权）
CREATE TABLE orders (
  id         INT PRIMARY KEY AUTO_INCREMENT,
  username   VARCHAR(64) NOT NULL,
  item       VARCHAR(128),
  address    VARCHAR(256),
  status     VARCHAR(24) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT INTO orders (username, item, address, status) VALUES
  ('alice', 'Mechanical Keyboard', 'Room 501, Build 3', 'shipped'),
  ('bob',   'USB-C Hub',           'Floor 12, Tower A', 'pending');

-- 会话表：二阶触发页的鉴权依据（模拟真实系统的角色门禁）
CREATE TABLE sessions (
  token    VARCHAR(64) PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  role     VARCHAR(32) NOT NULL
) ENGINE=InnoDB;

INSERT INTO sessions (token, username, role) VALUES
  ('tok-admin-blackbox-0001', 'alice', 'admin'),
  ('tok-user-blackbox-0002',  'bob',   'user');

-- 用于真值 selftest 的标记表（确认提取通道能拖出真实数据）
CREATE TABLE secrets (
  id    INT PRIMARY KEY AUTO_INCREMENT,
  label VARCHAR(64),
  value VARCHAR(128)
) ENGINE=InnoDB;

INSERT INTO secrets (label, value) VALUES
  ('db_marker',  'BLACKBOX_LAB_DB_MARKER_7f3a9c'),
  ('api_key',    'sk-blackbox-4e8d2a1f7c6b'),
  ('flag',       'FLAG{blackbox_lab_independent_eval}');

SELECT 'schema ready' AS status,
       (SELECT COUNT(*) FROM users) AS users,
       (SELECT COUNT(*) FROM products) AS products,
       (SELECT COUNT(*) FROM secrets) AS secrets;
