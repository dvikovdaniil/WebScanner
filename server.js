const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "scanstock-k8x2m9pLwQz7vR4nJ6bY3cT0";

// ═══════════════════════════════════════════
// Database setup (persistent in /data)
// ═══════════════════════════════════════════
const fs = require("fs");

// Папка data рядом с сервером
const DB_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DB_DIR, "scanstock.db");

// Создаём папку если её нет
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
  console.log("📁 Создана папка data");
}

console.log("📦 База данных:", DB_PATH);

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS warehouses (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS cells (
    id TEXT PRIMARY KEY,
    warehouse_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (warehouse_id) REFERENCES warehouses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cell_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    barcode TEXT NOT NULL,
    article TEXT DEFAULT '',
    scanned_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (cell_id) REFERENCES cells(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    barcode TEXT NOT NULL,
    article TEXT NOT NULL,
    UNIQUE(user_id, barcode),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS settings (
    user_id INTEGER PRIMARY KEY,
    barcode_format TEXT DEFAULT 'all',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Prepared statements
const stmts = {
  // Users
  createUser: db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)"),
  findUser: db.prepare("SELECT * FROM users WHERE username = ?"),

  // Warehouses
  getWarehouses: db.prepare("SELECT * FROM warehouses WHERE user_id = ? ORDER BY created_at"),
  createWarehouse: db.prepare("INSERT INTO warehouses (id, user_id, name) VALUES (?, ?, ?)"),
  deleteWarehouse: db.prepare("DELETE FROM warehouses WHERE id = ? AND user_id = ?"),
  renameWarehouse: db.prepare("UPDATE warehouses SET name = ? WHERE id = ? AND user_id = ?"),

  // Cells
  getCells: db.prepare("SELECT * FROM cells WHERE warehouse_id = ? AND user_id = ? ORDER BY created_at"),
  createCell: db.prepare("INSERT INTO cells (id, warehouse_id, user_id, name) VALUES (?, ?, ?, ?)"),
  deleteCell: db.prepare("DELETE FROM cells WHERE id = ? AND user_id = ?"),
  getCell: db.prepare("SELECT * FROM cells WHERE id = ? AND user_id = ?"),

  // Scans
  getScans: db.prepare("SELECT * FROM scans WHERE cell_id = ? AND user_id = ? ORDER BY scanned_at DESC"),
  addScan: db.prepare("INSERT INTO scans (cell_id, user_id, barcode, article, scanned_at) VALUES (?, ?, ?, ?, ?)"),
  deleteScansByBarcode: db.prepare("DELETE FROM scans WHERE cell_id = ? AND user_id = ? AND barcode = ?"),
  deleteLastScan: db.prepare(`
    DELETE FROM scans WHERE id = (
      SELECT id FROM scans WHERE cell_id = ? AND user_id = ? AND barcode = ? ORDER BY scanned_at DESC LIMIT 1
    )
  `),

  // Articles
  getArticles: db.prepare("SELECT * FROM articles WHERE user_id = ?"),
  upsertArticle: db.prepare("INSERT INTO articles (user_id, barcode, article) VALUES (?, ?, ?) ON CONFLICT(user_id, barcode) DO UPDATE SET article = excluded.article"),
  getArticle: db.prepare("SELECT article FROM articles WHERE user_id = ? AND barcode = ?"),
  deleteArticles: db.prepare("DELETE FROM articles WHERE user_id = ?"),

  // Settings
  getSettings: db.prepare("SELECT * FROM settings WHERE user_id = ?"),
  upsertSettings: db.prepare("INSERT INTO settings (user_id, barcode_format) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET barcode_format = excluded.barcode_format"),

  // Export
  exportAll: db.prepare(`
    SELECT
      COALESCE(a.article, s.article, '') as article,
      s.barcode,
      w.name || ' / ' || c.name as cell,
      s.scanned_at
    FROM scans s
    JOIN cells c ON s.cell_id = c.id
    JOIN warehouses w ON c.warehouse_id = w.id
    LEFT JOIN articles a ON a.user_id = s.user_id AND a.barcode = s.barcode
    WHERE s.user_id = ?
    ORDER BY s.scanned_at DESC
  `),

  // Nuke
  deleteAllData: db.prepare("DELETE FROM warehouses WHERE user_id = ?"),
};

// ═══════════════════════════════════════════
// Middleware
// ═══════════════════════════════════════════
app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.static(path.join(__dirname, "public")));

// Auth middleware
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return res.status(401).json({ error: "Необходима авторизация" });
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = payload.id;
    req.username = payload.username;
    next();
  } catch {
    res.status(401).json({ error: "Токен истёк или невалиден" });
  }
}

function uid() {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
}

// ═══════════════════════════════════════════
// AUTH routes
// ═══════════════════════════════════════════
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username?.trim() || !password?.trim()) return res.status(400).json({ error: "Заполните все поля" });
  if (password.length < 4) return res.status(400).json({ error: "Пароль от 4 символов" });
  if (stmts.findUser.get(username.trim())) return res.status(409).json({ error: "Пользователь уже существует" });

  const hash = bcrypt.hashSync(password, 10);
  const result = stmts.createUser.run(username.trim(), hash);
  const token = jwt.sign({ id: result.lastInsertRowid, username: username.trim() }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, username: username.trim() });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = stmts.findUser.get(username?.trim());
  if (!user) return res.status(401).json({ error: "Пользователь не найден" });
  if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: "Неверный пароль" });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, username: user.username });
});

app.get("/api/me", auth, (req, res) => {
  res.json({ username: req.username });
});

// ═══════════════════════════════════════════
// WAREHOUSES
// ═══════════════════════════════════════════
app.get("/api/warehouses", auth, (req, res) => {
  const warehouses = stmts.getWarehouses.all(req.userId);
  // Add cell count and scan count
  const result = warehouses.map(w => {
    const cells = stmts.getCells.all(w.id, req.userId);
    let scanCount = 0;
    cells.forEach(c => { scanCount += stmts.getScans.all(c.id, req.userId).length; });
    return { ...w, cellCount: cells.length, scanCount };
  });
  res.json(result);
});

app.post("/api/warehouses", auth, (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Укажите название" });
  const id = uid();
  stmts.createWarehouse.run(id, req.userId, name.trim());
  res.json({ id, name: name.trim() });
});

app.delete("/api/warehouses/:id", auth, (req, res) => {
  stmts.deleteWarehouse.run(req.params.id, req.userId);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════
// CELLS
// ═══════════════════════════════════════════
app.get("/api/warehouses/:whId/cells", auth, (req, res) => {
  const cells = stmts.getCells.all(req.params.whId, req.userId);
  const result = cells.map(c => {
    const scans = stmts.getScans.all(c.id, req.userId);
    const items = {};
    scans.forEach(s => {
      if (!items[s.barcode]) items[s.barcode] = { barcode: s.barcode, article: s.article, qty: 0 };
      items[s.barcode].qty++;
      // Update article from articles table
      const art = stmts.getArticle.get(req.userId, s.barcode);
      if (art) items[s.barcode].article = art.article;
    });
    return { ...c, itemCount: Object.keys(items).length, scanCount: scans.length };
  });
  res.json(result);
});

app.post("/api/warehouses/:whId/cells", auth, (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Укажите название" });
  const id = uid();
  stmts.createCell.run(id, req.params.whId, req.userId, name.trim());
  res.json({ id, name: name.trim() });
});

app.delete("/api/cells/:id", auth, (req, res) => {
  stmts.deleteCell.run(req.params.id, req.userId);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════
// SCANS (items in a cell)
// ═══════════════════════════════════════════
app.get("/api/cells/:cellId/items", auth, (req, res) => {
  const scans = stmts.getScans.all(req.params.cellId, req.userId);
  const items = {};
  scans.forEach(s => {
    if (!items[s.barcode]) {
      const art = stmts.getArticle.get(req.userId, s.barcode);
      items[s.barcode] = { barcode: s.barcode, article: art?.article || s.article || "", qty: 0, scans: [] };
    }
    items[s.barcode].qty++;
    items[s.barcode].scans.push(s.scanned_at);
  });
  res.json(Object.values(items));
});

app.post("/api/cells/:cellId/scan", auth, (req, res) => {
  const { barcode } = req.body;
  if (!barcode?.trim()) return res.status(400).json({ error: "Пустой баркод" });
  const cell = stmts.getCell.get(req.params.cellId, req.userId);
  if (!cell) return res.status(404).json({ error: "Ячейка не найдена" });

  const art = stmts.getArticle.get(req.userId, barcode.trim());
  const now = new Date().toISOString();
  stmts.addScan.run(req.params.cellId, req.userId, barcode.trim(), art?.article || "", now);
  res.json({ ok: true, article: art?.article || "" });
});

app.delete("/api/cells/:cellId/items/:barcode", auth, (req, res) => {
  stmts.deleteScansByBarcode.run(req.params.cellId, req.userId, decodeURIComponent(req.params.barcode));
  res.json({ ok: true });
});

app.post("/api/cells/:cellId/items/:barcode/adjust", auth, (req, res) => {
  const { delta } = req.body;
  const barcode = decodeURIComponent(req.params.barcode);
  if (delta > 0) {
    const art = stmts.getArticle.get(req.userId, barcode);
    stmts.addScan.run(req.params.cellId, req.userId, barcode, art?.article || "", new Date().toISOString());
  } else if (delta < 0) {
    stmts.deleteLastScan.run(req.params.cellId, req.userId, barcode);
  }
  res.json({ ok: true });
});

// ═══════════════════════════════════════════
// ARTICLES
// ═══════════════════════════════════════════
app.get("/api/articles", auth, (req, res) => {
  res.json(stmts.getArticles.all(req.userId));
});

app.post("/api/articles/upload", auth, (req, res) => {
  const { items } = req.body; // [{ barcode, article }]
  if (!Array.isArray(items)) return res.status(400).json({ error: "Неверный формат" });
  const upsert = db.transaction((list) => {
    for (const { barcode, article } of list) {
      if (barcode?.trim() && article?.trim()) {
        stmts.upsertArticle.run(req.userId, barcode.trim(), article.trim());
      }
    }
  });
  upsert(items);
  res.json({ ok: true, count: items.length });
});

app.delete("/api/articles", auth, (req, res) => {
  stmts.deleteArticles.run(req.userId);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════
app.get("/api/settings", auth, (req, res) => {
  const s = stmts.getSettings.get(req.userId);
  res.json(s || { barcode_format: "all" });
});

app.put("/api/settings", auth, (req, res) => {
  const { barcode_format } = req.body;
  stmts.upsertSettings.run(req.userId, barcode_format || "all");
  res.json({ ok: true });
});

// ═══════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════
app.get("/api/export", auth, (req, res) => {
  const rows = stmts.exportAll.all(req.userId);
  res.json(rows);
});

// ═══════════════════════════════════════════
// RESET
// ═══════════════════════════════════════════
app.delete("/api/data", auth, (req, res) => {
  stmts.deleteAllData.run(req.userId);
  stmts.deleteArticles.run(req.userId);
  res.json({ ok: true });
});

// SPA fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ═══════════════════════════════════════════
// Start HTTP + HTTPS
// ═══════════════════════════════════════════
const https = require("https");
const { execSync } = require("child_process");

const keyPath = path.join(__dirname, "key.pem");
const certPath = path.join(__dirname, "cert.pem");

// Auto-generate self-signed cert if missing
if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  try {
    console.log("  🔐 Генерация SSL-сертификата...");
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 365 -nodes -subj "/CN=scanstock"`,
      { stdio: "ignore" }
    );
  } catch (e) {
    console.log("  ⚠️  openssl не найден — HTTPS недоступен. Камера будет работать только на localhost.");
    console.log("     Установите openssl или используйте: npx ngrok http " + PORT);
  }
}

// HTTP
app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n  ✅ ScanStock запущен:`);
  console.log(`     http://localhost:${PORT}`);
});

// HTTPS (for mobile camera)
if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
  const HTTPS_PORT = Number(PORT) + 443; // 3443
  try {
    https.createServer({
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    }, app).listen(HTTPS_PORT, "0.0.0.0", () => {
      console.log(`     https://localhost:${HTTPS_PORT}`);
      console.log(`\n  📱 С телефона: https://192.168.1.50:${HTTPS_PORT}`);
      console.log(`     (примите предупреждение о сертификате)\n`);
    });
  } catch (e) {
    console.log("  ⚠️  Не удалось запустить HTTPS:", e.message);
  }
}