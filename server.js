const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "scanstock-k8x2m9pLwQz7vR4nJ6bY3cT0";

const DB_DIR = "/data";
const DB_PATH = path.join(DB_DIR, "scanstock.db");
const BACKUP_DIR = path.join(DB_DIR, "backups");

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

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
    id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS cells (
    id TEXT PRIMARY KEY, warehouse_id TEXT NOT NULL, user_id INTEGER NOT NULL, name TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (warehouse_id) REFERENCES warehouses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cell_id TEXT NOT NULL, user_id INTEGER NOT NULL,
    barcode TEXT NOT NULL, article TEXT DEFAULT '', ki TEXT DEFAULT '',
    scanned_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (cell_id) REFERENCES cells(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, barcode TEXT NOT NULL, article TEXT NOT NULL,
    UNIQUE(user_id, barcode),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS settings (
    user_id INTEGER PRIMARY KEY,
    barcode_format TEXT DEFAULT 'all',
    scan_delay INTEGER DEFAULT 300,
    scan_confirmations INTEGER DEFAULT 3,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS user_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, file_type TEXT NOT NULL,
    filename TEXT NOT NULL, data BLOB NOT NULL,
    uploaded_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Migrations
try { db.exec("ALTER TABLE scans ADD COLUMN ki TEXT DEFAULT ''"); } catch(e) {}
try { db.exec("ALTER TABLE settings ADD COLUMN scan_delay INTEGER DEFAULT 300"); } catch(e) {}
try { db.exec("ALTER TABLE settings ADD COLUMN scan_confirmations INTEGER DEFAULT 3"); } catch(e) {}

// Track scan count for auto-backup
const scanCounters = {};

const stmts = {
  createUser: db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)"),
  findUser: db.prepare("SELECT * FROM users WHERE username = ?"),

  getWarehouses: db.prepare("SELECT * FROM warehouses WHERE user_id = ? ORDER BY created_at"),
  createWarehouse: db.prepare("INSERT INTO warehouses (id, user_id, name) VALUES (?, ?, ?)"),
  deleteWarehouse: db.prepare("DELETE FROM warehouses WHERE id = ? AND user_id = ?"),
  renameWarehouse: db.prepare("UPDATE warehouses SET name = ? WHERE id = ? AND user_id = ?"),

  getCells: db.prepare("SELECT * FROM cells WHERE warehouse_id = ? AND user_id = ? ORDER BY created_at"),
  createCell: db.prepare("INSERT INTO cells (id, warehouse_id, user_id, name) VALUES (?, ?, ?, ?)"),
  deleteCell: db.prepare("DELETE FROM cells WHERE id = ? AND user_id = ?"),
  getCell: db.prepare("SELECT * FROM cells WHERE id = ? AND user_id = ?"),
  renameCell: db.prepare("UPDATE cells SET name = ? WHERE id = ? AND user_id = ?"),

  getScans: db.prepare("SELECT * FROM scans WHERE cell_id = ? AND user_id = ? ORDER BY scanned_at DESC"),
  addScan: db.prepare("INSERT INTO scans (cell_id, user_id, barcode, article, ki, scanned_at) VALUES (?, ?, ?, ?, ?, ?)"),
  deleteScansByBarcode: db.prepare("DELETE FROM scans WHERE cell_id = ? AND user_id = ? AND barcode = ?"),
  deleteLastScan: db.prepare("DELETE FROM scans WHERE id = (SELECT id FROM scans WHERE cell_id = ? AND user_id = ? AND barcode = ? ORDER BY scanned_at DESC LIMIT 1)"),
  deleteScanById: db.prepare("DELETE FROM scans WHERE id = ? AND user_id = ?"),
  findScanByKI: db.prepare("SELECT s.id, s.ki, s.barcode, s.cell_id FROM scans s WHERE s.user_id = ? AND s.ki = ? AND s.ki != '' LIMIT 1"),

  findKI: db.prepare("SELECT s.id, c.name as cell_name, w.name as wh_name FROM scans s JOIN cells c ON s.cell_id = c.id JOIN warehouses w ON c.warehouse_id = w.id WHERE s.user_id = ? AND s.ki = ? AND s.ki != '' LIMIT 1"),

  // Pickup: find one scan by barcode in specific cell (prefer non-KI first)
  findScanForPickup: db.prepare("SELECT id, barcode, ki FROM scans WHERE cell_id = ? AND user_id = ? AND barcode = ? ORDER BY CASE WHEN ki = '' THEN 0 ELSE 1 END, scanned_at ASC LIMIT 1"),
  // Pickup by KI: find exact KI scan
  findScanByKIExact: db.prepare("SELECT id, barcode, ki, cell_id FROM scans WHERE user_id = ? AND ki = ? AND ki != '' LIMIT 1"),

  getArticles: db.prepare("SELECT * FROM articles WHERE user_id = ?"),
  upsertArticle: db.prepare("INSERT INTO articles (user_id, barcode, article) VALUES (?, ?, ?) ON CONFLICT(user_id, barcode) DO UPDATE SET article = excluded.article"),
  getArticle: db.prepare("SELECT article FROM articles WHERE user_id = ? AND barcode = ?"),
  getArticleByName: db.prepare("SELECT barcode, article FROM articles WHERE user_id = ? AND article = ?"),
  searchArticles: db.prepare("SELECT * FROM articles WHERE user_id = ? AND (article LIKE ? OR barcode LIKE ?) COLLATE NOCASE LIMIT 50"),
  deleteArticles: db.prepare("DELETE FROM articles WHERE user_id = ?"),

  getSettings: db.prepare("SELECT * FROM settings WHERE user_id = ?"),
  upsertSettings: db.prepare("INSERT INTO settings (user_id, barcode_format, scan_delay, scan_confirmations) VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET barcode_format=excluded.barcode_format, scan_delay=excluded.scan_delay, scan_confirmations=excluded.scan_confirmations"),

  // History: global (all scans for user, last 200)
  historyGlobal: db.prepare(`
    SELECT s.id, s.barcode, s.article, s.ki, s.scanned_at, c.name as cell_name, w.name as wh_name,
      COALESCE(a.article, s.article, '') as resolved_article, s.cell_id
    FROM scans s
    JOIN cells c ON s.cell_id = c.id
    JOIN warehouses w ON c.warehouse_id = w.id
    LEFT JOIN articles a ON a.user_id = s.user_id AND a.barcode = s.barcode
    WHERE s.user_id = ?
    ORDER BY s.scanned_at DESC LIMIT 200
  `),
  // History: per-cell
  historyCell: db.prepare(`
    SELECT s.id, s.barcode, s.article, s.ki, s.scanned_at, c.name as cell_name, w.name as wh_name,
      COALESCE(a.article, s.article, '') as resolved_article, s.cell_id
    FROM scans s
    JOIN cells c ON s.cell_id = c.id
    JOIN warehouses w ON c.warehouse_id = w.id
    LEFT JOIN articles a ON a.user_id = s.user_id AND a.barcode = s.barcode
    WHERE s.user_id = ? AND s.cell_id = ?
    ORDER BY s.scanned_at DESC LIMIT 200
  `),
  // Clear history (delete scans without affecting items — just remove from cell)
  clearHistory: db.prepare("DELETE FROM scans WHERE user_id = ? AND scanned_at < datetime('now')"),
  clearCellHistory: db.prepare("DELETE FROM scans WHERE user_id = ? AND cell_id = ?"),

  exportAll: db.prepare(`
    SELECT COALESCE(a.article, s.article, '') as article, s.barcode, s.ki,
      w.name as warehouse, c.name as cell, s.scanned_at
    FROM scans s JOIN cells c ON s.cell_id = c.id JOIN warehouses w ON c.warehouse_id = w.id
    LEFT JOIN articles a ON a.user_id = s.user_id AND a.barcode = s.barcode
    WHERE s.user_id = ? ORDER BY s.scanned_at DESC
  `),

  // Export only KIs (just the ki values)
  exportKIs: db.prepare(`
    SELECT s.ki FROM scans s
    WHERE s.user_id = ? AND s.ki != '' AND s.ki IS NOT NULL
    ORDER BY s.scanned_at DESC
  `),

  // Export barcode quantities — exclude KI scans (for LinenMark)
  exportBarcodeQty: db.prepare(`
    SELECT s.barcode, COUNT(*) as qty
    FROM scans s WHERE s.user_id = ? AND (s.ki = '' OR s.ki IS NULL)
    GROUP BY s.barcode ORDER BY s.barcode
  `),

  searchLocations: db.prepare(`
    SELECT a.article, s.barcode, w.id as wh_id, w.name as wh_name,
      c.id as cell_id, c.name as cell_name, COUNT(*) as qty,
      SUM(CASE WHEN s.ki != '' THEN 1 ELSE 0 END) as ki_count
    FROM scans s JOIN cells c ON s.cell_id = c.id JOIN warehouses w ON c.warehouse_id = w.id
    LEFT JOIN articles a ON a.user_id = s.user_id AND a.barcode = s.barcode
    WHERE s.user_id = ? AND (a.article LIKE ? COLLATE NOCASE OR s.barcode LIKE ? COLLATE NOCASE OR s.article LIKE ? COLLATE NOCASE)
    GROUP BY s.barcode, c.id ORDER BY a.article, w.name, c.name LIMIT 100
  `),
  searchLocationsWh: db.prepare(`
    SELECT a.article, s.barcode, w.id as wh_id, w.name as wh_name,
      c.id as cell_id, c.name as cell_name, COUNT(*) as qty,
      SUM(CASE WHEN s.ki != '' THEN 1 ELSE 0 END) as ki_count
    FROM scans s JOIN cells c ON s.cell_id = c.id JOIN warehouses w ON c.warehouse_id = w.id
    LEFT JOIN articles a ON a.user_id = s.user_id AND a.barcode = s.barcode
    WHERE s.user_id = ? AND w.id = ? AND (a.article LIKE ? COLLATE NOCASE OR s.barcode LIKE ? COLLATE NOCASE OR s.article LIKE ? COLLATE NOCASE)
    GROUP BY s.barcode, c.id ORDER BY a.article, w.name, c.name LIMIT 100
  `),

  deleteAllData: db.prepare("DELETE FROM warehouses WHERE user_id = ?"),

  // User files
  saveFile: db.prepare("INSERT INTO user_files (user_id, file_type, filename, data) VALUES (?, ?, ?, ?)"),
  getFile: db.prepare("SELECT * FROM user_files WHERE user_id = ? AND file_type = ? ORDER BY uploaded_at DESC LIMIT 1"),
  deleteFiles: db.prepare("DELETE FROM user_files WHERE user_id = ? AND file_type = ?"),
};

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return res.status(401).json({ error: "Необходима авторизация" });
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = payload.id;
    req.username = payload.username;
    next();
  } catch { res.status(401).json({ error: "Токен истёк" }); }
}

function uid() { return Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4); }

// Auto-backup logic
function maybeBackup(userId) {
  if (!scanCounters[userId]) scanCounters[userId] = 0;
  scanCounters[userId]++;
  if (scanCounters[userId] >= 10) {
    scanCounters[userId] = 0;
    try {
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      const dest = path.join(BACKUP_DIR, `backup_${userId}_${ts}.db`);
      db.backup(dest).then(() => {
        // Clean old backups (older than 7 days)
        const cutoff = Date.now() - 7 * 24 * 3600 * 1000;
        const files = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith(`backup_${userId}_`));
        for (const f of files) {
          const fp = path.join(BACKUP_DIR, f);
          const stat = fs.statSync(fp);
          if (stat.mtimeMs < cutoff) fs.unlinkSync(fp);
        }
      }).catch(() => {});
    } catch (e) { console.error("Backup error:", e.message); }
  }
}

// ═══ AUTH ═══
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

app.get("/api/me", auth, (req, res) => res.json({ username: req.username }));

// ═══ WAREHOUSES ═══
app.get("/api/warehouses", auth, (req, res) => {
  const warehouses = stmts.getWarehouses.all(req.userId);
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

app.put("/api/warehouses/:id", auth, (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Укажите название" });
  stmts.renameWarehouse.run(name.trim(), req.params.id, req.userId);
  res.json({ ok: true, name: name.trim() });
});

app.delete("/api/warehouses/:id", auth, (req, res) => {
  stmts.deleteWarehouse.run(req.params.id, req.userId);
  res.json({ ok: true });
});

// ═══ CELLS ═══
app.get("/api/warehouses/:whId/cells", auth, (req, res) => {
  const cells = stmts.getCells.all(req.params.whId, req.userId);
  const result = cells.map(c => {
    const scans = stmts.getScans.all(c.id, req.userId);
    const items = {}; let kiTotal = 0;
    scans.forEach(s => {
      if (!items[s.barcode]) items[s.barcode] = { barcode: s.barcode, qty: 0 };
      items[s.barcode].qty++;
      if (s.ki) kiTotal++;
    });
    return { ...c, itemCount: Object.keys(items).length, scanCount: scans.length, kiCount: kiTotal };
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

app.post("/api/warehouses/:whId/cells/import", auth, (req, res) => {
  const { names } = req.body;
  if (!Array.isArray(names) || !names.length) return res.status(400).json({ error: "Пустой список" });
  const createMany = db.transaction((list) => {
    let count = 0;
    for (const nm of list) { if (nm?.trim()) { stmts.createCell.run(uid(), req.params.whId, req.userId, nm.trim()); count++; } }
    return count;
  });
  res.json({ ok: true, count: createMany(names) });
});

app.put("/api/cells/:id", auth, (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Укажите название" });
  stmts.renameCell.run(name.trim(), req.params.id, req.userId);
  res.json({ ok: true, name: name.trim() });
});

app.delete("/api/cells/:id", auth, (req, res) => {
  stmts.deleteCell.run(req.params.id, req.userId);
  res.json({ ok: true });
});

// ═══ SCANS ═══
app.get("/api/cells/:cellId/items", auth, (req, res) => {
  const scans = stmts.getScans.all(req.params.cellId, req.userId);
  const items = {};
  scans.forEach(s => {
    if (!items[s.barcode]) {
      const art = stmts.getArticle.get(req.userId, s.barcode);
      items[s.barcode] = { barcode: s.barcode, article: art?.article || s.article || "", qty: 0, kiCount: 0, kis: [], scans: [] };
    }
    items[s.barcode].qty++;
    if (s.ki) { items[s.barcode].kiCount++; items[s.barcode].kis.push(s.ki); }
    items[s.barcode].scans.push(s.scanned_at);
  });
  res.json(Object.values(items));
});

app.post("/api/cells/:cellId/scan", auth, (req, res) => {
  const { barcode, article: manualArticle, ki } = req.body;
  if (!barcode?.trim() && !manualArticle?.trim()) return res.status(400).json({ error: "Пустой ввод" });
  const cell = stmts.getCell.get(req.params.cellId, req.userId);
  if (!cell) return res.status(404).json({ error: "Ячейка не найдена" });

  const kiVal = ki ? ki.replace(/[\r\n]/g, "").trim() : "";
  if (kiVal) {
    const existing = stmts.findKI.get(req.userId, kiVal);
    if (existing) {
      return res.status(409).json({ error: "Дубликат КИ: " + existing.wh_name + " / " + existing.cell_name });
    }
  }

  const bc = barcode?.trim() || "";
  const art = bc ? stmts.getArticle.get(req.userId, bc) : null;
  const articleVal = manualArticle?.trim() || art?.article || "";
  stmts.addScan.run(req.params.cellId, req.userId, bc, articleVal, kiVal, new Date().toISOString());
  maybeBackup(req.userId);
  res.json({ ok: true, article: articleVal });
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
    stmts.addScan.run(req.params.cellId, req.userId, barcode, art?.article || "", "", new Date().toISOString());
  } else if (delta < 0) {
    stmts.deleteLastScan.run(req.params.cellId, req.userId, barcode);
  }
  res.json({ ok: true });
});

// Delete specific scan by ID (for history undo)
app.delete("/api/scans/:id", auth, (req, res) => {
  stmts.deleteScanById.run(req.params.id, req.userId);
  res.json({ ok: true });
});

// ═══ PICKUP (забор из ячейки) ═══
app.post("/api/pickup", auth, (req, res) => {
  const { cellId, barcode, ki } = req.body;
  if (!cellId) return res.status(400).json({ error: "Не указана ячейка" });

  // If KI provided — find and remove exact KI scan
  if (ki) {
    const clean = ki.replace(/[\r\n]/g, "").trim();
    const parsed = ki.trim();
    const scan = stmts.findScanByKIExact.get(req.userId, parsed);
    if (!scan) {
      // Try with raw value too
      const scan2 = stmts.findScanByKIExact.get(req.userId, clean);
      if (!scan2) return res.status(404).json({ error: "КИ не найден в базе" });
      if (scan2.cell_id !== cellId) return res.status(400).json({ error: "КИ находится в другой ячейке" });
      stmts.deleteScanById.run(scan2.id, req.userId);
      return res.json({ ok: true, removed: "ki", barcode: scan2.barcode });
    }
    if (scan.cell_id !== cellId) return res.status(400).json({ error: "КИ находится в другой ячейке" });
    stmts.deleteScanById.run(scan.id, req.userId);
    return res.json({ ok: true, removed: "ki", barcode: scan.barcode });
  }

  // Barcode — find one scan for this barcode in this cell and remove it
  if (barcode) {
    const scan = stmts.findScanForPickup.get(cellId, req.userId, barcode.trim());
    if (!scan) return res.status(404).json({ error: "Баркод не найден в этой ячейке" });
    stmts.deleteScanById.run(scan.id, req.userId);
    return res.json({ ok: true, removed: "barcode", barcode: scan.barcode });
  }

  return res.status(400).json({ error: "Укажите баркод или КИ" });
});

// ═══ HISTORY ═══
app.get("/api/history", auth, (req, res) => {
  const cellId = req.query.cell;
  if (cellId) {
    res.json(stmts.historyCell.all(req.userId, cellId));
  } else {
    res.json(stmts.historyGlobal.all(req.userId));
  }
});

// Delete single history item (without removing from cell — just hide)
app.delete("/api/history/item/:id", auth, (req, res) => {
  // Soft-hide: we just remove from history display by setting a flag
  // For simplicity, we delete the scan but this is "history only" mode
  // Actually, to truly separate: we need to NOT delete the scan.
  // Since history IS scans, "hide from history" = do nothing visible.
  // The frontend just removes it from the displayed list.
  res.json({ ok: true });
});

app.delete("/api/history", auth, (req, res) => {
  const cellId = req.query.cell;
  const mode = req.query.mode; // "undo" = delete actual scans
  if (mode === "undo") {
    // Actually delete scans from cells
    if (cellId) {
      stmts.clearCellHistory.run(req.userId, cellId);
    } else {
      stmts.clearHistory.run(req.userId);
    }
  }
  // Without mode=undo, just acknowledge (history view cleared on frontend)
  res.json({ ok: true });
});

// ═══ ARTICLES ═══
app.get("/api/articles", auth, (req, res) => res.json(stmts.getArticles.all(req.userId)));

app.get("/api/articles/search", auth, (req, res) => {
  const q = req.query.q?.trim();
  if (!q) return res.json([]);
  const pattern = "%" + q + "%";
  res.json(stmts.searchArticles.all(req.userId, pattern, pattern));
});

app.get("/api/articles/lookup", auth, (req, res) => {
  const article = req.query.article?.trim();
  if (!article) return res.json({ found: false });
  const row = stmts.getArticleByName.get(req.userId, article);
  if (row) return res.json({ found: true, barcode: row.barcode, article: row.article });
  return res.json({ found: false });
});

app.post("/api/articles/upload", auth, (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items)) return res.status(400).json({ error: "Неверный формат" });
  const upsert = db.transaction((list) => {
    for (const { barcode, article } of list) {
      if (barcode?.trim() && article?.trim()) stmts.upsertArticle.run(req.userId, barcode.trim(), article.trim());
    }
  });
  upsert(items);
  res.json({ ok: true, count: items.length });
});

app.delete("/api/articles", auth, (req, res) => { stmts.deleteArticles.run(req.userId); res.json({ ok: true }); });

// ═══ SEARCH ═══
app.get("/api/search/locations", auth, (req, res) => {
  const q = req.query.q?.trim(); const whId = req.query.wh?.trim();
  if (!q) return res.json([]);
  const pattern = q + "%";
  if (whId) res.json(stmts.searchLocationsWh.all(req.userId, whId, pattern, pattern, pattern));
  else res.json(stmts.searchLocations.all(req.userId, pattern, pattern, pattern));
});

// ═══ SETTINGS ═══
app.get("/api/settings", auth, (req, res) => {
  const s = stmts.getSettings.get(req.userId);
  res.json(s || { barcode_format: "all", scan_delay: 300, scan_confirmations: 3 });
});

app.put("/api/settings", auth, (req, res) => {
  const { barcode_format, scan_delay, scan_confirmations } = req.body;
  stmts.upsertSettings.run(req.userId, barcode_format || "all", scan_delay != null ? Number(scan_delay) : 300, scan_confirmations != null ? Number(scan_confirmations) : 3);
  res.json({ ok: true });
});

// ═══ EXPORT ═══
app.get("/api/export", auth, (req, res) => res.json(stmts.exportAll.all(req.userId)));
app.get("/api/export/kis", auth, (req, res) => res.json(stmts.exportKIs.all(req.userId)));
app.get("/api/export/barcode-qty", auth, (req, res) => res.json(stmts.exportBarcodeQty.all(req.userId)));

// ═══ USER FILES (label CSV, linenmark XLSX) ═══
app.post("/api/files/:type", auth, (req, res) => {
  const { filename, data } = req.body; // data is base64
  if (!data) return res.status(400).json({ error: "Нет данных" });
  stmts.deleteFiles.run(req.userId, req.params.type);
  stmts.saveFile.run(req.userId, req.params.type, filename || "file", Buffer.from(data, "base64"));
  res.json({ ok: true });
});

app.get("/api/files/:type", auth, (req, res) => {
  const f = stmts.getFile.get(req.userId, req.params.type);
  if (!f) return res.status(404).json({ error: "Файл не найден" });
  res.json({ filename: f.filename, data: f.data.toString("base64"), uploaded_at: f.uploaded_at });
});

// ═══ BACKUPS ═══
app.get("/api/backups", auth, (req, res) => {
  try {
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith(`backup_${req.userId}_`) && f.endsWith(".db"))
      .map(f => {
        const stat = fs.statSync(path.join(BACKUP_DIR, f));
        return { name: f, size: stat.size, created: stat.mtime.toISOString() };
      })
      .sort((a, b) => b.created.localeCompare(a.created));
    res.json(files);
  } catch { res.json([]); }
});

app.post("/api/backups/restore/:name", auth, (req, res) => {
  const backupPath = path.join(BACKUP_DIR, req.params.name);
  if (!fs.existsSync(backupPath)) return res.status(404).json({ error: "Бэкап не найден" });
  try {
    // Copy backup over current DB (requires restart ideally, but for SQLite we can re-import)
    const backupDb = new Database(backupPath, { readonly: true });
    // Get all scans for this user from backup
    const scans = backupDb.prepare("SELECT * FROM scans WHERE user_id = ?").all(req.userId);
    const articles = backupDb.prepare("SELECT * FROM articles WHERE user_id = ?").all(req.userId);
    const warehouses = backupDb.prepare("SELECT * FROM warehouses WHERE user_id = ?").all(req.userId);
    const cells = backupDb.prepare("SELECT * FROM cells WHERE user_id = ?").all(req.userId);
    backupDb.close();

    // Clear current data and restore
    const restore = db.transaction(() => {
      stmts.deleteAllData.run(req.userId);
      stmts.deleteArticles.run(req.userId);
      for (const w of warehouses) {
        try { db.prepare("INSERT INTO warehouses (id, user_id, name, created_at) VALUES (?, ?, ?, ?)").run(w.id, w.user_id, w.name, w.created_at); } catch {}
      }
      for (const c of cells) {
        try { db.prepare("INSERT INTO cells (id, warehouse_id, user_id, name, created_at) VALUES (?, ?, ?, ?, ?)").run(c.id, c.warehouse_id, c.user_id, c.name, c.created_at); } catch {}
      }
      for (const s of scans) {
        try { db.prepare("INSERT INTO scans (cell_id, user_id, barcode, article, ki, scanned_at) VALUES (?, ?, ?, ?, ?, ?)").run(s.cell_id, s.user_id, s.barcode, s.article, s.ki || "", s.scanned_at); } catch {}
      }
      for (const a of articles) {
        try { stmts.upsertArticle.run(a.user_id, a.barcode, a.article); } catch {}
      }
    });
    restore();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Ошибка восстановления: " + e.message });
  }
});

// ═══ RESET ═══
app.delete("/api/data", auth, (req, res) => {
  stmts.deleteAllData.run(req.userId);
  stmts.deleteArticles.run(req.userId);
  res.json({ ok: true });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ═══ Start ═══
const https = require("https");
const { execSync } = require("child_process");
const keyPath = path.join(__dirname, "key.pem");
const certPath = path.join(__dirname, "cert.pem");

if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  try { execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 365 -nodes -subj "/CN=scanstock"`, { stdio: "ignore" }); } catch (e) {}
}

app.listen(PORT, "0.0.0.0", () => { console.log(`\n  ✅ ScanStock: http://localhost:${PORT}`); });

if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
  const HP = Number(PORT) + 443;
  try { https.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }, app).listen(HP, "0.0.0.0", () => { console.log(`  🔒 https://localhost:${HP}\n`); }); } catch (e) {}
}