'use strict';

const express  = require('express');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app        = express();
const PORT       = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dainichi-docserver-change-this-in-production-2026';
const UPLOADS    = path.join(__dirname, 'uploads');
const DATA_DIR   = path.join(__dirname, 'data');

[UPLOADS, DATA_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// ─── DB ─────────────────────────────────────────────────
const db = new Database(path.join(DATA_DIR, 'documents.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS companies (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    code       TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id    INTEGER NOT NULL REFERENCES companies(id),
    name          TEXT NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'uploader'
                  CHECK(role IN ('admin','approver','uploader')),
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT DEFAULT (datetime('now','localtime')),
    last_login    TEXT
  );

  CREATE TABLE IF NOT EXISTS documents (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id       INTEGER NOT NULL REFERENCES companies(id),
    document_type    TEXT NOT NULL
                     CHECK(document_type IN ('invoice','receipt','other')),
    document_date    TEXT NOT NULL,
    amount           INTEGER,
    counterparty     TEXT NOT NULL,
    description      TEXT,
    filename         TEXT NOT NULL,
    original_name    TEXT NOT NULL,
    file_path        TEXT NOT NULL,
    file_hash        TEXT NOT NULL,
    file_size        INTEGER NOT NULL,
    mime_type        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK(status IN ('pending','approved','rejected')),
    uploaded_by      INTEGER NOT NULL REFERENCES users(id),
    uploaded_at      TEXT DEFAULT (datetime('now','localtime')),
    approved_by      INTEGER REFERENCES users(id),
    approved_at      TEXT,
    rejection_reason TEXT
  );

  CREATE TABLE IF NOT EXISTS approvals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    user_id     INTEGER NOT NULL REFERENCES users(id),
    action      TEXT NOT NULL,
    comment     TEXT,
    timestamp   TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id),
    action      TEXT NOT NULL,
    document_id INTEGER REFERENCES documents(id),
    details     TEXT,
    ip_address  TEXT,
    timestamp   TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE INDEX IF NOT EXISTS idx_doc_date         ON documents(document_date);
  CREATE INDEX IF NOT EXISTS idx_doc_counterparty ON documents(counterparty);
  CREATE INDEX IF NOT EXISTS idx_doc_company      ON documents(company_id);
  CREATE INDEX IF NOT EXISTS idx_doc_status       ON documents(status);
`);

// 初期管理者アカウント作成
{
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@dainichi.co.jp');
  if (!exists) {
    let co = db.prepare('SELECT id FROM companies WHERE code = ?').get('DAINICHI');
    if (!co) {
      const r = db.prepare('INSERT INTO companies (name, code) VALUES (?, ?)').run('大日産業', 'DAINICHI');
      co = { id: r.lastInsertRowid };
    }
    db.prepare('INSERT INTO users (company_id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)').run(
      co.id, 'システム管理者', 'admin@dainichi.co.jp', bcrypt.hashSync('admin1234', 10), 'admin'
    );
  }
}

// ─── MULTER ─────────────────────────────────────────────
const storage = multer.diskStorage({
  destination(req, file, cb) {
    const now  = new Date();
    const year = now.getFullYear();
    const mon  = String(now.getMonth() + 1).padStart(2, '0');
    const cid  = req.user ? req.user.company_id : 1;
    const dir  = path.join(UPLOADS, String(cid), String(year), mon);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ok = ['application/pdf','image/jpeg','image/png','image/tiff','image/webp'];
    cb(ok.includes(file.mimetype) ? null : new Error('PDF・JPEG・PNG・TIFF・WEBPのみ対応'), true);
  }
});

// ─── MIDDLEWARE ─────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const auth = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '認証が必要です' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: '認証トークンが無効です' }); }
};

const role = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: '権限がありません' });

const audit = (uid, action, docId, details, ip) => {
  try {
    db.prepare('INSERT INTO audit_log (user_id,action,document_id,details,ip_address) VALUES(?,?,?,?,?)').run(
      uid, action, docId ?? null, details ? JSON.stringify(details) : null, ip ?? null
    );
  } catch {}
};

const sha256 = fp => crypto.createHash('sha256').update(fs.readFileSync(fp)).digest('hex');

// ─── AUTH ────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body ?? {};
  const u = db.prepare(`
    SELECT u.*, c.name as company_name FROM users u
    JOIN companies c ON u.company_id = c.id
    WHERE u.email = ? AND u.is_active = 1
  `).get(email);

  if (!u || !bcrypt.compareSync(password ?? '', u.password_hash))
    return res.status(401).json({ error: 'メールアドレスまたはパスワードが正しくありません' });

  db.prepare("UPDATE users SET last_login = datetime('now','localtime') WHERE id = ?").run(u.id);
  audit(u.id, 'LOGIN', null, null, req.ip);

  const payload = { id: u.id, name: u.name, email: u.email, role: u.role, company_id: u.company_id, company_name: u.company_name };
  res.json({ token: jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' }), user: payload });
});

app.post('/api/auth/change-password', auth, (req, res) => {
  const { current, next: next_pw } = req.body ?? {};
  const u = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(current ?? '', u.password_hash))
    return res.status(400).json({ error: '現在のパスワードが正しくありません' });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(next_pw, 10), req.user.id);
  audit(req.user.id, 'CHANGE_PASSWORD', null, null, req.ip);
  res.json({ success: true });
});

// ─── COMPANIES ──────────────────────────────────────────
app.get('/api/companies', auth, (req, res) => {
  const rows = req.user.role === 'admin'
    ? db.prepare('SELECT * FROM companies ORDER BY name').all()
    : db.prepare('SELECT * FROM companies WHERE id = ?').all(req.user.company_id);
  res.json(rows);
});

app.post('/api/companies', auth, role('admin'), (req, res) => {
  const { name, code } = req.body ?? {};
  if (!name || !code) return res.status(400).json({ error: '会社名とコードは必須です' });
  try {
    const r = db.prepare('INSERT INTO companies (name, code) VALUES (?, ?)').run(name, code.toUpperCase());
    audit(req.user.id, 'CREATE_COMPANY', null, { name, code }, req.ip);
    res.json({ id: r.lastInsertRowid, name, code: code.toUpperCase() });
  } catch { res.status(400).json({ error: '会社コードが重複しています' }); }
});

// ─── USERS ──────────────────────────────────────────────
app.get('/api/users', auth, role('admin'), (req, res) => {
  res.json(db.prepare(`
    SELECT u.id, u.name, u.email, u.role, u.is_active, u.created_at, u.last_login,
           c.name as company_name, u.company_id
    FROM users u JOIN companies c ON u.company_id = c.id ORDER BY c.name, u.name
  `).all());
});

app.post('/api/users', auth, role('admin'), (req, res) => {
  const { name, email, password, role: r, company_id } = req.body ?? {};
  if (!name || !email || !password || !r || !company_id)
    return res.status(400).json({ error: '全項目を入力してください' });
  try {
    const result = db.prepare(
      'INSERT INTO users (name, email, password_hash, role, company_id) VALUES (?, ?, ?, ?, ?)'
    ).run(name, email, bcrypt.hashSync(password, 10), r, company_id);
    audit(req.user.id, 'CREATE_USER', null, { name, email, role: r }, req.ip);
    res.json({ id: result.lastInsertRowid });
  } catch { res.status(400).json({ error: 'メールアドレスが重複しています' }); }
});

app.put('/api/users/:id', auth, role('admin'), (req, res) => {
  const { name, role: r, is_active, password } = req.body ?? {};
  const id = req.params.id;
  if (name)                          db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, id);
  if (r)                             db.prepare('UPDATE users SET role = ? WHERE id = ?').run(r, id);
  if (typeof is_active === 'number') db.prepare('UPDATE users SET is_active = ? WHERE id = ?').run(is_active, id);
  if (password)                      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), id);
  audit(req.user.id, 'UPDATE_USER', null, { target_id: id }, req.ip);
  res.json({ success: true });
});

// ─── DOCUMENTS ──────────────────────────────────────────
app.get('/api/documents', auth, (req, res) => {
  const {
    date_from, date_to, amount_min, amount_max,
    counterparty, document_type, status, company_id,
    keyword, page = 1, limit = 50
  } = req.query;

  const conds = [], params = [];
  if (req.user.role !== 'admin') { conds.push('d.company_id = ?'); params.push(req.user.company_id); }
  else if (company_id)           { conds.push('d.company_id = ?'); params.push(+company_id); }

  if (date_from)      { conds.push('d.document_date >= ?'); params.push(date_from); }
  if (date_to)        { conds.push('d.document_date <= ?'); params.push(date_to); }
  if (amount_min)     { conds.push('d.amount >= ?');        params.push(+amount_min); }
  if (amount_max)     { conds.push('d.amount <= ?');        params.push(+amount_max); }
  if (counterparty)   { conds.push('d.counterparty LIKE ?'); params.push(`%${counterparty}%`); }
  if (document_type)  { conds.push('d.document_type = ?');  params.push(document_type); }
  if (status)         { conds.push('d.status = ?');         params.push(status); }
  if (keyword)        {
    conds.push('(d.counterparty LIKE ? OR d.description LIKE ? OR d.original_name LIKE ?)');
    params.push(`%${keyword}%`, `%${keyword}%`, `%${keyword}%`);
  }

  const where  = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const offset = (+page - 1) * +limit;
  const total  = db.prepare(`SELECT COUNT(*) as n FROM documents d ${where}`).get(...params).n;
  const docs   = db.prepare(`
    SELECT d.id, d.document_type, d.document_date, d.amount, d.counterparty,
           d.description, d.original_name, d.file_size, d.mime_type,
           d.status, d.uploaded_at, d.approved_at, d.rejection_reason,
           u1.name as uploader_name, u2.name as approver_name, c.name as company_name
    FROM documents d
    LEFT JOIN users u1 ON d.uploaded_by = u1.id
    LEFT JOIN users u2 ON d.approved_by = u2.id
    LEFT JOIN companies c ON d.company_id = c.id
    ${where} ORDER BY d.document_date DESC, d.id DESC LIMIT ? OFFSET ?
  `).all(...params, +limit, offset);

  res.json({ documents: docs, total, page: +page, limit: +limit });
});

app.post('/api/documents', auth, (req, res) => {
  upload.single('file')(req, res, err => {
    if (err)      return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'ファイルを選択してください' });

    const { document_type, document_date, amount, counterparty, description, company_id } = req.body;
    if (!document_type || !document_date || !counterparty) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: '書類種別・取引日・取引先は必須です' });
    }

    const cid     = req.user.role === 'admin' && company_id ? +company_id : req.user.company_id;
    const hash    = sha256(req.file.path);
    const relPath = path.relative(UPLOADS, req.file.path);
    const dup     = db.prepare('SELECT id, original_name FROM documents WHERE file_hash = ? AND company_id = ?').get(hash, cid);
    const amt     = amount ? +String(amount).replace(/,/g, '') : null;

    const r = db.prepare(`
      INSERT INTO documents
        (company_id, document_type, document_date, amount, counterparty, description,
         filename, original_name, file_path, file_hash, file_size, mime_type, uploaded_by)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(cid, document_type, document_date, amt, counterparty, description || null,
           req.file.filename, req.file.originalname, relPath,
           hash, req.file.size, req.file.mimetype, req.user.id);

    const docId = r.lastInsertRowid;
    db.prepare('INSERT INTO approvals (document_id, user_id, action) VALUES (?,?,?)').run(docId, req.user.id, 'submitted');
    audit(req.user.id, 'UPLOAD', docId, { filename: req.file.originalname, counterparty, amount: amt }, req.ip);

    res.json({ id: docId, duplicate: dup ? { id: dup.id, name: dup.original_name } : null });
  });
});

app.get('/api/documents/:id', auth, (req, res) => {
  const doc = db.prepare(`
    SELECT d.*, u1.name as uploader_name, u2.name as approver_name, c.name as company_name
    FROM documents d
    LEFT JOIN users u1 ON d.uploaded_by = u1.id
    LEFT JOIN users u2 ON d.approved_by = u2.id
    LEFT JOIN companies c ON d.company_id = c.id
    WHERE d.id = ?
  `).get(req.params.id);

  if (!doc) return res.status(404).json({ error: '文書が見つかりません' });
  if (req.user.role !== 'admin' && doc.company_id !== req.user.company_id)
    return res.status(403).json({ error: 'アクセス権限がありません' });

  const history = db.prepare(`
    SELECT a.*, u.name as user_name FROM approvals a
    LEFT JOIN users u ON a.user_id = u.id
    WHERE a.document_id = ? ORDER BY a.timestamp
  `).all(req.params.id);

  audit(req.user.id, 'VIEW', doc.id, null, req.ip);
  res.json({ ...doc, history });
});

app.get('/api/documents/:id/file', auth, (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return res.status(404).json({ error: '文書が見つかりません' });
  if (req.user.role !== 'admin' && doc.company_id !== req.user.company_id)
    return res.status(403).json({ error: 'アクセス権限がありません' });

  const filePath = path.resolve(path.join(UPLOADS, doc.file_path));
  if (!filePath.startsWith(UPLOADS)) return res.status(400).json({ error: '不正なパスです' });
  if (!fs.existsSync(filePath))      return res.status(404).json({ error: 'ファイルが見つかりません' });

  const currentHash = sha256(filePath);
  if (currentHash !== doc.file_hash) {
    audit(req.user.id, 'INTEGRITY_ERROR', doc.id, { expected: doc.file_hash, actual: currentHash }, req.ip);
    return res.status(500).json({ error: 'ファイルの整合性エラー。管理者に連絡してください。' });
  }

  audit(req.user.id, 'VIEW_FILE', doc.id, null, req.ip);
  res.setHeader('Content-Type', doc.mime_type);
  res.setHeader('Content-Disposition', `inline; filename*=UTF-8''${encodeURIComponent(doc.original_name)}`);
  res.sendFile(filePath);
});

app.post('/api/documents/:id/approve', auth, role('admin', 'approver'), (req, res) => {
  const { comment } = req.body ?? {};
  const doc = db.prepare('SELECT status, company_id FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return res.status(404).json({ error: '文書が見つかりません' });
  if (req.user.role !== 'admin' && doc.company_id !== req.user.company_id)
    return res.status(403).json({ error: 'アクセス権限がありません' });
  if (doc.status !== 'pending') return res.status(400).json({ error: '承認待ちの文書のみ操作できます' });

  db.prepare("UPDATE documents SET status='approved', approved_by=?, approved_at=datetime('now','localtime') WHERE id=?").run(req.user.id, req.params.id);
  db.prepare('INSERT INTO approvals (document_id, user_id, action, comment) VALUES (?,?,?,?)').run(+req.params.id, req.user.id, 'approved', comment || null);
  audit(req.user.id, 'APPROVE', +req.params.id, { comment }, req.ip);
  res.json({ success: true });
});

app.post('/api/documents/:id/reject', auth, role('admin', 'approver'), (req, res) => {
  const { reason } = req.body ?? {};
  if (!reason) return res.status(400).json({ error: '却下理由を入力してください' });
  const doc = db.prepare('SELECT status, company_id FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return res.status(404).json({ error: '文書が見つかりません' });
  if (req.user.role !== 'admin' && doc.company_id !== req.user.company_id)
    return res.status(403).json({ error: 'アクセス権限がありません' });

  db.prepare("UPDATE documents SET status='rejected', rejection_reason=? WHERE id=?").run(reason, req.params.id);
  db.prepare('INSERT INTO approvals (document_id, user_id, action, comment) VALUES (?,?,?,?)').run(+req.params.id, req.user.id, 'rejected', reason);
  audit(req.user.id, 'REJECT', +req.params.id, { reason }, req.ip);
  res.json({ success: true });
});

// ─── STATS ───────────────────────────────────────────────
app.get('/api/stats', auth, (req, res) => {
  const cid = req.user.role !== 'admin' ? req.user.company_id : null;
  const w   = cid ? `WHERE company_id = ${cid}` : '';
  const wa  = cid ? `WHERE company_id = ${cid} AND` : 'WHERE';
  res.json({
    total:      db.prepare(`SELECT COUNT(*) n FROM documents ${w}`).get().n,
    pending:    db.prepare(`SELECT COUNT(*) n FROM documents ${wa} status='pending'`).get().n,
    approved:   db.prepare(`SELECT COUNT(*) n FROM documents ${wa} status='approved'`).get().n,
    rejected:   db.prepare(`SELECT COUNT(*) n FROM documents ${wa} status='rejected'`).get().n,
    this_month: db.prepare(`SELECT COUNT(*) n FROM documents ${wa} document_date >= date('now','start of month')`).get().n,
    this_year:  db.prepare(`SELECT COUNT(*) n FROM documents ${wa} document_date >= date('now','start of year')`).get().n,
  });
});

// ─── CSV エクスポート ─────────────────────────────────────
app.get('/api/export', auth, (req, res) => {
  const { date_from, date_to, company_id } = req.query;
  const conds = req.user.role !== 'admin' ? [`d.company_id = ${req.user.company_id}`] : [];
  if (req.user.role === 'admin' && company_id) conds.push(`d.company_id = ${+company_id}`);
  if (date_from) conds.push(`d.document_date >= '${date_from}'`);
  if (date_to)   conds.push(`d.document_date <= '${date_to}'`);
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';

  const docs = db.prepare(`
    SELECT d.id, c.name as company_name,
      CASE d.document_type WHEN 'invoice' THEN '請求書' WHEN 'receipt' THEN '領収書' ELSE 'その他' END as type,
      d.document_date, d.amount, d.counterparty, d.description,
      CASE d.status WHEN 'approved' THEN '承認済' WHEN 'rejected' THEN '却下' ELSE '承認待ち' END as status,
      u1.name as uploader, d.uploaded_at, u2.name as approver, d.approved_at,
      d.original_name, d.file_size, d.file_hash
    FROM documents d
    LEFT JOIN users u1 ON d.uploaded_by = u1.id
    LEFT JOIN users u2 ON d.approved_by = u2.id
    LEFT JOIN companies c ON d.company_id = c.id
    ${where} ORDER BY d.document_date DESC
  `).all();

  audit(req.user.id, 'EXPORT_CSV', null, { count: docs.length }, req.ip);

  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const header = 'ID,会社名,書類種別,取引年月日,金額（円）,取引先,摘要,ステータス,登録者,登録日時,承認者,承認日時,ファイル名,ファイルサイズ,SHA256ハッシュ値';
  const rows = docs.map(d =>
    [d.id, esc(d.company_name), d.type, d.document_date, d.amount ?? '',
     esc(d.counterparty), esc(d.description), d.status,
     esc(d.uploader), d.uploaded_at, esc(d.approver), d.approved_at ?? '',
     esc(d.original_name), d.file_size, d.file_hash].join(',')
  );

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="documents_${new Date().toISOString().slice(0,10)}.csv"`);
  res.send('﻿' + header + '\n' + rows.join('\n'));
});

// ─── 監査ログ ─────────────────────────────────────────────
app.get('/api/audit-log', auth, role('admin'), (req, res) => {
  res.json(db.prepare(`
    SELECT a.*, u.name as user_name FROM audit_log a
    LEFT JOIN users u ON a.user_id = u.id
    ORDER BY a.timestamp DESC LIMIT 1000
  `).all());
});

// ─── START ────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  const line = '─'.repeat(52);
  console.log(`\n${line}`);
  console.log('  電子帳簿保存法対応 書類管理サーバー 起動完了');
  console.log(line);
  console.log(`  URL      : http://localhost:${PORT}`);
  console.log(`  初期ID   : admin@dainichi.co.jp`);
  console.log(`  初期PW   : admin1234`);
  console.log('  ※ 初回ログイン後すぐにパスワードを変更してください');
  console.log(`${line}\n`);
});
