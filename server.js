// TrustedMiners backend v2  |  Node 18+  |  SQLite (better-sqlite3)
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const scrypt = require('util').promisify(crypto.scrypt);

// Tiny .env loader (no extra dependency). Real environment variables win.
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => {
    const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch {}

const express = require('express');
const Database = require('better-sqlite3');
const QRCode = require('qrcode');

const CFG = {
  PORT: Number(process.env.PORT || 3000),
  BUY_RATE: Number(process.env.BUY_RATE || 102.5),     // INR per 1 USDT
  MIN_USDT: Number(process.env.MIN_USDT || 1),          // minimum buy, in USDT
  SELL_RATE: Number(process.env.SELL_RATE || 100),      // sell price shown on the site
  MIN_WITHDRAW: Number(process.env.MIN_WITHDRAW || 1),  // minimum withdrawal, in USDT
  MAX_INR: Number(process.env.MAX_INR || 10000),
  MAX_OPEN: Number(process.env.MAX_OPEN || 5),                                          // max orders one user can keep in the queue
  ADMIN_KEY: process.env.ADMIN_KEY || crypto.randomBytes(12).toString('hex'),
  SUPPORT: { email: process.env.SUPPORT_EMAIL || '', whatsapp: process.env.SUPPORT_WHATSAPP || '' },
  UPI_ID: /^[\w.\-]{2,}@[\w.\-]{2,}$/.test(process.env.UPI_ID || '') ? process.env.UPI_ID : '',   // your UPI ID (VPA)
  UPI_NAME: (process.env.UPI_NAME || 'TrustedMiners').slice(0, 40),
  // Deposit chains shown to users. Change the address with DEPOSIT_ADDRESS in .env
  CHAINS: [{ id: 'bsc', short: 'BSC', name: 'BNB Smart Chain (BEP20)',
    address: /^0x[a-fA-F0-9]{40}$/.test(process.env.DEPOSIT_ADDRESS || '') ? process.env.DEPOSIT_ADDRESS : '0xC0199Fa884867156F503Ddf2bF6d3C2cD2D03969' }],
};
CFG.MIN_INR = Math.ceil(CFG.MIN_USDT * CFG.BUY_RATE);   // 1 USDT at the buy price, rounded up to whole rupees

// ---------------- Database ----------------
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
const db = new Database(path.join(__dirname, 'data', 'trustedminers.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id),
  inr INTEGER NOT NULL CHECK(inr > 0),
  rate REAL NOT NULL,
  usdt_micro INTEGER NOT NULL CHECK(usdt_micro > 0),      -- USDT x 1,000,000 (no float money bugs)
  status TEXT NOT NULL DEFAULT 'processing' CHECK(status IN ('processing','completed','cancelled')),
  idem_key TEXT,
  gateway_ref TEXT,                                       -- for the payment gateway step
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(user_id, idem_key)
);
CREATE INDEX IF NOT EXISTS idx_orders_queue ON orders(status, id);
CREATE TABLE IF NOT EXISTS ledger(                        -- balance = SUM(ledger); one credit per order, ever
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  order_id INTEGER NOT NULL UNIQUE REFERENCES orders(id),
  usdt_micro INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5), text TEXT, created_at INTEGER NOT NULL
);`);
db.prepare("INSERT OR IGNORE INTO users(id,name,created_at) VALUES(1,'demo',?)").run(Date.now());
db.exec(`CREATE TABLE IF NOT EXISTS withdrawals(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id),
  usdt_micro INTEGER NOT NULL CHECK(usdt_micro > 0),
  chain TEXT NOT NULL,
  address TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed','rejected')),
  txid TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);`);
// Upgrade older databases: columns for the user's UPI payment proof (UTR)
const cols = db.prepare('PRAGMA table_info(orders)').all().map(c => c.name);
if (!cols.includes('utr')) db.exec('ALTER TABLE orders ADD COLUMN utr TEXT');
if (!cols.includes('submitted_at')) db.exec('ALTER TABLE orders ADD COLUMN submitted_at INTEGER');
if (!cols.includes('fail_reason')) db.exec('ALTER TABLE orders ADD COLUMN fail_reason TEXT');
const wcols = db.prepare('PRAGMA table_info(withdrawals)').all().map(c => c.name);
if (!wcols.includes('fail_reason')) db.exec('ALTER TABLE withdrawals ADD COLUMN fail_reason TEXT');
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_utr ON orders(utr)');   // one UTR can only be used once
// ---- Accounts and login sessions
const ucols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
if (!ucols.includes('email')) db.exec('ALTER TABLE users ADD COLUMN email TEXT');
if (!ucols.includes('password_hash')) db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT');
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)');
db.exec(`CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);`);
db.exec(`CREATE TABLE IF NOT EXISTS password_resets(          -- one-time codes the admin hands out
  user_id INTEGER PRIMARY KEY REFERENCES users(id), code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0
);`);

const q = {
  // available balance = credited orders - withdrawals that are pending or sent (rejected ones are refunded automatically)
  balance: db.prepare(`SELECT COALESCE((SELECT SUM(usdt_micro) FROM ledger WHERE user_id=?),0)
                            - COALESCE((SELECT SUM(usdt_micro) FROM withdrawals WHERE user_id=? AND status IN ('pending','completed')),0) AS b`),
  wInsert: db.prepare('INSERT INTO withdrawals(public_id,user_id,usdt_micro,chain,address,created_at,updated_at) VALUES(?,?,?,?,?,?,?)'),
  wByPid: db.prepare('SELECT * FROM withdrawals WHERE public_id=?'),
  wList: db.prepare('SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 50'),
  wPending: db.prepare("SELECT * FROM withdrawals WHERE status='pending' ORDER BY id"),
  wSet: db.prepare("UPDATE withdrawals SET status=?, txid=?, updated_at=? WHERE public_id=? AND status='pending'"),
  openCount: db.prepare("SELECT COUNT(*) AS c FROM orders WHERE user_id=? AND status='processing'"),
  byIdem: db.prepare('SELECT * FROM orders WHERE user_id=? AND idem_key=?'),
  byPid: db.prepare('SELECT * FROM orders WHERE public_id=?'),
  list: db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 50'),
  position: db.prepare("SELECT COUNT(*) AS c FROM orders WHERE status='processing' AND id<=?"),
  queue: db.prepare("SELECT * FROM orders WHERE status='processing' ORDER BY id"),
  insert: db.prepare('INSERT INTO orders(public_id,user_id,inr,rate,usdt_micro,idem_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)'),
  setStatus: db.prepare("UPDATE orders SET status=?, updated_at=? WHERE id=? AND status='processing'"),
  credit: db.prepare('INSERT INTO ledger(user_id,order_id,usdt_micro,created_at) VALUES(?,?,?,?)'),
  userByEmail: db.prepare('SELECT * FROM users WHERE email=?'),
  userEmail: db.prepare('SELECT email FROM users WHERE id=?'),
  addUser: db.prepare('INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)'),
  addSession: db.prepare('INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)'),
  getSession: db.prepare('SELECT u.id, u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?'),
  delSession: db.prepare('DELETE FROM sessions WHERE token_hash=?'),
  purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at<=?'),
  failOrder: db.prepare("UPDATE orders SET status='cancelled', fail_reason=?, updated_at=? WHERE id=? AND status='processing'"),
  wFail: db.prepare("UPDATE withdrawals SET status='rejected', fail_reason=?, updated_at=? WHERE public_id=? AND status='pending'"),
  setReset: db.prepare('INSERT INTO password_resets(user_id,code_hash,expires_at,tries) VALUES(?,?,?,0) ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash, expires_at=excluded.expires_at, tries=0'),
  getReset: db.prepare('SELECT * FROM password_resets WHERE user_id=?'),
  delReset: db.prepare('DELETE FROM password_resets WHERE user_id=?'),
  bumpReset: db.prepare('UPDATE password_resets SET tries=tries+1 WHERE user_id=?'),
  setPassword: db.prepare('UPDATE users SET password_hash=? WHERE id=?'),
  delUserSessions: db.prepare('DELETE FROM sessions WHERE user_id=?'),
  delOtherSessions: db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash!=?'),
  setUtr: db.prepare("UPDATE orders SET utr=?, submitted_at=? WHERE id=? AND status='processing'"),
  review: db.prepare('INSERT INTO reviews(user_id,rating,text,created_at) VALUES(?,?,?,?)'),
};

const upiLink = o => `upi://pay?pa=${CFG.UPI_ID}&pn=${encodeURIComponent(CFG.UPI_NAME)}&am=${o.inr.toFixed(2)}&cu=INR&tn=${encodeURIComponent('TM ' + o.public_id)}`;

const view = o => ({
  id: o.public_id, inr: o.inr, usdt: o.usdt_micro / 1e6, rate: o.rate, status: o.status,
  queuePosition: o.status === 'processing' ? q.position.get(o.id).c : null, createdAt: o.created_at,
  paymentSubmitted: !!o.utr,
  failReason: o.fail_reason,
  pay: o.status === 'processing' && CFG.UPI_ID ? { upiId: CFG.UPI_ID, name: CFG.UPI_NAME, link: upiLink(o) } : null,
});

// Moves a queued order to completed and credits the balance, atomically and only once.
// The payment-gateway webhook will call this same function.
const completeOrder = db.transaction(pid => {
  const o = q.byPid.get(pid);
  if (!o) return 'notfound';
  if (q.setStatus.run('completed', Date.now(), o.id).changes !== 1) return 'invalid';
  q.credit.run(o.user_id, o.id, o.usdt_micro, Date.now());
  return 'ok';
});
const cancelOrder = (pid, userId, reason) => {
  const o = q.byPid.get(pid);
  if (!o || (userId && o.user_id !== userId)) return 'notfound';
  if (userId && o.utr) return 'invalid';   // payment already submitted: only the admin can cancel
  const r = reason ? q.failOrder.run(reason, Date.now(), o.id) : q.setStatus.run('cancelled', Date.now(), o.id);
  return r.changes === 1 ? 'ok' : 'invalid';
};

const wView = w => ({ id: w.public_id, usdt: w.usdt_micro / 1e6, chain: w.chain, address: w.address, status: w.status, txid: w.txid, failReason: w.fail_reason, createdAt: w.created_at });

// Checks the balance and records the withdrawal in one atomic step (no double spending).
const requestWithdrawal = db.transaction((userId, micro, chain, address) => {
  const bal = q.balance.get(userId, userId).b;
  if (micro > bal) return { insufficient: true, bal };
  const pid = crypto.randomBytes(6).toString('hex'), t = Date.now();
  q.wInsert.run(pid, userId, micro, chain, address, t, t);
  return { pid };
});

// ---------------- Middleware ----------------
const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || true);   // only when behind Nginx/Cloudflare
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' });
  next();
});
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const hits = new Map();
const limiter = (max, windowMs = 60000) => (req, res, next) => {
  const k = req.ip + req.path, t = Date.now(), h = (hits.get(k) || []).filter(x => t - x < windowMs);
  if (h.length >= max) return res.status(429).json({ error: 'Too many requests. Please wait a minute and try again.' });
  h.push(t); hits.set(k, h); next();
};
setInterval(() => hits.clear(), 600000).unref();

const adminAuth = (req, res, next) => {
  const a = Buffer.from(String(req.get('x-admin-key') || '')), b = Buffer.from(CFG.ADMIN_KEY);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Wrong admin key.' });
  next();
};

// ---------------- Login: email + password, server-side sessions ----------------
const SESSION_MS = 30 * 24 * 3600 * 1000;
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const emailOf = id => q.userEmail.get(id)?.email || null;
const cookieOf = (req, name) => (req.headers.cookie || '').split(';').map(c => c.trim().split('=')).find(c => c[0] === name)?.[1];
const sessionCookie = (req, token, maxAgeMs) =>
  `tm_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(maxAgeMs / 1000)}${req.secure ? '; Secure' : ''}`;

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return 'scrypt$' + salt.toString('hex') + '$' + (await scrypt(pw, salt, 64)).toString('hex');
}
async function checkPassword(pw, stored) {
  const [, saltHex, hashHex] = String(stored || '').split('$');
  if (!saltHex || !hashHex) { await scrypt(pw, Buffer.alloc(16), 64); return false; }   // same work for unknown emails
  const h = await scrypt(pw, Buffer.from(saltHex, 'hex'), 64), want = Buffer.from(hashHex, 'hex');
  return h.length === want.length && crypto.timingSafeEqual(h, want);
}
function startSession(req, res, userId) {
  const token = crypto.randomBytes(32).toString('hex'), t = Date.now();
  q.purgeSessions.run(t);
  q.addSession.run(sha(token), userId, t, t + SESSION_MS);      // only a hash of the token is stored
  res.append('Set-Cookie', sessionCookie(req, token, SESSION_MS));
}
const requireAuth = (req, res, next) => {
  const tok = cookieOf(req, 'tm_session'), u = tok && q.getSession.get(sha(tok), Date.now());
  if (!u) return res.status(401).json({ error: 'Please log in.' });
  req.user = u; next();
};

const fails = new Map();   // email -> recent failed login times
setInterval(() => fails.clear(), 900000).unref();
const lockedOut = e => { const t = Date.now(), a = (fails.get(e) || []).filter(x => t - x < 900000); fails.set(e, a); return a.length >= 5; };
const EMAIL_RE = /^[^\s@<>"'&]+@[^\s@<>"'&]+\.[^\s@<>"'&]+$/;
const cred = b => ({ email: String(b.email || '').trim().toLowerCase().slice(0, 254), password: String(b.password || '').slice(0, 200) });

app.post('/api/auth/register', limiter(10), async (req, res) => {
  const { email, password } = cred(req.body || {});
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Password must be 8 to 128 characters.' });
  if (q.userByEmail.get(email)) return res.status(409).json({ error: 'An account with this email already exists. Please log in.' });
  const hash = await hashPassword(password);
  let id;
  try { id = q.addUser.run(email.split('@')[0], email, hash, Date.now()).lastInsertRowid; }
  catch { return res.status(409).json({ error: 'An account with this email already exists. Please log in.' }); }
  startSession(req, res, Number(id));
  res.status(201).json({ email });
});

app.post('/api/auth/login', limiter(10), async (req, res) => {
  const { email, password } = cred(req.body || {});
  if (lockedOut(email)) return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
  const u = q.userByEmail.get(email), ok = await checkPassword(password, u?.password_hash);
  if (!u || !ok) { fails.set(email, [...(fails.get(email) || []), Date.now()]); return res.status(401).json({ error: 'Wrong email or password.' }); }
  fails.delete(email); startSession(req, res, u.id);
  res.json({ email: u.email });
});

app.post('/api/auth/logout', (req, res) => {
  const tok = cookieOf(req, 'tm_session');
  if (tok) q.delSession.run(sha(tok));
  res.append('Set-Cookie', 'tm_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});
app.get('/api/me', requireAuth, (req, res) => res.json({ email: req.user.email }));

// Forgot password: the admin checks it is really the owner, then gives a one-time code (valid 30 minutes)
app.post('/api/auth/reset', limiter(10), async (req, res) => {
  const b = req.body || {}, email = cred(b).email, password = String(b.password || '').slice(0, 200);
  const code = String(b.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
  const bad = () => res.status(400).json({ error: 'Invalid or expired reset code.' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Password must be 8 to 128 characters.' });
  const u = q.userByEmail.get(email), r = u && q.getReset.get(u.id);
  if (!r || r.expires_at < Date.now()) return bad();
  if (r.tries >= 5) { q.delReset.run(u.id); return bad(); }          // 5 wrong guesses destroy the code
  if (code.length !== 8 || !crypto.timingSafeEqual(Buffer.from(sha(code)), Buffer.from(r.code_hash))) { q.bumpReset.run(u.id); return bad(); }
  q.setPassword.run(await hashPassword(password), u.id);
  q.delReset.run(u.id); q.delUserSessions.run(u.id);                  // code works once; every device is logged out
  res.json({ ok: true });
});

app.post('/api/auth/password', limiter(10), requireAuth, async (req, res) => {
  const b = req.body || {}, cur = String(b.current || '').slice(0, 200), next = String(b.next || '').slice(0, 200);
  if (next.length < 8 || next.length > 128) return res.status(400).json({ error: 'New password must be 8 to 128 characters.' });
  const u = q.userByEmail.get(req.user.email);
  if (!(await checkPassword(cur, u.password_hash))) return res.status(400).json({ error: 'Your current password is wrong.' });
  q.setPassword.run(await hashPassword(next), u.id);
  q.delOtherSessions.run(u.id, sha(cookieOf(req, 'tm_session')));    // other devices are logged out, this one stays
  res.json({ ok: true });
});

// Everything that touches a user's money or orders needs a logged-in user
app.use(['/api/balance', '/api/orders', '/api/withdrawals', '/api/reviews'], requireAuth);

// ---------------- User API ----------------
app.get('/api/rate', (req, res) => res.json({
  buyRate: CFG.BUY_RATE, sellRate: CFG.SELL_RATE, min: CFG.MIN_INR, max: CFG.MAX_INR, minUsdt: CFG.MIN_USDT,
  minWithdraw: CFG.MIN_WITHDRAW, support: CFG.SUPPORT, chains: CFG.CHAINS,
}));

app.get('/api/balance', (req, res) => {
  const usdt = q.balance.get(req.user.id, req.user.id).b / 1e6;
  res.json({ usdt, inrValue: +(usdt * CFG.SELL_RATE).toFixed(2) });
});

app.post('/api/orders', limiter(20), (req, res) => {
  const body = req.body || {}, inr = Number(body.inr);
  if (!Number.isInteger(inr)) return res.status(400).json({ error: 'Enter a whole rupee amount.' });
  if (inr < CFG.MIN_INR || inr > CFG.MAX_INR)
    return res.status(400).json({ error: `Order amount must be between ₹${CFG.MIN_INR} and ₹${CFG.MAX_INR}.` });

  const key = String(req.get('Idempotency-Key') || '').slice(0, 64) || null;   // double-tap / retry safety
  if (key) { const ex = q.byIdem.get(req.user.id, key); if (ex) return res.json(view(ex)); }
  if (q.openCount.get(req.user.id).c >= CFG.MAX_OPEN)
    return res.status(429).json({ code: 'QUEUE_FULL', error: `You already have ${CFG.MAX_OPEN} orders in the queue. Cancel one or wait for it to finish.` });

  const pid = crypto.randomBytes(6).toString('hex'), t = Date.now();
  const usdtMicro = Math.round(inr * 1e6 / CFG.BUY_RATE);
  q.insert.run(pid, req.user.id, inr, CFG.BUY_RATE, usdtMicro, key, t, t);   // starts as 'processing' = in the queue
  res.status(201).json(view(q.byPid.get(pid)));
});

app.get('/api/orders', (req, res) => res.json(q.list.all(req.user.id).map(view)));

app.get('/api/orders/:id', (req, res) => {
  const o = q.byPid.get(req.params.id);
  if (!o || o.user_id !== req.user.id) return res.status(404).json({ error: 'Order not found.' });
  res.json(view(o));
});

app.post('/api/orders/:id/cancel', (req, res) => {
  const r = cancelOrder(req.params.id, req.user.id);
  if (r === 'notfound') return res.status(404).json({ error: 'Order not found.' });
  if (r === 'invalid') return res.status(409).json({ error: 'This order can no longer be cancelled.' });
  res.json({ ok: true });
});

app.post('/api/reviews', limiter(5), (req, res) => {
  const body = req.body || {}, rating = Number(body.rating), text = String(body.text || '').trim().slice(0, 500);
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be 1 to 5 stars.' });
  q.review.run(req.user.id, rating, text, Date.now());
  res.json({ ok: true });
});

// ---------------- Withdrawals (you send the USDT manually, then mark it sent) ----------------
app.post('/api/withdrawals', limiter(10), (req, res) => {
  const b = req.body || {}, amount = Number(b.amount), address = String(b.address || '').trim();
  if (b.chain !== 'bsc') return res.status(400).json({ error: 'Select a supported chain.' });
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return res.status(400).json({ error: 'Enter a valid BSC (BEP20) wallet address. It starts with 0x and is 42 characters long.' });
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Enter the amount you want to withdraw.' });
  const micro = Math.round(amount * 1e6);
  if (micro < CFG.MIN_WITHDRAW * 1e6) return res.status(400).json({ error: `Minimum withdrawal is ${CFG.MIN_WITHDRAW} USDT.` });
  const r = requestWithdrawal(req.user.id, micro, 'bsc', address);
  if (r.insufficient) return res.status(400).json({ code: 'INSUFFICIENT', error: `Insufficient balance. You have ${(r.bal / 1e6).toFixed(4)} USDT available.` });
  res.status(201).json(wView(q.wByPid.get(r.pid)));
});
app.get('/api/withdrawals', (req, res) => res.json(q.wList.all(req.user.id).map(wView)));

// ---------------- Manual UPI payment ----------------
// QR code for this order's UPI payment (only while the order is waiting)
app.get('/api/orders/:id/qr.svg', async (req, res) => {
  const o = q.byPid.get(req.params.id);
  if (!o || o.user_id !== req.user.id || o.status !== 'processing' || !CFG.UPI_ID) return res.sendStatus(404);
  res.set({ 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-store' });
  res.send(await QRCode.toString(upiLink(o), { type: 'svg', margin: 2, errorCorrectionLevel: 'M' }));
});

// User says "I have paid" and gives the 12-digit UPI reference (UTR). You verify it in your bank app.
app.post('/api/orders/:id/paid', limiter(10), (req, res) => {
  const o = q.byPid.get(req.params.id);
  if (!o || o.user_id !== req.user.id) return res.status(404).json({ error: 'Order not found.' });
  const utr = String((req.body || {}).utr || '').trim();
  if (!/^\d{12}$/.test(utr)) return res.status(400).json({ error: 'Enter the 12-digit UPI reference number (UTR) from your payment app.' });
  try {
    if (q.setUtr.run(utr, Date.now(), o.id).changes !== 1) return res.status(409).json({ error: 'This order is no longer waiting for payment.' });
  } catch (e) {
    return res.status(409).json({ error: 'This reference number was already used on another order.' });
  }
  res.json(view(q.byPid.get(o.public_id)));
});

const reasonOf = b => { const r = String((b || {}).reason || '').trim().replace(/\s+/g, ' ').slice(0, 200); return r.length >= 3 ? r : ''; };
const NEED_REASON = { error: 'Write a short reason (at least 3 characters). The user will see it.' };

// ---------------- Admin: works the queue until the gateway is live ----------------
const admin = [limiter(60), adminAuth];
app.get('/api/admin/queue', ...admin, (req, res) => res.json(q.queue.all().map(o => ({ ...view(o), utr: o.utr, submittedAt: o.submitted_at, email: emailOf(o.user_id) }))));
app.post('/api/admin/orders/:id/complete', ...admin, (req, res) => {
  const r = completeOrder(req.params.id);
  if (r === 'notfound') return res.status(404).json({ error: 'Order not found.' });
  if (r === 'invalid') return res.status(409).json({ error: 'Order is not in the queue.' });
  res.json({ ok: true });
});
app.post('/api/admin/orders/:id/cancel', ...admin, (req, res) => {
  const reason = reasonOf(req.body);
  if (!reason) return res.status(400).json(NEED_REASON);
  const r = cancelOrder(req.params.id, null, reason);
  if (r === 'notfound') return res.status(404).json({ error: 'Order not found.' });
  if (r === 'invalid') return res.status(409).json({ error: 'Order is not in the queue.' });
  res.json({ ok: true });
});

app.get('/api/admin/withdrawals', ...admin, (req, res) => res.json(q.wPending.all().map(w => ({ ...wView(w), email: emailOf(w.user_id) }))));
const wFinish = status => (req, res) => {
  const txid = String((req.body || {}).txid || '').trim();
  if (txid && !/^0x[a-fA-F0-9]{64}$/.test(txid)) return res.status(400).json({ error: 'That transaction hash does not look right (0x + 64 characters). Leave it empty to skip.' });
  if (q.wSet.run(status, txid || null, Date.now(), req.params.id).changes !== 1) return res.status(409).json({ error: 'Withdrawal not found or already processed.' });
  res.json({ ok: true });
};
app.post('/api/admin/withdrawals/:id/complete', ...admin, wFinish('completed'));
app.post('/api/admin/withdrawals/:id/reject', ...admin, (req, res) => {
  const reason = reasonOf(req.body);
  if (!reason) return res.status(400).json(NEED_REASON);
  if (q.wFail.run(reason, Date.now(), req.params.id).changes !== 1) return res.status(409).json({ error: 'Withdrawal not found or already processed.' });
  res.json({ ok: true });                                              // the amount returns to the user's balance automatically
});

const CODE_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';                   // no look-alike characters
app.post('/api/admin/reset-code', ...admin, (req, res) => {
  const u = q.userByEmail.get(cred(req.body || {}).email);
  if (!u) return res.status(404).json({ error: 'No account with that email.' });
  const code = Array.from({ length: 8 }, () => CODE_CHARS[crypto.randomInt(CODE_CHARS.length)]).join('');
  q.setReset.run(u.id, sha(code), Date.now() + 30 * 60000);
  res.json({ code: code.slice(0, 4) + '-' + code.slice(4), minutes: 30 });
});

// Search the full history (nothing is ever deleted: paid, cancelled and rejected stay in the database)
app.get('/api/admin/search', ...admin, (req, res) => {
  const type = req.query.type === 'withdrawals' ? 'withdrawals' : 'orders';
  const status = String(req.query.status || ''), t = String(req.query.q || '').replace(/[%_]/g, '').trim().slice(0, 80);
  const where = [], args = [];
  if (type === 'orders') {
    if (['processing', 'completed', 'cancelled'].includes(status)) { where.push('status=?'); args.push(status); }
    if (t) { where.push('(public_id LIKE ? OR utr LIKE ? OR inr = ? OR user_id IN (SELECT id FROM users WHERE email LIKE ?))'); args.push(t.toLowerCase() + '%', '%' + t + '%', Number(t) || -1, '%' + t.toLowerCase() + '%'); }
  } else {
    if (['pending', 'completed', 'rejected'].includes(status)) { where.push('status=?'); args.push(status); }
    if (t) { const l = t.toLowerCase(); where.push("(public_id LIKE ? OR LOWER(address) LIKE ? OR LOWER(COALESCE(txid,'')) LIKE ? OR user_id IN (SELECT id FROM users WHERE email LIKE ?))"); args.push(l + '%', '%' + l + '%', '%' + l + '%', '%' + l + '%'); }
  }
  const rows = db.prepare(`SELECT * FROM ${type} ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id DESC LIMIT 100`).all(...args);
  res.json(type === 'orders'
    ? rows.map(o => ({ ...view(o), utr: o.utr, updatedAt: o.updated_at, email: emailOf(o.user_id) }))
    : rows.map(w => ({ ...wView(w), updatedAt: w.updated_at, email: emailOf(w.user_id) })));
});

app.use((err, req, res, next) => res.status(400).json({ error: 'Bad request.' }));

app.listen(CFG.PORT, err => {
  if (err) {
    console.error(err.code === 'EADDRINUSE'
      ? `PORT ${CFG.PORT} IS ALREADY IN USE. An old server is still running. Close all VS Code terminals (trash icon), open a new one and run npm start again.`
      : err);
    process.exit(1);
  }
  console.log(`TrustedMiners running on http://localhost:${CFG.PORT}`);
  console.log(`Limits ₹${CFG.MIN_INR} to ₹${CFG.MAX_INR}  |  buy rate ₹${CFG.BUY_RATE}  |  admin page: /admin.html`);
  console.log(CFG.UPI_ID ? `UPI payments to ${CFG.UPI_ID} (${CFG.UPI_NAME})` : 'WARNING: UPI_ID is not set in .env, so users cannot see a payment QR.');
  if (!process.env.ADMIN_KEY) console.log('Temporary admin key (put ADMIN_KEY in .env to keep one):', CFG.ADMIN_KEY);
});