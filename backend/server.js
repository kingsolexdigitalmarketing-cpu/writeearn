'use strict';
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { parse } = require('csv-parse/sync');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET || '';
const isProd = process.env.NODE_ENV === 'production';
if (JWT_SECRET.length < 32) {
  console.error('FATAL: Set JWT_SECRET to a random value at least 32 characters long.');
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is required.');
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'false' ? false : (isProd ? { rejectUnauthorized: false } : undefined),
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});
const allowedOrigins = (process.env.FRONTEND_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600
}));
// Allow the documented 2 MB task import payload plus JSON encoding overhead.
app.use(express.json({ limit: '5mb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 25, standardHeaders: true, legacyHeaders: false }));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const clean = value => String(value ?? '').trim();
const emailValid = s => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const toPublicUser = u => ({ id: u.id, name: u.name, username: u.username, email: u.email, role: u.role, status: u.status, balance: Number(u.balance), totalEarned: Number(u.total_earned), referralCode: u.referral_code || null, createdAt: u.created_at });
const signToken = u => jwt.sign({ sub: u.id, role: u.role }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '8h', issuer: 'writeearn-api', audience: 'writeearn-web' });

async function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'Please log in.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: 'writeearn-api', audience: 'writeearn-web' });
    const result = await pool.query('SELECT id,name,username,email,role,status,balance,total_earned,referral_code,created_at FROM users WHERE id=$1', [payload.sub]);
    if (!result.rowCount || result.rows[0].status !== 'active') return res.status(401).json({ error: 'Account is unavailable.' });
    req.user = result.rows[0];
    next();
  } catch (e) { return res.status(401).json({ error: 'Your session is invalid or expired. Please log in again.' }); }
}
const adminOnly = (req, res, next) => req.user?.role === 'admin' ? next() : res.status(403).json({ error: 'Admin access required.' });

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name VARCHAR(100) NOT NULL,
    username VARCHAR(30) NOT NULL UNIQUE, email VARCHAR(254) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, role VARCHAR(10) NOT NULL DEFAULT 'member' CHECK(role IN ('member','admin')),
    status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','pending')),
    balance NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK(balance >= 0),
    total_earned NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK(total_earned >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  // Safe migrations for existing installations; no existing account or balance is replaced.
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(20)');
  const usersWithoutCodes = await pool.query('SELECT id FROM users WHERE referral_code IS NULL');
  for (const row of usersWithoutCodes.rows) {
    let code, collision;
    do {
      code = crypto.randomBytes(5).toString('hex').toUpperCase();
      collision = await pool.query('SELECT 1 FROM users WHERE referral_code=$1', [code]);
    } while (collision.rowCount);
    await pool.query('UPDATE users SET referral_code=$1 WHERE id=$2 AND referral_code IS NULL', [code, row.id]);
  }
  await pool.query('ALTER TABLE users ALTER COLUMN referral_code SET NOT NULL');
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)');
  await pool.query(`CREATE TABLE IF NOT EXISTS referrals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    referrer_id UUID NOT NULL REFERENCES users(id),
    referred_user_id UUID NOT NULL UNIQUE REFERENCES users(id),
    status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','qualified','rewarded','rejected')),
    reward_mode VARCHAR(24) NOT NULL DEFAULT 'first_task_bonus' CHECK(reward_mode IN ('signup_bonus','first_task_bonus','percentage_earnings')),
    reward_value NUMERIC(8,2) NOT NULL DEFAULT 100 CHECK(reward_value >= 0),
    reward_total NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK(reward_total >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), qualified_at TIMESTAMPTZ, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query("ALTER TABLE referrals ADD COLUMN IF NOT EXISTS reward_mode VARCHAR(24) NOT NULL DEFAULT 'first_task_bonus'");
  await pool.query('ALTER TABLE referrals ADD COLUMN IF NOT EXISTS reward_value NUMERIC(10,2) NOT NULL DEFAULT 100');
  await pool.query('ALTER TABLE referrals ALTER COLUMN reward_value TYPE NUMERIC(10,2)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_referrals_referrer_created ON referrals(referrer_id,created_at DESC)');
  await pool.query(`CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), type VARCHAR(16) NOT NULL CHECK(type IN ('typing','story')),
    title VARCHAR(180) NOT NULL, brief TEXT NOT NULL, source TEXT NOT NULL DEFAULT '',
    minutes INTEGER NOT NULL DEFAULT 15 CHECK(minutes BETWEEN 1 AND 240),
    reward NUMERIC(12,2) NOT NULL CHECK(reward >= 0), min_words INTEGER NOT NULL DEFAULT 0 CHECK(min_words BETWEEN 0 AND 50000),
    status VARCHAR(16) NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),
    created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id), task_id UUID NOT NULL REFERENCES tasks(id),
    answer_title VARCHAR(180) NOT NULL DEFAULT '', answer TEXT NOT NULL, status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
    reward NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(reward >= 0), review_note TEXT NOT NULL DEFAULT '', reviewed_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), reviewed_at TIMESTAMPTZ
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS withdrawals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id), amount NUMERIC(12,2) NOT NULL CHECK(amount >= 500),
    bank_name VARCHAR(100) NOT NULL, account_number VARCHAR(10) NOT NULL, account_name VARCHAR(100) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','paid','rejected')),
    admin_note TEXT NOT NULL DEFAULT '', reviewed_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), reviewed_at TIMESTAMPTZ
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS settings (key VARCHAR(80) PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS ledger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id), kind VARCHAR(24) NOT NULL,
    amount NUMERIC(12,2) NOT NULL, reference_id UUID, note TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_tasks_status_type ON tasks(status,type)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_submissions_status_created ON submissions(status,created_at DESC)`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_one_live_submission_per_task ON submissions(user_id,task_id) WHERE status IN ('pending','approved')`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_withdrawals_status_created ON withdrawals(status,created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ledger_user_created ON ledger(user_id,created_at DESC)`);
  await pool.query(`INSERT INTO settings(key,value) VALUES ('withdrawal_min','500'),('withdrawal_max','100000'),('telegram_url','https://t.me/WriteEarns'),('referral_mode','first_task_bonus'),('referral_signup_bonus','0'),('referral_first_task_bonus','100'),('referral_percentage','10') ON CONFLICT(key) DO NOTHING`);
  // Bootstrap the first admin only when both values are provided in Render environment variables.
  const adminEmail = clean(process.env.ADMIN_EMAIL).toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD || '';
  if (adminEmail && adminPassword) {
    if (!emailValid(adminEmail) || adminPassword.length < 12) throw new Error('ADMIN_EMAIL must be valid and ADMIN_PASSWORD must be at least 12 characters.');
    const existing = await pool.query('SELECT id FROM users WHERE email=$1', [adminEmail]);
    if (!existing.rowCount) {
      const hash = await bcrypt.hash(adminPassword, 12);
      const username = ('admin_' + crypto.randomBytes(4).toString('hex')).slice(0, 30);
      // referral_code is NOT NULL for every user, including administrators.
      let adminReferralCode, codeCollision;
      do {
        adminReferralCode = crypto.randomBytes(5).toString('hex').toUpperCase();
        codeCollision = await pool.query('SELECT 1 FROM users WHERE referral_code=$1', [adminReferralCode]);
      } while (codeCollision.rowCount);
      await pool.query(`INSERT INTO users(name,username,email,password_hash,referral_code,role,status) VALUES($1,$2,$3,$4,$5,'admin','active')`, ['WriteEarn Administrator', username, adminEmail, hash, adminReferralCode]);
      console.log('Initial admin account created from environment settings.');
    } else {
      const bootstrapHash = await bcrypt.hash(adminPassword, 12);
      await pool.query("UPDATE users SET role='admin', status='active', password_hash=$1, updated_at=NOW() WHERE email=$2", [bootstrapHash, adminEmail]);
    }
  }
}

app.get('/health', asyncRoute(async (_req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true, service: 'writeearn-api', database: 'connected' });
}));
app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const name = clean(req.body.name), username = clean(req.body.username).toLowerCase(), email = clean(req.body.email).toLowerCase(), password = String(req.body.password || '');
  const referralCode = clean(req.body.referralCode || '').toUpperCase();
  if (name.length < 2 || name.length > 100) return res.status(400).json({ error: 'Name must be 2–100 characters.' });
  if (!/^[a-z0-9_]{3,30}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–30 characters using letters, numbers, or underscores.' });
  if (!emailValid(email) || email.length > 254) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 10 || password.length > 128) return res.status(400).json({ error: 'Password must be at least 10 characters.' });
  if (referralCode && !/^[A-F0-9]{10}$/.test(referralCode)) return res.status(400).json({ error: 'The referral link is invalid. You can remove the referral code and try again.' });
  const hash = await bcrypt.hash(password, 12);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let referrer = null;
    if (referralCode) {
      const rr = await client.query("SELECT id FROM users WHERE referral_code=$1 AND role='member' AND status='active' FOR SHARE", [referralCode]);
      if (!rr.rowCount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'This referral link is invalid or its owner is not active.' }); }
      referrer = rr.rows[0];
    }
    let newCode, collision;
    do {
      newCode = crypto.randomBytes(5).toString('hex').toUpperCase();
      collision = await client.query('SELECT 1 FROM users WHERE referral_code=$1', [newCode]);
    } while (collision.rowCount);
    const created = await client.query(`INSERT INTO users(name,username,email,password_hash,referral_code) VALUES($1,$2,$3,$4,$5) RETURNING id,name,username,email,role,status,balance,total_earned,referral_code,created_at`, [name,username,email,hash,newCode]);
    const user = created.rows[0];
    if (referrer) {
      const settingRows = await client.query("SELECT key,value FROM settings WHERE key IN ('referral_mode','referral_signup_bonus','referral_first_task_bonus','referral_percentage')");
      const cfg = Object.fromEntries(settingRows.rows.map(x => [x.key,x.value]));
      const mode = ['signup_bonus','first_task_bonus','percentage_earnings'].includes(cfg.referral_mode) ? cfg.referral_mode : 'first_task_bonus';
      const rewardValue = mode === 'signup_bonus' ? Math.max(0, Number(cfg.referral_signup_bonus)||0) : mode === 'percentage_earnings' ? Math.min(50,Math.max(0,Number(cfg.referral_percentage)||0)) : Math.max(0,Number(cfg.referral_first_task_bonus)||0);
      const initialStatus = mode === 'signup_bonus' ? (rewardValue > 0 ? 'rewarded' : 'qualified') : 'pending';
      await client.query("INSERT INTO referrals(referrer_id,referred_user_id,status,reward_mode,reward_value,reward_total,qualified_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $3 IN ('rewarded','qualified') THEN NOW() ELSE NULL END,NOW())", [referrer.id,user.id,initialStatus,mode,rewardValue,initialStatus==='rewarded'?rewardValue:0]);
      if (initialStatus === 'rewarded') {
        await client.query('UPDATE users SET balance=balance+$1,total_earned=total_earned+$1,updated_at=NOW() WHERE id=$2',[rewardValue,referrer.id]);
        await client.query("INSERT INTO ledger(user_id,kind,amount,reference_id,note) VALUES($1,'referral_reward',$2,$3,'Referral registration bonus')",[referrer.id,rewardValue,user.id]);
      }
    }
    await client.query('COMMIT');
    res.status(201).json({ token: signToken(user), user: toPublicUser(user) });
  } catch (e) {
    await client.query('ROLLBACK');
    if (e.code === '23505') return res.status(409).json({ error: 'That email or username is already registered.' });
    throw e;
  } finally { client.release(); }
}));
app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const email = clean(req.body.email).toLowerCase(), password = String(req.body.password || '');
  const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
  if (user.status !== 'active') return res.status(403).json({ error: 'Your account is not active. Contact support.' });
  res.json({ token: signToken(user), user: toPublicUser(user) });
}));
app.get('/api/auth/me', auth, (req, res) => res.json({ user: toPublicUser(req.user) }));
app.patch('/api/profile', auth, asyncRoute(async (req, res) => {
  const name = clean(req.body.name);
  if (name.length < 2 || name.length > 100) return res.status(400).json({ error: 'Name must be 2–100 characters.' });
  const result = await pool.query('UPDATE users SET name=$1, updated_at=NOW() WHERE id=$2 RETURNING id,name,username,email,role,status,balance,total_earned,created_at', [name, req.user.id]);
  res.json({ user: toPublicUser(result.rows[0]) });
}));
app.get('/api/public/settings', asyncRoute(async (_req, res) => {
  const r = await pool.query("SELECT key,value FROM settings WHERE key IN ('withdrawal_min','withdrawal_max','telegram_url','referral_mode','referral_signup_bonus','referral_first_task_bonus','referral_percentage')");
  res.set('Cache-Control', 'public, max-age=60');
  res.json({ settings: Object.fromEntries(r.rows.map(x => [x.key, x.value])) });
}));
app.get('/api/tasks', auth, asyncRoute(async (_req, res) => {
  const r = await pool.query("SELECT id,type,title,brief,source,minutes,reward,min_words AS \"minWords\",status,created_at AS \"createdAt\" FROM tasks WHERE status='published' ORDER BY created_at DESC");
  res.json({ tasks: r.rows });
}));
app.post('/api/submissions', auth, asyncRoute(async (req, res) => {
  const taskId = clean(req.body.taskId), answer = clean(req.body.answer), answerTitle = clean(req.body.title).slice(0,180);
  if (!taskId || !answer || answer.length > 100000) return res.status(400).json({ error: 'Task and answer are required; answer limit is 100,000 characters.' });
  const taskR = await pool.query("SELECT * FROM tasks WHERE id=$1 AND status='published'", [taskId]);
  if (!taskR.rowCount) return res.status(404).json({ error: 'Task not found or no longer available.' });
  const task = taskR.rows[0];
  if (task.type === 'story' && task.min_words > 0 && answer.split(/\s+/).filter(Boolean).length < task.min_words) return res.status(400).json({ error: `This task requires at least ${task.min_words} words.` });
  const duplicate = await pool.query("SELECT id FROM submissions WHERE user_id=$1 AND task_id=$2 AND status IN ('pending','approved')", [req.user.id, taskId]);
  if (duplicate.rowCount) return res.status(409).json({ error: 'You already submitted this task.' });
  let r;
  try {
    r = await pool.query('INSERT INTO submissions(user_id,task_id,answer_title,answer,reward) VALUES($1,$2,$3,$4,$5) RETURNING id,status,created_at', [req.user.id,taskId,answerTitle,answer,task.reward]);
  } catch (e) {
    // The partial unique index is the concurrency-safe guard against duplicate live submissions.
    if (e.code === '23505') return res.status(409).json({ error: 'You already submitted this task.' });
    throw e;
  }
  res.status(201).json({ submission: r.rows[0], message: 'Submitted for admin review. No reward is credited until approval.' });
}));
app.get('/api/me/summary', auth, asyncRoute(async (req, res) => {
  const [s, w, l] = await Promise.all([
    pool.query('SELECT s.id,s.task_id,s.status,s.reward,s.created_at,t.title,t.type FROM submissions s JOIN tasks t ON t.id=s.task_id WHERE s.user_id=$1 ORDER BY s.created_at DESC LIMIT 100',[req.user.id]),
    pool.query('SELECT id,amount,bank_name,account_name,status,admin_note,created_at FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',[req.user.id]),
    pool.query('SELECT id,kind,amount,note,created_at FROM ledger WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[req.user.id])
  ]);
  res.json({ user: toPublicUser(req.user), submissions: s.rows, withdrawals: w.rows, ledger: l.rows });
}));
app.post('/api/withdrawals', auth, asyncRoute(async (req, res) => {
  const amount = Number(req.body.amount), bank = clean(req.body.bankName), account = clean(req.body.accountNumber), accountName = clean(req.body.accountName);
  const settings = await pool.query("SELECT key,value FROM settings WHERE key IN ('withdrawal_min','withdrawal_max')");
  const cfg = Object.fromEntries(settings.rows.map(r => [r.key, Number(r.value)]));
  const min = cfg.withdrawal_min || 500, max = cfg.withdrawal_max || 100000;
  if (!Number.isFinite(amount) || !Number.isInteger(amount) || amount < min || amount > max) return res.status(400).json({ error: `Withdrawal must be a whole naira amount between ₦${min} and ₦${max}.` });
  if (bank.length < 2 || bank.length > 100 || !/^\d{10}$/.test(account) || accountName.length < 2 || accountName.length > 100) return res.status(400).json({ error: 'Enter a bank name, 10-digit account number, and account name.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const locked = await client.query('SELECT balance FROM users WHERE id=$1 FOR UPDATE', [req.user.id]);
    if (!locked.rowCount || Number(locked.rows[0].balance) < amount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Insufficient available balance.' }); }
    await client.query('UPDATE users SET balance=balance-$1,updated_at=NOW() WHERE id=$2', [amount,req.user.id]);
    const wr = await client.query('INSERT INTO withdrawals(user_id,amount,bank_name,account_number,account_name) VALUES($1,$2,$3,$4,$5) RETURNING id,amount,status,created_at', [req.user.id,amount,bank,account,accountName]);
    await client.query("INSERT INTO ledger(user_id,kind,amount,reference_id,note) VALUES($1,'withdrawal_reserved',$2,$3,'Funds reserved for pending withdrawal')", [req.user.id,-amount,wr.rows[0].id]);
    await client.query('COMMIT');
    res.status(201).json({ withdrawal: wr.rows[0], message: 'Withdrawal request submitted for admin review.' });
  } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
}));

app.get('/api/me/referrals', auth, asyncRoute(async (req,res)=>{
  const [userResult, referralResult, settingResult, statsResult] = await Promise.all([
    pool.query('SELECT referral_code FROM users WHERE id=$1',[req.user.id]),
    pool.query(`SELECT r.id,r.status,r.reward_total,r.created_at,r.qualified_at,u.username,u.name
      FROM referrals r JOIN users u ON u.id=r.referred_user_id WHERE r.referrer_id=$1 ORDER BY r.created_at DESC LIMIT 500`,[req.user.id]),
    pool.query("SELECT key,value FROM settings WHERE key IN ('referral_mode','referral_signup_bonus','referral_first_task_bonus','referral_percentage')"),
    pool.query(`SELECT COUNT(*)::int AS count, COUNT(*) FILTER (WHERE reward_total > 0)::int AS rewarded_count,
      COALESCE(SUM(reward_total),0)::numeric AS total_rewards FROM referrals WHERE referrer_id=$1`,[req.user.id])
  ]);
  const settings=Object.fromEntries(settingResult.rows.map(x=>[x.key,x.value]));
  const referrals=referralResult.rows, stats=statsResult.rows[0];
  res.json({ referralCode:userResult.rows[0].referral_code, referrals, count:stats.count,
    rewardedCount:stats.rewarded_count, totalRewards:Number(stats.total_rewards||0), settings });
}));

// Admin API: task studio, task imports, members, reviews, withdrawals, and site settings.
app.get('/api/admin/summary', auth, adminOnly, asyncRoute(async (_req, res) => {
  const q = await pool.query(`SELECT (SELECT COUNT(*) FROM users WHERE role='member') AS members,
    (SELECT COUNT(*) FROM tasks WHERE status='published') AS published_tasks,
    (SELECT COUNT(*) FROM submissions WHERE status='pending') AS pending_submissions,
    (SELECT COUNT(*) FROM withdrawals WHERE status='pending') AS pending_withdrawals,
    (SELECT COALESCE(SUM(total_earned),0) FROM users) AS total_earned`);
  res.json({ summary: q.rows[0] });
}));
app.get('/api/admin/tasks', auth, adminOnly, asyncRoute(async (_req, res) => {
  const r = await pool.query('SELECT * FROM tasks ORDER BY created_at DESC'); res.json({ tasks: r.rows });
}));
function validateTask(b) {
  const type = clean(b.type).toLowerCase(), title = clean(b.title), brief = clean(b.brief), source = String(b.source ?? ''), status = clean(b.status || 'draft').toLowerCase();
  const minutes = Number(b.minutes ?? 15), reward = Number(b.reward), minWords = Number(b.minWords ?? b.min_words ?? 0);
  if (!['typing','story'].includes(type)) return 'Task type must be typing or story.';
  if (title.length < 3 || title.length > 180 || brief.length < 3 || brief.length > 20000) return 'Title (3–180 chars) and brief (3–20,000 chars) are required.';
  if (source.length > 100000) return 'Source text is too long (max 100,000 characters).';
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 240) return 'Minutes must be between 1 and 240.';
  if (!Number.isFinite(reward) || reward < 0 || reward > 1000000) return 'Reward must be between ₦0 and ₦1,000,000.';
  if (!Number.isInteger(minWords) || minWords < 0 || minWords > 50000) return 'Minimum words must be between 0 and 50,000.';
  if (!['draft','published','archived'].includes(status)) return 'Status must be draft, published, or archived.';
  return { type,title,brief,source,minutes,reward,minWords,status };
}
app.post('/api/admin/tasks', auth, adminOnly, asyncRoute(async (req, res) => {
  const v = validateTask(req.body); if (typeof v === 'string') return res.status(400).json({ error: v });
  const r = await pool.query(`INSERT INTO tasks(type,title,brief,source,minutes,reward,min_words,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`, [v.type,v.title,v.brief,v.source,v.minutes,v.reward,v.minWords,v.status,req.user.id]);
  res.status(201).json({ task: r.rows[0] });
}));
app.patch('/api/admin/tasks/:id', auth, adminOnly, asyncRoute(async (req, res) => {
  const v = validateTask(req.body); if (typeof v === 'string') return res.status(400).json({ error: v });
  const r = await pool.query(`UPDATE tasks SET type=$1,title=$2,brief=$3,source=$4,minutes=$5,reward=$6,min_words=$7,status=$8,updated_at=NOW() WHERE id=$9 RETURNING *`, [v.type,v.title,v.brief,v.source,v.minutes,v.reward,v.minWords,v.status,req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'Task not found.' }); res.json({ task: r.rows[0] });
}));
app.delete('/api/admin/tasks/:id', auth, adminOnly, asyncRoute(async (req, res) => {
  const r = await pool.query("UPDATE tasks SET status='archived',updated_at=NOW() WHERE id=$1 RETURNING id,status", [req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'Task not found.' }); res.json({ task: r.rows[0] });
}));
app.post('/api/admin/tasks/import', auth, adminOnly, asyncRoute(async (req, res) => {
  const raw = req.body.content;
  if (typeof raw !== 'string' || raw.length > 2_000_000) return res.status(400).json({ error: 'Paste a CSV or JSON file under 2 MB.' });
  let rows;
  try { rows = raw.trim().startsWith('[') ? JSON.parse(raw) : parse(raw, { columns: true, skip_empty_lines: true, bom: true, trim: true }); }
  catch (_) { return res.status(400).json({ error: 'Could not parse import. Use valid JSON array or CSV with headers: type,title,brief,source,minutes,reward,minWords,status.' }); }
  if (!Array.isArray(rows) || !rows.length || rows.length > 500) return res.status(400).json({ error: 'Import must contain 1–500 tasks.' });
  const client = await pool.connect(); const imported = [], errors = [];
  try {
    await client.query('BEGIN');
    for (let i=0;i<rows.length;i++) {
      const v = validateTask(rows[i]);
      if (typeof v === 'string') { errors.push({ row:i+1,error:v }); continue; }
      const r = await client.query(`INSERT INTO tasks(type,title,brief,source,minutes,reward,min_words,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,title,status`, [v.type,v.title,v.brief,v.source,v.minutes,v.reward,v.minWords,v.status,req.user.id]); imported.push(r.rows[0]);
    }
    await client.query('COMMIT');
    res.json({ imported: imported.length, errors, tasks: imported });
  } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
}));
app.get('/api/admin/users', auth, adminOnly, asyncRoute(async (req, res) => {
  const q = clean(req.query.q).slice(0,100), status = clean(req.query.status);
  const r = await pool.query(`SELECT id,name,username,email,role,status,balance,total_earned,created_at FROM users WHERE ($1='' OR name ILIKE '%'||$1||'%' OR username ILIKE '%'||$1||'%' OR email ILIKE '%'||$1||'%') AND ($2='' OR status=$2) ORDER BY created_at DESC LIMIT 500`, [q,['active','suspended','pending'].includes(status)?status:'']);
  res.json({ users:r.rows.map(toPublicUser) });
}));
app.patch('/api/admin/users/:id/status', auth, adminOnly, asyncRoute(async (req, res) => {
  const status = clean(req.body.status);
  if (!['active','suspended','pending'].includes(status)) return res.status(400).json({ error:'Status must be active, suspended, or pending.' });
  if (req.params.id === req.user.id) return res.status(400).json({ error:'You cannot change your own status.' });
  const r = await pool.query("UPDATE users SET status=$1,updated_at=NOW() WHERE id=$2 AND role='member' RETURNING id,name,username,email,role,status,balance,total_earned,created_at", [status,req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error:'Member not found.' }); res.json({ user:toPublicUser(r.rows[0]) });
}));
app.get('/api/admin/submissions', auth, adminOnly, asyncRoute(async (req,res)=>{
  const status = clean(req.query.status); const valid = ['pending','approved','rejected'].includes(status) ? status : '';
  const r = await pool.query(`SELECT s.id,s.user_id,s.task_id,s.answer_title,s.answer,s.status,s.reward,s.review_note,s.created_at,s.reviewed_at,u.name AS user_name,u.username,t.title AS task_title,t.type AS task_type FROM submissions s JOIN users u ON u.id=s.user_id JOIN tasks t ON t.id=s.task_id WHERE ($1='' OR s.status=$1) ORDER BY s.created_at DESC LIMIT 500`, [valid]); res.json({ submissions:r.rows });
}));
app.post('/api/admin/submissions/:id/review', auth, adminOnly, asyncRoute(async(req,res)=>{
  const decision=clean(req.body.status), note=clean(req.body.note).slice(0,2000);
  if(!['approved','rejected'].includes(decision)) return res.status(400).json({error:'Status must be approved or rejected.'});
  const c=await pool.connect();
  try{
    await c.query('BEGIN');
    const sr=await c.query('SELECT * FROM submissions WHERE id=$1 FOR UPDATE',[req.params.id]);
    if(!sr.rowCount){await c.query('ROLLBACK');return res.status(404).json({error:'Submission not found.'});}
    const s=sr.rows[0]; if(s.status!=='pending'){await c.query('ROLLBACK');return res.status(409).json({error:'This submission has already been reviewed.'});}
    await c.query('UPDATE submissions SET status=$1,review_note=$2,reviewed_by=$3,reviewed_at=NOW() WHERE id=$4',[decision,note,req.user.id,s.id]);
    if(decision==='approved'){
      await c.query('UPDATE users SET balance=balance+$1,total_earned=total_earned+$1,updated_at=NOW() WHERE id=$2',[s.reward,s.user_id]);
      await c.query("INSERT INTO ledger(user_id,kind,amount,reference_id,note) VALUES($1,'task_reward',$2,$3,'Approved task submission')",[s.user_id,s.reward,s.id]);
      const referralResult = await c.query(`SELECT r.* FROM referrals r WHERE r.referred_user_id=$1 FOR UPDATE`,[s.user_id]);
      if (referralResult.rowCount) {
        const referral = referralResult.rows[0];
        const mode = referral.reward_mode;
        const referrerCheck = await c.query("SELECT status FROM users WHERE id=$1 FOR UPDATE",[referral.referrer_id]);
        if (referrerCheck.rowCount && referrerCheck.rows[0].status === 'active') {
          if (mode === 'first_task_bonus' && referral.status === 'pending') {
            const bonus = Math.max(0, Number(referral.reward_value)||0);
            await c.query("UPDATE referrals SET status='rewarded',reward_total=reward_total+$1,qualified_at=NOW(),updated_at=NOW() WHERE id=$2",[bonus,referral.id]);
            if (bonus > 0) {
              await c.query('UPDATE users SET balance=balance+$1,total_earned=total_earned+$1,updated_at=NOW() WHERE id=$2',[bonus,referral.referrer_id]);
              await c.query("INSERT INTO ledger(user_id,kind,amount,reference_id,note) VALUES($1,'referral_reward',$2,$3,'Referral first approved task bonus')",[referral.referrer_id,bonus,s.id]);
            }
          } else if (mode === 'percentage_earnings' && referral.status !== 'rejected') {
            const pct = Math.min(50, Math.max(0, Number(referral.reward_value)||0));
            const bonus = Math.round((Number(s.reward)*pct/100)*100)/100;
            await c.query("UPDATE referrals SET status='qualified',reward_total=reward_total+$1,qualified_at=COALESCE(qualified_at,NOW()),updated_at=NOW() WHERE id=$2",[bonus,referral.id]);
            if (bonus > 0) {
              await c.query('UPDATE users SET balance=balance+$1,total_earned=total_earned+$1,updated_at=NOW() WHERE id=$2',[bonus,referral.referrer_id]);
              await c.query("INSERT INTO ledger(user_id,kind,amount,reference_id,note) VALUES($1,'referral_reward',$2,$3,$4)",[referral.referrer_id,bonus,s.id,`Referral share (${pct}%) from approved task`]);
            }
          }
        }
      }
    }
    await c.query('COMMIT'); res.json({ok:true,status:decision,message:decision==='approved'?'Approved and reward credited.':'Submission rejected; no reward credited.'});
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
}));
app.get('/api/admin/withdrawals', auth, adminOnly, asyncRoute(async(_req,res)=>{
  const r=await pool.query('SELECT w.*,u.name AS user_name,u.username,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.created_at DESC LIMIT 500'); res.json({withdrawals:r.rows});
}));
app.post('/api/admin/withdrawals/:id/review', auth, adminOnly, asyncRoute(async(req,res)=>{
  const decision=clean(req.body.status),note=clean(req.body.note).slice(0,2000);
  if(!['paid','rejected'].includes(decision))return res.status(400).json({error:'Status must be paid or rejected.'});
  const c=await pool.connect();
  try{
    await c.query('BEGIN'); const wr=await c.query('SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE',[req.params.id]);
    if(!wr.rowCount){await c.query('ROLLBACK');return res.status(404).json({error:'Withdrawal not found.'});}
    const w=wr.rows[0]; if(w.status!=='pending'){await c.query('ROLLBACK');return res.status(409).json({error:'This withdrawal has already been handled.'});}
    await c.query('UPDATE withdrawals SET status=$1,admin_note=$2,reviewed_by=$3,reviewed_at=NOW() WHERE id=$4',[decision,note,req.user.id,w.id]);
    if(decision==='rejected'){
      await c.query('UPDATE users SET balance=balance+$1,updated_at=NOW() WHERE id=$2',[w.amount,w.user_id]);
      await c.query("INSERT INTO ledger(user_id,kind,amount,reference_id,note) VALUES($1,'withdrawal_refund',$2,$3,'Rejected withdrawal returned to available balance')",[w.user_id,w.amount,w.id]);
    } else {
      await c.query("INSERT INTO ledger(user_id,kind,amount,reference_id,note) VALUES($1,'withdrawal_paid',0,$2,'Admin marked withdrawal as paid; verify transfer separately')",[w.user_id,w.id]);
    }
    await c.query('COMMIT'); res.json({ok:true,status:decision,message:decision==='paid'?'Marked paid. Complete and verify the bank transfer separately.':'Rejected and funds returned to member balance.'});
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
}));
app.get('/api/admin/referrals',auth,adminOnly,asyncRoute(async(_req,res)=>{
  const r=await pool.query(`SELECT r.id,r.status,r.reward_total,r.created_at,r.qualified_at,
    ref.name AS referrer_name,ref.username AS referrer_username,ref.email AS referrer_email,
    newu.name AS referred_name,newu.username AS referred_username,newu.email AS referred_email
    FROM referrals r JOIN users ref ON ref.id=r.referrer_id JOIN users newu ON newu.id=r.referred_user_id
    ORDER BY r.created_at DESC LIMIT 1000`);
  res.json({referrals:r.rows});
}));
app.get('/api/admin/settings',auth,adminOnly,asyncRoute(async(_req,res)=>{const r=await pool.query('SELECT key,value FROM settings ORDER BY key');res.json({settings:Object.fromEntries(r.rows.map(x=>[x.key,x.value]))});}));
app.patch('/api/admin/settings',auth,adminOnly,asyncRoute(async(req,res)=>{
  const incoming=req.body||{};
  const allowed=['withdrawal_min','withdrawal_max','telegram_url','referral_mode','referral_signup_bonus','referral_first_task_bonus','referral_percentage'];
  const mergedRows=await pool.query('SELECT key,value FROM settings');
  const merged=Object.fromEntries(mergedRows.rows.map(x=>[x.key,x.value]));
  for(const key of allowed) if(incoming[key]!==undefined) merged[key]=String(incoming[key]).trim();
  const min=Number(merged.withdrawal_min),max=Number(merged.withdrawal_max);
  if(!Number.isInteger(min)||min<500||min>1000000||!Number.isInteger(max)||max<min||max>10000000)return res.status(400).json({error:'Minimum must be at least ₦500 and maximum must be >= minimum.'});
  if(!/^https:\/\/t\.me\/[A-Za-z0-9_]{5,64}\/?$/.test(merged.telegram_url||''))return res.status(400).json({error:'Telegram link must be a valid https://t.me/username URL.'});
  if(!['signup_bonus','first_task_bonus','percentage_earnings'].includes(merged.referral_mode))return res.status(400).json({error:'Choose a valid referral reward mode.'});
  for(const key of ['referral_signup_bonus','referral_first_task_bonus']) if(!/^\d+(\.\d{1,2})?$/.test(merged[key]||'')||Number(merged[key])<0||Number(merged[key])>1000000)return res.status(400).json({error:`${key} must be between ₦0 and ₦1,000,000.`});
  if(!/^\d+(\.\d{1,2})?$/.test(merged.referral_percentage||'')||Number(merged.referral_percentage)<0||Number(merged.referral_percentage)>50)return res.status(400).json({error:'Referral percentage must be between 0 and 50.'});
  for(const key of allowed){if(incoming[key]===undefined)continue;await pool.query('INSERT INTO settings(key,value,updated_at) VALUES($1,$2,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()',[key,merged[key]]);}
  const r=await pool.query('SELECT key,value FROM settings ORDER BY key');res.json({settings:Object.fromEntries(r.rows.map(x=>[x.key,x.value]))});
}));
app.get('/api/admin/ledger',auth,adminOnly,asyncRoute(async(_req,res)=>{const r=await pool.query('SELECT l.*,u.username,u.name FROM ledger l JOIN users u ON u.id=l.user_id ORDER BY l.created_at DESC LIMIT 1000');res.json({ledger:r.rows});}));

app.use((err, _req, res, _next) => {
  if (err.message === 'Origin not allowed by CORS') return res.status(403).json({ error: 'This website origin is not allowed.' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request body is too large. Task imports must be no larger than 2 MB.' });
  if (err instanceof SyntaxError && Object.prototype.hasOwnProperty.call(err, 'body')) return res.status(400).json({ error: 'Request body contains invalid JSON.' });
  console.error(err.stack || err);
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});
(async()=>{
  try { await initDb(); app.listen(PORT,()=>console.log(`WriteEarn API listening on ${PORT}`)); }
  catch(e){ console.error('Startup failed:',e); process.exit(1); }
})();
