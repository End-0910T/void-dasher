"use strict";

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'game.db');

if (!require('fs').existsSync(DATA_DIR)) require('fs').mkdirSync(DATA_DIR, { recursive: true });

// ─── 数据库初始化 ──────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    token TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    high_score INTEGER DEFAULT 0,
    coins INTEGER DEFAULT 0,
    upgrades TEXT DEFAULT '{}',
    total_kills INTEGER DEFAULT 0,
    total_games INTEGER DEFAULT 0,
    achievements TEXT DEFAULT '[]',
    unlocked_skins TEXT DEFAULT '["0"]',
    equipped_skin INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS leaderboard (
    username TEXT PRIMARY KEY,
    score INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS endless_data (
    username TEXT PRIMARY KEY,
    talents TEXT DEFAULT '{}',
    essence INTEGER DEFAULT 0,
    equipment TEXT DEFAULT '[]'
  );
`);

// ─── 数据迁移：JSON → SQLite ──────────────────────
function migrateIfNeeded() {
  const fs = require('fs');
  const USERS_FILE = path.join(DATA_DIR, 'users.json');
  const LEADERBOARD_FILE = path.join(DATA_DIR, 'leaderboard.json');
  const TALENTS_FILE = path.join(DATA_DIR, 'endless_talents.json');
  const EQUIPMENT_FILE = path.join(DATA_DIR, 'endless_equipment.json');

  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  if (userCount > 0) return; // Already migrated

  function readJSON(fp) {
    try { if (fs.existsSync(fp)) return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch(e) {}
    return {};
  }

  const users = readJSON(USERS_FILE);
  const lb = readJSON(LEADERBOARD_FILE);
  const talents = readJSON(TALENTS_FILE);
  const equipment = readJSON(EQUIPMENT_FILE);

  const insertUser = db.prepare(`INSERT OR IGNORE INTO users (username,password,token,created_at,high_score,coins,upgrades,total_kills,total_games,achievements,unlocked_skins,equipped_skin) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`);
  const insertLb = db.prepare('INSERT OR IGNORE INTO leaderboard (username,score) VALUES (?,?)');
  const insertEndless = db.prepare('INSERT OR IGNORE INTO endless_data (username,talents,essence,equipment) VALUES (?,?,?,?)');

  const tx = db.transaction(() => {
    for (const uid of Object.keys(users)) {
      const u = users[uid];
      const p = u.progress || {};
      insertUser.run(u.username, u.password, u.token, u.createdAt || new Date().toISOString(),
        p.highScore || 0, p.coins || 0, JSON.stringify(p.upgrades || {}),
        p.totalKills || 0, p.totalGames || 0, JSON.stringify(p.achievements || []),
        JSON.stringify(p.unlockedSkins || ['0']), p.equippedSkin || 0);
    }
    for (const name of Object.keys(lb)) insertLb.run(name, lb[name]);
    for (const name of Object.keys(talents)) insertEndless.run(name, JSON.stringify(talents[name] || {}), 0, '[]');
    for (const name of Object.keys(equipment)) {
      db.prepare('INSERT OR IGNORE INTO endless_data (username,talents,essence,equipment) VALUES (?,?,?,?)').run(name, '{}', 0, JSON.stringify(equipment[name] || []));
    }
  });
  try { tx(); console.log('[迁移] JSON数据已迁移至SQLite'); } catch(e) { console.error('迁移失败:', e.message); }
}
migrateIfNeeded();

// ─── 密码哈希 ──────────────────────────────────────
function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'void-dasher-salt').digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ─── 中间件 ────────────────────────────────────────
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname, {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
}));

// ─── 限速（防暴力破解） ────────────────────────────
const rateLimit = new Map();
function rateLimiter(maxRequests, windowMs) {
  return (req, res, next) => {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const entry = rateLimit.get(ip) || { count: 0, reset: now + windowMs };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
    entry.count++;
    rateLimit.set(ip, entry);
    if (entry.count > maxRequests) {
      return res.status(429).json({ error: '请求过于频繁，请稍后再试' });
    }
    next();
  };
}

// ─── 认证中间件 ────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization || req.query.token || '';
  if (!token) return res.status(401).json({ error: '未登录' });
  const user = db.prepare('SELECT * FROM users WHERE token = ?').get(token);
  if (!user) return res.status(401).json({ error: '登录已过期，请重新登录' });
  req.user = user;
  next();
}

// ─── API路由 ───────────────────────────────────────

// 注册
app.post('/api/register', rateLimiter(10, 60000), (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  if (username.length < 2 || username.length > 20) return res.status(400).json({ error: '用户名长度需在2-20个字符之间' });
  if (password.length < 3 || password.length > 50) return res.status(400).json({ error: '密码长度需在3-50个字符之间' });

  const existing = db.prepare('SELECT username FROM users WHERE LOWER(username) = LOWER(?)').get(username);
  if (existing) return res.status(400).json({ error: '用户名已存在' });

  const token = generateToken();
  const hashedPw = hashPassword(password);
  db.prepare('INSERT INTO users (username,password,token) VALUES (?,?,?)').run(username, hashedPw, token);
  console.log(`[注册] 新用户: ${username}`);
  res.json({ token, username });
});

// 登录
app.post('/api/login', rateLimiter(15, 60000), (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });

  const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
  if (!user) return res.status(400).json({ error: '用户不存在' });

  const hashedPw = hashPassword(password);
  if (user.password !== hashedPw) return res.status(400).json({ error: '密码错误' });

  const token = generateToken();
  db.prepare('UPDATE users SET token = ? WHERE username = ?').run(token, user.username);
  console.log(`[登录] 用户: ${username}`);
  res.json({ token, username: user.username });
});

// 获取进度
app.get('/api/progress', authMiddleware, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(req.user.username);
  res.json({
    username: u.username,
    progress: {
      highScore: u.high_score,
      coins: u.coins,
      upgrades: JSON.parse(u.upgrades || '{}'),
      storeItems: {},
      totalKills: u.total_kills,
      totalGames: u.total_games,
      achievements: JSON.parse(u.achievements || '[]'),
      unlockedSkins: JSON.parse(u.unlocked_skins || '["0"]'),
      equippedSkin: u.equipped_skin
    }
  });
});

// 保存进度
app.post('/api/progress', authMiddleware, (req, res) => {
  const { progress } = req.body;
  if (!progress) return res.status(400).json({ error: '无效的进度数据' });

  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(req.user.username);
  const oldUpgrades = JSON.parse(u.upgrades || '{}');
  const mergedUpgrades = { ...oldUpgrades, ...(progress.upgrades || {}) };
  const oldAchievements = JSON.parse(u.achievements || '[]');
  const mergedAchievements = [...new Set([...oldAchievements, ...(progress.achievements || [])])];

  db.prepare(`UPDATE users SET high_score=MAX(high_score,?), coins=MAX(coins,?), upgrades=?, total_kills=MAX(total_kills,?), total_games=total_games+1, achievements=?, unlocked_skins=?, equipped_skin=? WHERE username=?`)
    .run(progress.highScore || 0, progress.coins || 0, JSON.stringify(mergedUpgrades),
      progress.totalKills || 0, JSON.stringify(mergedAchievements),
      JSON.stringify(progress.unlockedSkins || ['0']), progress.equippedSkin || 0,
      req.user.username);

  db.prepare('INSERT INTO leaderboard (username,score) VALUES (?,?) ON CONFLICT(username) DO UPDATE SET score=MAX(score,?)')
    .run(req.user.username, progress.highScore || 0, progress.highScore || 0);

  console.log(`[进度] ${req.user.username}: 分数=${progress.highScore}, 金币=${progress.coins}`);
  res.json({ success: true });
});

// 排行榜
app.get('/api/leaderboard', (req, res) => {
  const rows = db.prepare('SELECT username, score FROM leaderboard ORDER BY score DESC LIMIT 50').all();
  const rankings = rows.map(r => ({ username: r.username, score: r.score }));
  res.json(rankings);
});

// 无尽模式——加载
app.get('/api/endless/load', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT talents, essence, equipment FROM endless_data WHERE username = ?').get(req.user.username);
  const talents = row ? JSON.parse(row.talents || '{}') : {};
  const equipment = row ? JSON.parse(row.equipment || '[]') : [];
  const essence = row ? row.essence : 0;
  res.json({ talents, equipment, essence });
});

// 无尽模式——保存
app.post('/api/endless/save', authMiddleware, (req, res) => {
  const { talents, equipment, essence } = req.body;
  const existing = db.prepare('SELECT * FROM endless_data WHERE username = ?').get(req.user.username);

  if (existing) {
    const mergedTalents = talents ? JSON.stringify({ ...JSON.parse(existing.talents || '{}'), ...talents }) : existing.talents;
    const mergedEquip = equipment ? JSON.stringify(equipment) : existing.equipment;
    const mergedEssence = essence != null ? Math.max(existing.essence, essence) : existing.essence;
    db.prepare('UPDATE endless_data SET talents=?, essence=?, equipment=? WHERE username=?')
      .run(mergedTalents, mergedEssence, mergedEquip, req.user.username);
  } else {
    db.prepare('INSERT INTO endless_data (username,talents,essence,equipment) VALUES (?,?,?,?)')
      .run(req.user.username, JSON.stringify(talents || {}), essence || 0, JSON.stringify(equipment || []));
  }

  console.log(`[无尽模式] ${req.user.username}: 数据已保存`);
  res.json({ success: true });
});

// 服务器配置
app.get('/api/config', (req, res) => {
  const host = req.headers.host || '';
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  res.json({ serverUrl: `${proto}://${host}`, version: '2.5.0' });
});

// ─── 启动服务器 ────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════╗
║   🎮 虚空冲刺 - Void Dasher 服务器      ║
║   地址: http://localhost:${PORT}          ║
║   按 Ctrl+C 停止服务器                  ║
╚══════════════════════════════════════════╝
  `);
});
