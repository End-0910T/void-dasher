"use strict";

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── 数据文件路径 ──────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const LEADERBOARD_FILE = path.join(DATA_DIR, 'leaderboard.json');
const ENDLESS_TALENTS_FILE = path.join(DATA_DIR, 'endless_talents.json');
const ENDLESS_EQUIPMENT_FILE = path.join(DATA_DIR, 'endless_equipment.json');

// 确保数据目录存在
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ─── 数据读写 ──────────────────────────────────────
function readJSON(filepath) {
  try {
    if (fs.existsSync(filepath)) {
      return JSON.parse(fs.readFileSync(filepath, 'utf8'));
    }
  } catch(e) { console.error('读取文件失败:', filepath, e.message); }
  return {};
}

function writeJSON(filepath, data) {
  fs.writeFileSync(filepath, JSON.stringify(data, null, 2), 'utf8');
}

// ─── 密码哈希（简单SHA256） ────────────────────────
function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'void-dasher-salt').digest('hex');
}

// ─── 生成Token ─────────────────────────────────────
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ─── 中间件 ────────────────────────────────────────
app.use(express.json());
app.use(express.static(__dirname, {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
}));

// ─── API路由 ───────────────────────────────────────

// 注册
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }
  if (username.length < 2 || username.length > 20) {
    return res.status(400).json({ error: '用户名长度需在2-20个字符之间' });
  }
  if (password.length < 3 || password.length > 50) {
    return res.status(400).json({ error: '密码长度需在3-50个字符之间' });
  }

  const users = readJSON(USERS_FILE);

  // 检查用户名是否已存在
  for (const uid of Object.keys(users)) {
    if (users[uid].username.toLowerCase() === username.toLowerCase()) {
      return res.status(400).json({ error: '用户名已存在' });
    }
  }

  const token = generateToken();
  const hashedPw = hashPassword(password);

  users[username] = {
    username: username,
    password: hashedPw,
    token: token,
    createdAt: new Date().toISOString(),
    progress: {
      highScore: 0,
      coins: 0,
      upgrades: {},
      totalKills: 0,
      totalGames: 0,
      achievements: []
    }
  };

  writeJSON(USERS_FILE, users);

  console.log(`[注册] 新用户: ${username}`);
  res.json({ token: token, username: username });
});

// 登录
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }

  const users = readJSON(USERS_FILE);

  // 查找用户（不区分大小写）
  let foundKey = null;
  for (const uid of Object.keys(users)) {
    if (users[uid].username.toLowerCase() === username.toLowerCase()) {
      foundKey = uid;
      break;
    }
  }

  if (!foundKey) {
    return res.status(400).json({ error: '用户不存在' });
  }

  const user = users[foundKey];
  const hashedPw = hashPassword(password);

  if (user.password !== hashedPw) {
    return res.status(400).json({ error: '密码错误' });
  }

  // 生成新token
  const token = generateToken();
  user.token = token;
  writeJSON(USERS_FILE, users);

  console.log(`[登录] 用户: ${username}`);
  res.json({ token: token, username: user.username });
});

// 验证Token的中间件
function authMiddleware(req, res, next) {
  const token = req.headers.authorization || req.query.token || '';

  if (!token) {
    return res.status(401).json({ error: '未登录' });
  }

  const users = readJSON(USERS_FILE);
  let found = null;

  for (const uid of Object.keys(users)) {
    if (users[uid].token === token) {
      found = users[uid];
      break;
    }
  }

  if (!found) {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }

  req.user = found;
  next();
}

// 获取进度
app.get('/api/progress', authMiddleware, (req, res) => {
  res.json({
    username: req.user.username,
    progress: req.user.progress
  });
});

// 保存进度
app.post('/api/progress', authMiddleware, (req, res) => {
  const { progress } = req.body;

  if (!progress) {
    return res.status(400).json({ error: '无效的进度数据' });
  }

  const users = readJSON(USERS_FILE);

  // 找到并更新用户进度
  for (const uid of Object.keys(users)) {
    if (users[uid].token === req.user.token) {
      // 合并进度（保留更高的值）
      const oldProgress = users[uid].progress;
      users[uid].progress = {
        highScore: Math.max(oldProgress.highScore || 0, progress.highScore || 0),
        coins: Math.max(oldProgress.coins || 0, progress.coins || 0),
        upgrades: { ...oldProgress.upgrades, ...progress.upgrades },
        totalKills: Math.max(oldProgress.totalKills || 0, progress.totalKills || 0),
        totalGames: (oldProgress.totalGames || 0) + 1,
        achievements: [...new Set([...(oldProgress.achievements || []), ...(progress.achievements || [])])]
      };

      writeJSON(USERS_FILE, users);

      // 更新排行榜
      updateLeaderboard(uid, users[uid].progress.highScore);

      console.log(`[进度] ${uid}: 分数=${progress.highScore}, 金币=${progress.coins}`);
      return res.json({ success: true });
    }
  }

  res.status(400).json({ error: '用户不存在' });
});

// 排行榜
app.get('/api/leaderboard', (req, res) => {
  const leaderboard = readJSON(LEADERBOARD_FILE);
  // 转为数组并排序
  const rankings = Object.entries(leaderboard)
    .map(([name, score]) => ({ username: name, score: score }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 50);
  res.json(rankings);
});

function updateLeaderboard(username, score) {
  let leaderboard = readJSON(LEADERBOARD_FILE);
  leaderboard[username] = Math.max(leaderboard[username] || 0, score);
  writeJSON(LEADERBOARD_FILE, leaderboard);
}

// ─── 无尽模式API ──────────────────────────────────

// 获取无尽模式数据
app.get('/api/endless/load', authMiddleware, (req, res) => {
  const talents = readJSON(ENDLESS_TALENTS_FILE);
  const equipment = readJSON(ENDLESS_EQUIPMENT_FILE);
  const userTalents = talents[req.user.username] || {};
  const userEquipment = equipment[req.user.username] || {};
  res.json({
    talents: userTalents,
    equipment: userEquipment
  });
});

// 保存无尽模式数据
app.post('/api/endless/save', authMiddleware, (req, res) => {
  const { talents, equipment } = req.body;

  if (talents) {
    const allTalents = readJSON(ENDLESS_TALENTS_FILE);
    const existing = allTalents[req.user.username] || {};
    allTalents[req.user.username] = { ...existing, ...talents };
    writeJSON(ENDLESS_TALENTS_FILE, allTalents);
  }

  if (equipment) {
    const allEquipment = readJSON(ENDLESS_EQUIPMENT_FILE);
    const existing = allEquipment[req.user.username] || {};
    allEquipment[req.user.username] = { ...existing, ...equipment };
    writeJSON(ENDLESS_EQUIPMENT_FILE, allEquipment);
  }

  console.log(`[无尽模式] ${req.user.username}: 数据已保存`);
  res.json({ success: true });
});

// 服务器配置
app.get('/api/config', (req, res) => {
  const host = req.headers.host || '';
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  res.json({
    serverUrl: `${proto}://${host}`,
    version: '2.5.0'
  });
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
