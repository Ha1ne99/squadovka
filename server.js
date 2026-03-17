const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, maxPayload: 2 * 1024 * 1024 });

const publicDir = path.join(__dirname, 'public');
const rootIndex = path.join(__dirname, 'index.html');
const publicIndex = path.join(publicDir, 'index.html');
const uploadsDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

app.set('trust proxy', 1);

const SESSION_SECRET = process.env.SESSION_SECRET || '';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const AUTH_WINDOW_MS = 1000 * 60 * 10;
const AUTH_MAX_ATTEMPTS = 10;
const ACTION_WINDOW_MS = 1000 * 30;
const ACTION_LIMITS = {
  update_avatar: 6,
  update_banner: 6,
  update_profile: 20,
  create_group: 8,
  friend_request: 20,
  get_messages: 90,
  message: 120,
  typing: 240,
  read: 120,
  edit_message: 40,
  delete_message: 40,
  get_group_messages: 90,
  group_message: 120,
  edit_group_message: 40,
  delete_group_message: 40,
  update_group: 20,
  add_group_members: 20,
  remove_group_member: 20,
  leave_group: 20,
  call_start: 12,
  call_signal: 600,
  call_response: 30,
  call_end: 60
};
const MAX_MESSAGE_LENGTH = 4000;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_FILENAME_LENGTH = 180;
const MAX_GROUP_NAME_LENGTH = 48;
const CHAT_HISTORY_LIMIT = 200;
const MAX_NICKNAME_LENGTH = 32;
const LOGIN_RE = /^[a-zA-Z0-9_\-.]{3,32}$/;
const authAttempts = new Map();
const actionAttempts = new Map();

if (!SESSION_SECRET && isProduction()) {
  console.error('SESSION_SECRET not found in environment variables');
  process.exit(1);
}
if (!SESSION_SECRET) {
  console.warn('SESSION_SECRET not set. Using development-only fallback secret.');
}
const EFFECTIVE_SESSION_SECRET = SESSION_SECRET || 'dev-only-session-secret-change-me';

function getIceServers() {
  const servers = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
  const turnUrl = (process.env.TURN_URL || '').trim();
  const turnUsername = (process.env.TURN_USERNAME || '').trim();
  const turnCredential = (process.env.TURN_CREDENTIAL || '').trim();
  if (turnUrl) {
    const turnServer = { urls: turnUrl.includes(',') ? turnUrl.split(',').map(v => v.trim()).filter(Boolean) : [turnUrl] };
    if (turnUsername) turnServer.username = turnUsername;
    if (turnCredential) turnServer.credential = turnCredential;
    servers.push(turnServer);
  }
  return servers;
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
}

function isProduction() {
  return process.env.NODE_ENV === 'production';
}

function hmacSafeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function signSessionPayload(payload) {
  return crypto.createHmac('sha256', EFFECTIVE_SESSION_SECRET).update(payload).digest('base64url');
}

function hashSessionId(sessionId) {
  return crypto.createHash('sha256').update(String(sessionId)).digest('base64url');
}

async function issueSessionToken(login) {
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;
  const sessionId = crypto.randomBytes(24).toString('base64url');
  const nonce = crypto.randomBytes(16).toString('base64url');
  const payload = `${login}.${expiresAt}.${sessionId}.${nonce}`;
  const signature = signSessionPayload(payload);

  await pool.query(`
    INSERT INTO sessions (id, login, sessionHash, createdAt, expiresAt, revoked)
    VALUES ($1, $2, $3, $4, $5, FALSE)
  `, [sessionId, login, hashSessionId(sessionId), now, expiresAt]);

  return `${payload}.${signature}`;
}

async function verifySessionToken(token) {
  if (typeof token !== 'string' || !token) return null;
  const parts = token.split('.');
  if (parts.length < 5) return null;
  const signature = parts.pop();
  const nonce = parts.pop();
  const sessionId = parts.pop();
  const expiresAt = Number(parts.pop());
  const login = parts.join('.');
  if (!login || !Number.isFinite(expiresAt) || !sessionId || !nonce) return null;
  const payload = `${login}.${expiresAt}.${sessionId}.${nonce}`;
  const expected = signSessionPayload(payload);
  if (!hmacSafeEqual(signature, expected) || expiresAt < Date.now()) return null;

  const result = await pool.query(`
    SELECT id, login, expiresAt, revoked
    FROM sessions
    WHERE id = $1 AND login = $2 AND sessionHash = $3
    LIMIT 1
  `, [sessionId, login, hashSessionId(sessionId)]);
  const session = result.rows[0];
  if (!session || session.revoked || Number(session.expiresat) < Date.now()) return null;
  return { login, expiresAt, sessionId };
}

function cleanupOldAuthAttempts(now = Date.now()) {
  for (const [ip, data] of authAttempts) {
    if (!data || now - data.firstSeenAt > AUTH_WINDOW_MS) authAttempts.delete(ip);
  }
}

function recordAuthAttempt(ip, success) {
  const now = Date.now();
  cleanupOldAuthAttempts(now);
  if (success) {
    authAttempts.delete(ip);
    return false;
  }
  const current = authAttempts.get(ip);
  if (!current || now - current.firstSeenAt > AUTH_WINDOW_MS) {
    authAttempts.set(ip, { count: 1, firstSeenAt: now });
    return false;
  }
  current.count += 1;
  authAttempts.set(ip, current);
  return current.count >= AUTH_MAX_ATTEMPTS;
}

function isRateLimited(ip) {
  cleanupOldAuthAttempts();
  const entry = authAttempts.get(ip);
  return Boolean(entry && entry.count >= AUTH_MAX_ATTEMPTS && Date.now() - entry.firstSeenAt <= AUTH_WINDOW_MS);
}

function cleanupActionAttempts(now = Date.now()) {
  for (const [key, data] of actionAttempts) {
    if (!data || now - data.firstSeenAt > ACTION_WINDOW_MS) actionAttempts.delete(key);
  }
}

function recordActionAttempt(ip, action) {
  const now = Date.now();
  cleanupActionAttempts(now);
  const limit = ACTION_LIMITS[action];
  if (!limit) return false;
  const key = `${ip}:${action}`;
  const current = actionAttempts.get(key);
  if (!current || now - current.firstSeenAt > ACTION_WINDOW_MS) {
    actionAttempts.set(key, { count: 1, firstSeenAt: now });
    return false;
  }
  current.count += 1;
  actionAttempts.set(key, current);
  return current.count > limit;
}

function sanitizeLogin(value) {
  const login = typeof value === 'string' ? value.trim() : '';
  return LOGIN_RE.test(login) ? login : '';
}

function sanitizeText(value, maxLen = MAX_MESSAGE_LENGTH) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

function sanitizeName(value, maxLen) {
  if (typeof value !== 'string') return '';
  return value.trim().replace(/\s+/g, ' ').slice(0, maxLen);
}

function sanitizeFilename(filename) {
  const raw = typeof filename === 'string' ? filename : 'file';
  const cleaned = raw.normalize('NFKC').replace(/[\\\/?%*:|"<>]/g, '_').replace(/\s+/g, ' ').trim().slice(0, MAX_FILENAME_LENGTH);
  return cleaned || 'file';
}

function getExtension(filename) {
  return path.extname(filename || '').toLowerCase().slice(0, 16);
}

function isImageMime(mimeType = '') {
  return /^image\//i.test(String(mimeType || ''));
}

function normalizeMimeType(mimeType, filename = '') {
  const type = String(mimeType || '').trim().toLowerCase();
  if (type) return type.slice(0, 120);
  const ext = getExtension(filename);
  if (['.jpg', '.jpeg'].includes(ext)) return 'image/jpeg';
  if (ext === '.png') return 'image/png';
  if (ext === '.gif') return 'image/gif';
  if (ext === '.webp') return 'image/webp';
  if (ext === '.svg') return 'image/svg+xml';
  return 'application/octet-stream';
}

function sanitizeAttachmentPayload(attachment) {
  if (!attachment || typeof attachment !== 'object') return null;
  const name = sanitizeFilename(attachment.name || attachment.originalName || attachment.filename || 'file');
  const url = typeof attachment.url === 'string' ? attachment.url.trim() : '';
  const size = Number(attachment.size);
  const mimeType = normalizeMimeType(attachment.mimeType || attachment.type, name);
  if (!url.startsWith('/uploads/') || !Number.isFinite(size) || size <= 0 || size > MAX_FILE_SIZE) return null;
  return { name, url, size, mimeType, isImage: isImageMime(mimeType) };
}
function sanitizeReplyPayload(reply) {
  if (!reply || typeof reply !== 'object') return null;
  const id = Number(reply.id);
  if (!Number.isFinite(id)) return null;
  const text = typeof reply.text === 'string' ? reply.text.trim().slice(0, 240) : '';
  const from = typeof reply.from === 'string' ? sanitizeLogin(reply.from) : '';
  const fromNick = typeof reply.fromNick === 'string' ? sanitizeName(reply.fromNick, MAX_NICKNAME_LENGTH) : '';
  const attachment = sanitizeAttachmentPayload(reply.attachment);
  if (!from && !fromNick && !text && !attachment) return null;
  return { id, text, from, fromNick, attachment };
}

async function readRequestBody(req, maxBytes = MAX_FILE_SIZE) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      const err = new Error('FILE_TOO_LARGE');
      err.code = 'FILE_TOO_LARGE';
      throw err;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

async function requireAuthFromRequest(req) {
  const authHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization.trim() : '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!token) return null;
  return verifySessionToken(token);
}

function isSecureRequest(req) {
  return req.secure || req.headers['x-forwarded-proto'] === 'https';
}

app.use((req, res, next) => {
  if (isProduction() && !isSecureRequest(req)) {
    const host = req.headers.host;
    if (host) return res.redirect(301, `https://${host}${req.originalUrl}`);
  }
  next();
});

app.use('/uploads', express.static(uploadsDir, {
  maxAge: '7d',
  etag: true,
  fallthrough: false
}));

app.use(express.json({ limit: '2mb' }));

app.post('/api/upload', async (req, res) => {
  try {
    const auth = await requireAuthFromRequest(req);
    if (!auth?.login) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    if (!contentType || !contentType.includes('application/octet-stream')) {
      return res.status(400).json({ ok: false, error: 'INVALID_CONTENT_TYPE' });
    }

    const originalName = sanitizeFilename(req.headers['x-file-name'] || 'file');
    const mimeType = normalizeMimeType(req.headers['x-file-type'] || '', originalName);
    const sizeHeader = Number(req.headers['x-file-size'] || 0);
    if (!Number.isFinite(sizeHeader) || sizeHeader <= 0 || sizeHeader > MAX_FILE_SIZE) {
      return res.status(400).json({ ok: false, error: 'INVALID_FILE_SIZE' });
    }

    const body = await readRequestBody(req, MAX_FILE_SIZE);
    if (!body.length || body.length > MAX_FILE_SIZE) {
      return res.status(400).json({ ok: false, error: 'INVALID_FILE_SIZE' });
    }

    const ext = getExtension(originalName) || '';
    const fileId = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
    const savedName = `${fileId}${ext}`;
    const fullPath = path.join(uploadsDir, savedName);
    await fsp.writeFile(fullPath, body);

    return res.json({
      ok: true,
      attachment: {
        name: originalName,
        url: `/uploads/${savedName}`,
        size: body.length,
        mimeType,
        isImage: isImageMime(mimeType)
      }
    });
  } catch (err) {
    if (err?.code === 'FILE_TOO_LARGE') {
      return res.status(413).json({ ok: false, error: 'FILE_TOO_LARGE' });
    }
    console.error('Upload error:', err);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

app.get('/', (req, res) => {
  if (fs.existsSync(rootIndex)) return res.sendFile(rootIndex);
  if (fs.existsSync(publicIndex)) return res.sendFile(publicIndex);
  return res.status(404).send('index.html not found');
});

app.use(express.static(publicDir));

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('DATABASE_URL not found in environment variables');
  process.exit(1);
}

const pool = new Pool({
  connectionString,
  ssl: isProduction() ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      login TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      nickname TEXT NOT NULL,
      status TEXT DEFAULT '',
      customStatus TEXT DEFAULT '',
      avatarImage TEXT DEFAULT '',
      bannerImage TEXT DEFAULT '',
      profileAbout TEXT DEFAULT '',
      presence TEXT DEFAULT 'online'
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS friend_requests (
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      createdAt BIGINT NOT NULL,
      PRIMARY KEY (fromUser, toUser)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS friends (
      user1 TEXT NOT NULL,
      user2 TEXT NOT NULL,
      PRIMARY KEY (user1, user2)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      text TEXT NOT NULL DEFAULT '',
      time BIGINT NOT NULL,
      edited BOOLEAN NOT NULL DEFAULT FALSE,
      editedAt BIGINT,
      deliveredAt BIGINT,
      readAt BIGINT,
      attachment JSONB,
      replyTo JSONB
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS unread (
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (fromUser, toUser)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS groups (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      owner TEXT NOT NULL,
      createdAt BIGINT NOT NULL,
      avatarImage TEXT DEFAULT '',
      about TEXT DEFAULT ''
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_members (
      groupId BIGINT NOT NULL,
      login TEXT NOT NULL,
      joinedAt BIGINT NOT NULL,
      PRIMARY KEY (groupId, login)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_messages (
      id BIGSERIAL PRIMARY KEY,
      groupId BIGINT NOT NULL,
      fromUser TEXT NOT NULL,
      text TEXT NOT NULL DEFAULT '',
      time BIGINT NOT NULL,
      edited BOOLEAN NOT NULL DEFAULT FALSE,
      editedAt BIGINT,
      attachment JSONB,
      replyTo JSONB
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_unread (
      groupId BIGINT NOT NULL,
      login TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (groupId, login)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS dm_backgrounds (
      ownerLogin TEXT NOT NULL,
      peerLogin TEXT NOT NULL,
      imageUrl TEXT NOT NULL,
      updatedAt BIGINT NOT NULL,
      PRIMARY KEY (ownerLogin, peerLogin)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      login TEXT NOT NULL,
      sessionHash TEXT NOT NULL,
      createdAt BIGINT NOT NULL,
      expiresAt BIGINT NOT NULL,
      revoked BOOLEAN NOT NULL DEFAULT FALSE
    )
  `);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS customStatus TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatarImage TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS bannerImage TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS profileAbout TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS presence TEXT DEFAULT 'online'`);
  await pool.query(`ALTER TABLE groups ADD COLUMN IF NOT EXISTS avatarImage TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE groups ADD COLUMN IF NOT EXISTS about TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS editedAt BIGINT`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS deliveredAt BIGINT`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS readAt BIGINT`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment JSONB`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS replyTo JSONB`);
  await pool.query(`ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS edited BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS editedAt BIGINT`);
  await pool.query(`ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS attachment JSONB`);
  await pool.query(`ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS replyTo JSONB`);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_friend_requests_to_user ON friend_requests (toUser, createdAt DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_friends_user1 ON friends (user1)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_friends_user2 ON friends (user2)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_pair_time ON messages (fromUser, toUser, time DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_pair_reverse_time ON messages (toUser, fromUser, time DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_to_read ON messages (toUser, fromUser, readAt)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_unread_to_user ON unread (toUser)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_group_members_login ON group_members (login, groupId)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_group_messages_group_time ON group_messages (groupId, time DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_group_unread_login ON group_unread (login, groupId)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sessions_login_expires ON sessions (login, expiresAt)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions (sessionHash)`);

  await pool.query(`DELETE FROM sessions WHERE expiresAt < $1`, [Date.now()]);
}

function send(ws, data) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
    return true;
  }
  return false;
}

const clients = new Map();
const pendingCalls = new Map();
const activeCalls = new Map();

function buildAvatar(login, nickname = '', avatarImage = '') {
  const avatar = typeof avatarImage === 'string' ? avatarImage.trim() : '';
  return {
    login,
    nickname: nickname || login,
    image: avatar,
    letter: (nickname || login || '?').trim().charAt(0).toUpperCase() || '?'
  };
}

function mapUserRow(row) {
  return {
    login: row.login,
    nickname: row.nickname || row.login,
    status: row.status || '',
    customStatus: row.customstatus || '',
    avatarImage: row.avatarimage || '',
    bannerImage: row.bannerimage || '',
    about: row.profileabout || '',
    presence: row.presence || 'online',
    online: isUserOnline(row.login),
    avatar: buildAvatar(row.login, row.nickname, row.avatarimage)
  };
}

async function getUserPublic(login, viewerLogin = null) {
  const result = await pool.query(`
    SELECT login, nickname, status, customStatus, avatarImage, bannerImage, profileAbout, presence
    FROM users
    WHERE login = $1
    LIMIT 1
  `, [login]);
  const row = result.rows[0];
  if (!row) return null;
  const user = mapUserRow(row);
  if (!viewerLogin || viewerLogin === login || await areFriends(viewerLogin, login)) {
    return user;
  }
  return {
    login: user.login,
    nickname: user.nickname,
    status: '',
    customStatus: '',
    avatarImage: user.avatarImage,
    bannerImage: '',
    about: '',
    presence: user.presence,
    online: user.online,
    avatar: user.avatar
  };
}

function isUserOnline(login) {
  for (const [ws, info] of clients.entries()) {
    if (info?.login === login && ws.readyState === WebSocket.OPEN) return true;
  }
  return false;
}

function getSocketsByLogin(login) {
  const list = [];
  for (const [ws, info] of clients.entries()) {
    if (info?.login === login && ws.readyState === WebSocket.OPEN) list.push(ws);
  }
  return list;
}

function sendToUser(login, data) {
  const sockets = getSocketsByLogin(login);
  let sent = false;
  for (const ws of sockets) {
    sent = send(ws, data) || sent;
  }
  return sent;
}

async function userExists(login) {
  const result = await pool.query(`SELECT 1 FROM users WHERE login = $1 LIMIT 1`, [login]);
  return Boolean(result.rows[0]);
}

async function areFriends(a, b) {
  const result = await pool.query(`
    SELECT 1 FROM friends
    WHERE (user1 = $1 AND user2 = $2) OR (user1 = $2 AND user2 = $1)
    LIMIT 1
  `, [a, b]);
  return Boolean(result.rows[0]);
}

async function getFriendLogins(login) {
  const result = await pool.query(`
    SELECT CASE WHEN user1 = $1 THEN user2 ELSE user1 END AS friend
    FROM friends
    WHERE user1 = $1 OR user2 = $1
    ORDER BY friend
  `, [login]);
  return result.rows.map(row => row.friend);
}

async function getFriendUsers(login) {
  const result = await pool.query(`
    SELECT u.login, u.nickname, u.status, u.customStatus, u.avatarImage, u.bannerImage, u.profileAbout, u.presence
    FROM users u
    WHERE u.login IN (
      SELECT CASE WHEN f.user1 = $1 THEN f.user2 ELSE f.user1 END
      FROM friends f
      WHERE f.user1 = $1 OR f.user2 = $1
    )
    ORDER BY LOWER(u.nickname), LOWER(u.login)
  `, [login]);
  return result.rows.map(mapUserRow);
}

async function getIncomingRequests(login) {
  const result = await pool.query(`
    SELECT u.login, u.nickname, u.status, u.customStatus, u.avatarImage, u.bannerImage, u.profileAbout, u.presence
    FROM friend_requests r
    JOIN users u ON u.login = r.fromUser
    WHERE r.toUser = $1
    ORDER BY r.createdAt DESC
  `, [login]);
  return result.rows.map(mapUserRow);
}

async function getUnreadMap(login) {
  const result = await pool.query(`
    SELECT fromUser, count
    FROM unread
    WHERE toUser = $1
  `, [login]);
  const map = {};
  for (const row of result.rows) map[row.fromuser] = Number(row.count) || 0;
  return map;
}

async function getDmBackgrounds(ownerLogin) {
  const result = await pool.query(`
    SELECT peerLogin, imageUrl
    FROM dm_backgrounds
    WHERE ownerLogin = $1
  `, [ownerLogin]);
  const backgrounds = {};
  for (const row of result.rows) backgrounds[row.peerlogin] = row.imageurl;
  return backgrounds;
}

async function getDialogList(login) {
  const friends = await getFriendUsers(login);
  const unreadMap = await getUnreadMap(login);

  const [messageAgg, groupRows] = await Promise.all([
    pool.query(`
      WITH latest AS (
        SELECT DISTINCT ON (
          CASE WHEN fromUser = $1 THEN toUser ELSE fromUser END
        )
          CASE WHEN fromUser = $1 THEN toUser ELSE fromUser END AS peer,
          id,
          fromUser,
          toUser,
          text,
          time,
          edited,
          editedAt,
          deliveredAt,
          readAt,
          attachment,
          replyTo
        FROM messages
        WHERE fromUser = $1 OR toUser = $1
        ORDER BY
          CASE WHEN fromUser = $1 THEN toUser ELSE fromUser END,
          time DESC,
          id DESC
      )
      SELECT *
      FROM latest
    `, [login]),
    pool.query(`
      SELECT
        g.id,
        g.name,
        g.owner,
        g.createdAt,
        g.avatarImage,
        g.about,
        gu.count AS unread,
        (
          SELECT gm.text
          FROM group_messages gm
          WHERE gm.groupId = g.id
          ORDER BY gm.time DESC, gm.id DESC
          LIMIT 1
        ) AS lastText,
        (
          SELECT gm.time
          FROM group_messages gm
          WHERE gm.groupId = g.id
          ORDER BY gm.time DESC, gm.id DESC
          LIMIT 1
        ) AS lastTime
      FROM groups g
      JOIN group_members gmbr ON gmbr.groupId = g.id
      LEFT JOIN group_unread gu ON gu.groupId = g.id AND gu.login = $1
      WHERE gmbr.login = $1
      ORDER BY COALESCE((
        SELECT gm2.time
        FROM group_messages gm2
        WHERE gm2.groupId = g.id
        ORDER BY gm2.time DESC, gm2.id DESC
        LIMIT 1
      ), g.createdAt) DESC
    `, [login])
  ]);

  const latestByPeer = new Map();
  for (const row of messageAgg.rows) {
    latestByPeer.set(row.peer, {
      id: Number(row.id),
      from: row.fromuser,
      to: row.touser,
      text: row.text || '',
      time: Number(row.time) || 0,
      edited: Boolean(row.edited),
      editedAt: row.editedat ? Number(row.editedat) : null,
      deliveredAt: row.deliveredat ? Number(row.deliveredat) : null,
      readAt: row.readat ? Number(row.readat) : null,
      attachment: row.attachment || null,
      replyTo: row.replyto || null
    });
  }

  const dms = friends.map(friend => ({
    type: 'dm',
    with: friend.login,
    user: friend,
    unread: unreadMap[friend.login] || 0,
    lastMessage: latestByPeer.get(friend.login) || null
  }));

  const groups = groupRows.rows.map(row => ({
    type: 'group',
    id: Number(row.id),
    name: row.name,
    owner: row.owner,
    createdAt: Number(row.createdat) || 0,
    avatarImage: row.avatarimage || '',
    about: row.about || '',
    unread: Number(row.unread) || 0,
    lastMessage: row.lasttime ? {
      text: row.lasttext || '',
      time: Number(row.lasttime) || 0
    } : null
  }));

  dms.sort((a, b) => (b.lastMessage?.time || 0) - (a.lastMessage?.time || 0));
  return { dms, groups };
}

async function getMessagesForUsers(a, b, limit = CHAT_HISTORY_LIMIT) {
  const safeLimit = Math.max(20, Math.min(Number(limit) || CHAT_HISTORY_LIMIT, CHAT_HISTORY_LIMIT));
  const result = await pool.query(`
    SELECT id, fromUser, toUser, text, time, edited, editedAt, deliveredAt, readAt, attachment, replyTo
    FROM messages
    WHERE (fromUser = $1 AND toUser = $2) OR (fromUser = $2 AND toUser = $1)
    ORDER BY time DESC, id DESC
    LIMIT $3
  `, [a, b, safeLimit]);

  const users = await pool.query(`
    SELECT login, nickname, avatarImage
    FROM users
    WHERE login = $1 OR login = $2
  `, [a, b]);
  const usersMap = new Map(users.rows.map(row => [row.login, row]));

  return result.rows.reverse().map(row => {
    const author = usersMap.get(row.fromuser) || { login: row.fromuser, nickname: row.fromuser, avatarimage: '' };
    let receiptStatus = 'pending';
    if (row.readat) receiptStatus = 'read';
    else if (row.deliveredat) receiptStatus = 'sent';

    return {
      id: Number(row.id),
      from: row.fromuser,
      to: row.touser,
      text: row.text || '',
      time: Number(row.time) || 0,
      edited: Boolean(row.edited),
      editedAt: row.editedat ? Number(row.editedat) : null,
      deliveredAt: row.deliveredat ? Number(row.deliveredat) : null,
      readAt: row.readat ? Number(row.readat) : null,
      receiptStatus,
      attachment: row.attachment || null,
      replyTo: row.replyto || null,
      fromNick: author.nickname || row.fromuser,
      avatar: buildAvatar(author.login, author.nickname, author.avatarimage)
    };
  });
}

async function getGroupMembers(groupId) {
  const result = await pool.query(`
    SELECT u.login, u.nickname, u.status, u.customStatus, u.avatarImage, u.bannerImage, u.profileAbout, u.presence
    FROM group_members gm
    JOIN users u ON u.login = gm.login
    WHERE gm.groupId = $1
    ORDER BY LOWER(u.nickname), LOWER(u.login)
  `, [groupId]);
  return result.rows.map(mapUserRow);
}

async function getGroupMessages(groupId, limit = CHAT_HISTORY_LIMIT) {
  const safeLimit = Math.max(20, Math.min(Number(limit) || CHAT_HISTORY_LIMIT, CHAT_HISTORY_LIMIT));
  const result = await pool.query(`
    SELECT gm.id, gm.groupId, gm.fromUser, gm.text, gm.time, gm.edited, gm.editedAt, gm.attachment, gm.replyTo,
           u.nickname, u.avatarImage
    FROM group_messages gm
    JOIN users u ON u.login = gm.fromUser
    WHERE gm.groupId = $1
    ORDER BY gm.time DESC, gm.id DESC
    LIMIT $2
  `, [groupId, safeLimit]);

  return result.rows.reverse().map(row => ({
    id: Number(row.id),
    groupId: Number(row.groupid),
    from: row.fromuser,
    text: row.text || '',
    time: Number(row.time) || 0,
    edited: Boolean(row.edited),
    editedAt: row.editedat ? Number(row.editedat) : null,
    attachment: row.attachment || null,
    replyTo: row.replyto || null,
    fromNick: row.nickname || row.fromuser,
    avatar: buildAvatar(row.fromuser, row.nickname, row.avatarimage)
  }));
}

async function notifyReceiptUpdate(fromUser, toUser, ids, status) {
  if (!Array.isArray(ids) || !ids.length) return;
  sendToUser(fromUser, {
    type: 'receipt_update',
    with: toUser,
    ids,
    status
  });
}

function clearPendingBetween(a, b) {
  if (pendingCalls.get(a) === b) pendingCalls.delete(a);
  if (pendingCalls.get(b) === a) pendingCalls.delete(b);
}

function clearActiveBetween(a, b) {
  if (activeCalls.get(a) === b) activeCalls.delete(a);
  if (activeCalls.get(b) === a) activeCalls.delete(b);
}

async function broadcastOnlineFriends() {
  const uniqueLogins = new Set();
  for (const info of clients.values()) {
    if (info?.login) uniqueLogins.add(info.login);
  }

  await Promise.all([...uniqueLogins].map(async login => {
    const friends = await getFriendUsers(login);
    sendToUser(login, {
      type: 'friends_list',
      friends
    });
  }));
}

function requireActionAllowed(ws, ip, action) {
  if (recordActionAttempt(ip, action)) {
    send(ws, { type: 'error', message: 'Слишком много действий. Попробуй позже.' });
    return false;
  }
  return true;
}

wss.on('connection', (ws, req) => {
  const clientIp = getClientIp(req);
  let userLogin = null;

  ws.on('message', async raw => {
    try {
      let data = null;
      try {
        data = JSON.parse(String(raw));
      } catch {
        return;
      }
      if (!data || typeof data !== 'object') return;

      if (data.type === 'register') {
        if (isRateLimited(clientIp)) {
          send(ws, { type: 'error', message: 'Слишком много попыток. Попробуй позже.' });
          return;
        }

        const login = sanitizeLogin(data.login);
        const password = typeof data.password === 'string' ? data.password : '';
        const nickname = sanitizeName(data.nickname || login, MAX_NICKNAME_LENGTH) || login;

        if (!login || password.length < 4) {
          recordAuthAttempt(clientIp, false);
          send(ws, { type: 'error', message: 'Неверные данные регистрации' });
          return;
        }

        const exists = await pool.query(`SELECT 1 FROM users WHERE login = $1 LIMIT 1`, [login]);
        if (exists.rows[0]) {
          recordAuthAttempt(clientIp, false);
          send(ws, { type: 'error', message: 'Логин уже занят' });
          return;
        }

        const hash = await bcrypt.hash(password, 10);
        await pool.query(`
          INSERT INTO users (login, password, nickname, status, customStatus, avatarImage, bannerImage, profileAbout, presence)
          VALUES ($1, $2, $3, '', '', '', '', '', 'online')
        `, [login, hash, nickname]);

        const token = await issueSessionToken(login);
        const me = await getUserPublic(login, login);

        userLogin = login;
        clients.set(ws, { login, sessionId: token.split('.').slice(-3, -2)[0] });

        recordAuthAttempt(clientIp, true);

        send(ws, {
          type: 'login_ok',
          me,
          token,
          iceServers: getIceServers(),
          dialogs: { dms: [], groups: [] },
          unread: {},
          requests: [],
          backgrounds: {}
        });

        await broadcastOnlineFriends();
        return;
      }

      if (data.type === 'login') {
        if (isRateLimited(clientIp)) {
          send(ws, { type: 'error', message: 'Слишком много попыток. Попробуй позже.' });
          return;
        }

        const login = sanitizeLogin(data.login);
        const password = typeof data.password === 'string' ? data.password : '';

        if (!login || !password) {
          recordAuthAttempt(clientIp, false);
          send(ws, { type: 'error', message: 'Неверный логин или пароль' });
          return;
        }

        const result = await pool.query(`
          SELECT login, password, nickname, status, customStatus, avatarImage, bannerImage, profileAbout, presence
          FROM users
          WHERE login = $1
          LIMIT 1
        `, [login]);
        const row = result.rows[0];
        if (!row) {
          recordAuthAttempt(clientIp, false);
          send(ws, { type: 'error', message: 'Неверный логин или пароль' });
          return;
        }

        const valid = await bcrypt.compare(password, row.password);
        if (!valid) {
          recordAuthAttempt(clientIp, false);
          send(ws, { type: 'error', message: 'Неверный логин или пароль' });
          return;
        }

        const token = await issueSessionToken(login);
        const me = mapUserRow(row);

        userLogin = login;
        clients.set(ws, { login, sessionId: token.split('.').slice(-3, -2)[0] });

        recordAuthAttempt(clientIp, true);

        const [dialogs, unread, requests, backgrounds] = await Promise.all([
          getDialogList(login),
          getUnreadMap(login),
          getIncomingRequests(login),
          getDmBackgrounds(login)
        ]);

        send(ws, {
          type: 'login_ok',
          me,
          token,
          iceServers: getIceServers(),
          dialogs,
          unread,
          requests,
          backgrounds
        });

        await broadcastOnlineFriends();
        return;
      }

      if (data.type === 'restore_session') {
        const token = typeof data.token === 'string' ? data.token.trim() : '';
        const session = await verifySessionToken(token);
        if (!session?.login) {
          send(ws, { type: 'session_invalid' });
          return;
        }

        const result = await pool.query(`
          SELECT login, nickname, status, customStatus, avatarImage, bannerImage, profileAbout, presence
          FROM users
          WHERE login = $1
          LIMIT 1
        `, [session.login]);
        const row = result.rows[0];
        if (!row) {
          send(ws, { type: 'session_invalid' });
          return;
        }

        userLogin = session.login;
        clients.set(ws, { login: session.login, sessionId: session.sessionId });

        const me = mapUserRow(row);
        const [dialogs, unread, requests, backgrounds] = await Promise.all([
          getDialogList(session.login),
          getUnreadMap(session.login),
          getIncomingRequests(session.login),
          getDmBackgrounds(session.login)
        ]);

        send(ws, {
          type: 'login_ok',
          me,
          token,
          iceServers: getIceServers(),
          dialogs,
          unread,
          requests,
          backgrounds
        });

        await broadcastOnlineFriends();
        return;
      }

      if (!userLogin) return;

      const meResult = await pool.query(`
        SELECT login, nickname, status, customStatus, avatarImage, bannerImage, profileAbout, presence
        FROM users
        WHERE login = $1
        LIMIT 1
      `, [userLogin]);
      const me = mapUserRow(meResult.rows[0] || { login: userLogin, nickname: userLogin });

      if (data.type === 'logout') {
        const sessionId = clients.get(ws)?.sessionId;
        if (sessionId) {
          await pool.query(`UPDATE sessions SET revoked = TRUE WHERE id = $1 AND login = $2`, [sessionId, userLogin]);
        }
        send(ws, { type: 'logged_out' });
        ws.close();
        return;
      }

      if (data.type === 'refresh_sidebar') {
        const [dialogs, unread, requests] = await Promise.all([
          getDialogList(userLogin),
          getUnreadMap(userLogin),
          getIncomingRequests(userLogin)
        ]);
        send(ws, { type: 'dialogs', ...dialogs });
        send(ws, { type: 'unread_update', unread });
        send(ws, { type: 'friend_requests', requests });
        return;
      }

      if (data.type === 'search_users') {
        const query = sanitizeLogin(data.query || '');
        if (!query) {
          send(ws, { type: 'search_results', users: [] });
          return;
        }
        const result = await pool.query(`
          SELECT login, nickname, status, customStatus, avatarImage, bannerImage, profileAbout, presence
          FROM users
          WHERE login ILIKE $1 OR nickname ILIKE $1
          ORDER BY login
          LIMIT 20
        `, [`%${query}%`]);

        const friends = new Set(await getFriendLogins(userLogin));
        const incoming = new Set((await getIncomingRequests(userLogin)).map(u => u.login));
        const outgoingRes = await pool.query(`SELECT toUser FROM friend_requests WHERE fromUser = $1`, [userLogin]);
        const outgoing = new Set(outgoingRes.rows.map(r => r.touser));

        const users = result.rows
          .filter(row => row.login !== userLogin)
          .map(row => ({
            ...mapUserRow(row),
            isFriend: friends.has(row.login),
            incomingRequest: incoming.has(row.login),
            outgoingRequest: outgoing.has(row.login)
          }));

        send(ws, { type: 'search_results', users });
        return;
      }

      if (data.type === 'friend_request') {
        if (!requireActionAllowed(ws, clientIp, 'friend_request')) return;
        const targetLogin = sanitizeLogin(data.to);
        if (!targetLogin || targetLogin === userLogin) return;
        if (!(await userExists(targetLogin))) {
          send(ws, { type: 'error', message: 'Пользователь не найден' });
          return;
        }
        if (await areFriends(userLogin, targetLogin)) {
          send(ws, { type: 'error', message: 'Вы уже друзья' });
          return;
        }

        await pool.query(`
          INSERT INTO friend_requests (fromUser, toUser, createdAt)
          VALUES ($1, $2, $3)
          ON CONFLICT (fromUser, toUser) DO NOTHING
        `, [userLogin, targetLogin, Date.now()]);

        sendToUser(targetLogin, {
          type: 'friend_requests',
          requests: await getIncomingRequests(targetLogin)
        });
        return;
      }

      if (data.type === 'accept_friend') {
        const otherLogin = sanitizeLogin(data.from);
        if (!otherLogin || otherLogin === userLogin) return;

        const reqExists = await pool.query(`
          SELECT 1 FROM friend_requests
          WHERE fromUser = $1 AND toUser = $2
          LIMIT 1
        `, [otherLogin, userLogin]);

        if (!reqExists.rows[0]) return;

        await pool.query(`DELETE FROM friend_requests WHERE fromUser = $1 AND toUser = $2`, [otherLogin, userLogin]);
        await pool.query(`
          INSERT INTO friends (user1, user2)
          VALUES ($1, $2), ($2, $1)
          ON CONFLICT DO NOTHING
        `, [userLogin, otherLogin]);

        send(ws, { type: 'friend_requests', requests: await getIncomingRequests(userLogin) });
        send(ws, { type: 'friends_list', friends: await getFriendUsers(userLogin) });
        sendToUser(otherLogin, { type: 'friends_list', friends: await getFriendUsers(otherLogin) });
        sendToUser(otherLogin, { type: 'friend_request_accepted', by: userLogin });
        await broadcastOnlineFriends();
        return;
      }

      if (data.type === 'decline_friend') {
        const otherLogin = sanitizeLogin(data.from);
        if (!otherLogin || otherLogin === userLogin) return;
        await pool.query(`DELETE FROM friend_requests WHERE fromUser = $1 AND toUser = $2`, [otherLogin, userLogin]);
        send(ws, { type: 'friend_requests', requests: await getIncomingRequests(userLogin) });
        return;
      }

      if (data.type === 'update_profile') {
        if (!requireActionAllowed(ws, clientIp, 'update_profile')) return;
        const nickname = sanitizeName(data.nickname || userLogin, MAX_NICKNAME_LENGTH) || userLogin;
        const status = sanitizeText(data.status || '', 80);
        const customStatus = sanitizeText(data.customStatus || '', 120);
        const about = sanitizeText(data.about || '', 600);
        const presenceAllowed = new Set(['online', 'idle', 'dnd', 'invisible']);
        const presence = presenceAllowed.has(String(data.presence || '').trim()) ? String(data.presence).trim() : 'online';

        await pool.query(`
          UPDATE users
          SET nickname = $1,
              status = $2,
              customStatus = $3,
              profileAbout = $4,
              presence = $5
          WHERE login = $6
        `, [nickname, status, customStatus, about, presence, userLogin]);

        const updated = await getUserPublic(userLogin, userLogin);
        send(ws, { type: 'profile_updated', me: updated });
        await broadcastOnlineFriends();
        return;
      }

      if (data.type === 'update_avatar') {
        if (!requireActionAllowed(ws, clientIp, 'update_avatar')) return;
        const avatarImage = typeof data.avatarImage === 'string' ? data.avatarImage.trim().slice(0, 500) : '';
        await pool.query(`UPDATE users SET avatarImage = $1 WHERE login = $2`, [avatarImage, userLogin]);
        const updated = await getUserPublic(userLogin, userLogin);
        send(ws, { type: 'profile_updated', me: updated });
        await broadcastOnlineFriends();
        return;
      }

      if (data.type === 'update_banner') {
        if (!requireActionAllowed(ws, clientIp, 'update_banner')) return;
        const bannerImage = typeof data.bannerImage === 'string' ? data.bannerImage.trim().slice(0, 500) : '';
        await pool.query(`UPDATE users SET bannerImage = $1 WHERE login = $2`, [bannerImage, userLogin]);
        const updated = await getUserPublic(userLogin, userLogin);
        send(ws, { type: 'profile_updated', me: updated });
        return;
      }

      if (data.type === 'set_dm_background') {
        const peerLogin = sanitizeLogin(data.with);
        const imageUrl = typeof data.imageUrl === 'string' ? data.imageUrl.trim().slice(0, 500) : '';
        if (!peerLogin || !imageUrl) return;
        if (!(await areFriends(userLogin, peerLogin))) return;

        await pool.query(`
          INSERT INTO dm_backgrounds (ownerLogin, peerLogin, imageUrl, updatedAt)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (ownerLogin, peerLogin)
          DO UPDATE SET imageUrl = EXCLUDED.imageUrl, updatedAt = EXCLUDED.updatedAt
        `, [userLogin, peerLogin, imageUrl, Date.now()]);

        send(ws, {
          type: 'dm_backgrounds',
          backgrounds: await getDmBackgrounds(userLogin)
        });
        return;
      }

      if (data.type === 'create_group') {
        if (!requireActionAllowed(ws, clientIp, 'create_group')) return;
        const name = sanitizeName(data.name, MAX_GROUP_NAME_LENGTH);
        const members = Array.isArray(data.members) ? data.members.map(sanitizeLogin).filter(Boolean) : [];
        const uniqueMembers = [...new Set([userLogin, ...members.filter(login => login !== userLogin)])];

        if (!name || uniqueMembers.length < 2) {
          send(ws, { type: 'error', message: 'Неверные данные группы' });
          return;
        }

        const friendLogins = new Set(await getFriendLogins(userLogin));
        for (const member of uniqueMembers) {
          if (member !== userLogin && !friendLogins.has(member)) {
            send(ws, { type: 'error', message: 'В группу можно добавить только друзей' });
            return;
          }
        }

        const createdAt = Date.now();
        const groupResult = await pool.query(`
          INSERT INTO groups (name, owner, createdAt, avatarImage, about)
          VALUES ($1, $2, $3, '', '')
          RETURNING id
        `, [name, userLogin, createdAt]);
        const groupId = Number(groupResult.rows[0].id);

        for (const login of uniqueMembers) {
          await pool.query(`
            INSERT INTO group_members (groupId, login, joinedAt)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
          `, [groupId, login, createdAt]);
          await pool.query(`
            INSERT INTO group_unread (groupId, login, count)
            VALUES ($1, $2, 0)
            ON CONFLICT DO NOTHING
          `, [groupId, login]);
        }

        for (const login of uniqueMembers) {
          const dialogs = await getDialogList(login);
          sendToUser(login, { type: 'dialogs', ...dialogs });
        }
        return;
      }

      if (data.type === 'get_group_messages') {
        if (!requireActionAllowed(ws, clientIp, 'get_group_messages')) return;
        const groupId = Number(data.groupId);
        if (!Number.isFinite(groupId)) return;

        const memberRes = await pool.query(`
          SELECT 1 FROM group_members WHERE groupId = $1 AND login = $2 LIMIT 1
        `, [groupId, userLogin]);
        if (!memberRes.rows[0]) return;

        const messages = await getGroupMessages(groupId);
        send(ws, { type: 'group_messages', groupId, messages });

        await pool.query(`
          UPDATE group_unread SET count = 0 WHERE groupId = $1 AND login = $2
        `, [groupId, userLogin]);
        const dialogs = await getDialogList(userLogin);
        send(ws, { type: 'dialogs', ...dialogs });
        return;
      }

      if (data.type === 'group_message') {
        if (!requireActionAllowed(ws, clientIp, 'group_message')) return;
        const groupId = Number(data.groupId);
        const text = sanitizeText(data.text);
        const attachment = sanitizeAttachmentPayload(data.attachment);
        const replyTo = sanitizeReplyPayload(data.replyTo);
        if (!Number.isFinite(groupId) || (!text && !attachment)) return;

        const groupRes = await pool.query(`SELECT id FROM groups WHERE id = $1 LIMIT 1`, [groupId]);
        if (!groupRes.rows[0]) return;

        const memberRes = await pool.query(`SELECT 1 FROM group_members WHERE groupId = $1 AND login = $2 LIMIT 1`, [groupId, userLogin]);
        if (!memberRes.rows[0]) return;

        const time = Date.now();
        const inserted = await pool.query(`
          INSERT INTO group_messages (groupId, fromUser, text, time, edited, editedAt, attachment, replyTo)
          VALUES ($1, $2, $3, $4, FALSE, NULL, $5::jsonb, $6::jsonb)
          RETURNING id
        `, [groupId, userLogin, text, time, attachment ? JSON.stringify(attachment) : null, replyTo ? JSON.stringify(replyTo) : null]);
        const messageId = Number(inserted.rows[0].id);

        await pool.query(`
          UPDATE group_unread
          SET count = count + 1
          WHERE groupId = $1 AND login <> $2
        `, [groupId, userLogin]);

        const payload = {
          type: 'group_message',
          id: messageId,
          groupId,
          from: userLogin,
          text,
          time,
          edited: false,
          editedAt: null,
          attachment,
          replyTo,
          fromNick: me.nickname,
          avatar: buildAvatar(userLogin, me.nickname, me.avatarImage)
        };

        const membersRes = await pool.query(`SELECT login FROM group_members WHERE groupId = $1`, [groupId]);
        for (const row of membersRes.rows) {
          sendToUser(row.login, payload);
          const dialogs = await getDialogList(row.login);
          sendToUser(row.login, { type: 'dialogs', ...dialogs });
        }
        return;
      }

      if (data.type === 'edit_group_message') {
        if (!requireActionAllowed(ws, clientIp, 'edit_group_message')) return;
        const id = Number(data.id);
        const newText = sanitizeText(data.text);
        if (!Number.isFinite(id) || !newText) return;

        const result = await pool.query(`
          SELECT id, groupId, fromUser
          FROM group_messages
          WHERE id = $1
          LIMIT 1
        `, [id]);
        const row = result.rows[0];
        if (!row || row.fromuser !== userLogin) return;

        const editedAt = Date.now();
        await pool.query(`
          UPDATE group_messages
          SET text = $1, edited = TRUE, editedAt = $2
          WHERE id = $3
        `, [newText, editedAt, id]);

        const membersRes = await pool.query(`SELECT login FROM group_members WHERE groupId = $1`, [row.groupid]);
        for (const member of membersRes.rows) {
          sendToUser(member.login, {
            type: 'group_message_edited',
            id,
            groupId: Number(row.groupid),
            text: newText,
            edited: true,
            editedAt
          });
        }
        return;
      }

      if (data.type === 'delete_group_message') {
        if (!requireActionAllowed(ws, clientIp, 'delete_group_message')) return;
        const id = Number(data.id);
        if (!Number.isFinite(id)) return;

        const result = await pool.query(`
          SELECT id, groupId, fromUser
          FROM group_messages
          WHERE id = $1
          LIMIT 1
        `, [id]);
        const row = result.rows[0];
        if (!row || row.fromuser !== userLogin) return;

        await pool.query(`DELETE FROM group_messages WHERE id = $1`, [id]);

        const membersRes = await pool.query(`SELECT login FROM group_members WHERE groupId = $1`, [row.groupid]);
        for (const member of membersRes.rows) {
          sendToUser(member.login, {
            type: 'group_message_deleted',
            id,
            groupId: Number(row.groupid)
          });
        }
        return;
      }

      if (data.type === 'update_group') {
        if (!requireActionAllowed(ws, clientIp, 'update_group')) return;
        const groupId = Number(data.groupId);
        if (!Number.isFinite(groupId)) return;

        const groupRes = await pool.query(`
          SELECT id, owner
          FROM groups
          WHERE id = $1
          LIMIT 1
        `, [groupId]);
        const group = groupRes.rows[0];
        if (!group || group.owner !== userLogin) return;

        const name = sanitizeName(data.name, MAX_GROUP_NAME_LENGTH);
        const about = sanitizeText(data.about, 600);
        const avatarImage = typeof data.avatarImage === 'string' ? data.avatarImage.trim().slice(0, 500) : '';

        await pool.query(`
          UPDATE groups
          SET name = COALESCE(NULLIF($1, ''), name),
              about = $2,
              avatarImage = $3
          WHERE id = $4
        `, [name, about, avatarImage, groupId]);

        const membersRes = await pool.query(`SELECT login FROM group_members WHERE groupId = $1`, [groupId]);
        for (const member of membersRes.rows) {
          const dialogs = await getDialogList(member.login);
          sendToUser(member.login, { type: 'dialogs', ...dialogs });
        }
        return;
      }

      if (data.type === 'add_group_members') {
        if (!requireActionAllowed(ws, clientIp, 'add_group_members')) return;
        const groupId = Number(data.groupId);
        const members = Array.isArray(data.members) ? data.members.map(sanitizeLogin).filter(Boolean) : [];
        if (!Number.isFinite(groupId) || !members.length) return;

        const groupRes = await pool.query(`
          SELECT id, owner
          FROM groups
          WHERE id = $1
          LIMIT 1
        `, [groupId]);
        const group = groupRes.rows[0];
        if (!group || group.owner !== userLogin) return;

        const friendLogins = new Set(await getFriendLogins(userLogin));
        for (const login of members) {
          if (!friendLogins.has(login)) {
            send(ws, { type: 'error', message: 'В группу можно добавить только друзей' });
            return;
          }
        }

        const joinedAt = Date.now();
        for (const login of [...new Set(members)]) {
          await pool.query(`
            INSERT INTO group_members (groupId, login, joinedAt)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
          `, [groupId, login, joinedAt]);
          await pool.query(`
            INSERT INTO group_unread (groupId, login, count)
            VALUES ($1, $2, 0)
            ON CONFLICT DO NOTHING
          `, [groupId, login]);
        }

        const membersRes = await pool.query(`SELECT login FROM group_members WHERE groupId = $1`, [groupId]);
        for (const member of membersRes.rows) {
          const dialogs = await getDialogList(member.login);
          sendToUser(member.login, { type: 'dialogs', ...dialogs });
        }
        return;
      }

      if (data.type === 'remove_group_member') {
        if (!requireActionAllowed(ws, clientIp, 'remove_group_member')) return;
        const groupId = Number(data.groupId);
        const targetLogin = sanitizeLogin(data.login);
        if (!Number.isFinite(groupId) || !targetLogin) return;

        const groupRes = await pool.query(`
          SELECT id, owner
          FROM groups
          WHERE id = $1
          LIMIT 1
        `, [groupId]);
        const group = groupRes.rows[0];
        if (!group || group.owner !== userLogin || targetLogin === userLogin) return;

        await pool.query(`DELETE FROM group_members WHERE groupId = $1 AND login = $2`, [groupId, targetLogin]);
        await pool.query(`DELETE FROM group_unread WHERE groupId = $1 AND login = $2`, [groupId, targetLogin]);

        const membersRes = await pool.query(`SELECT login FROM group_members WHERE groupId = $1`, [groupId]);
        for (const member of membersRes.rows) {
          const dialogs = await getDialogList(member.login);
          sendToUser(member.login, { type: 'dialogs', ...dialogs });
        }
        const dialogs = await getDialogList(targetLogin);
        sendToUser(targetLogin, { type: 'dialogs', ...dialogs });
        return;
      }

      if (data.type === 'leave_group') {
        if (!requireActionAllowed(ws, clientIp, 'leave_group')) return;
        const groupId = Number(data.groupId);
        if (!Number.isFinite(groupId)) return;

        const groupRes = await pool.query(`
          SELECT id, owner
          FROM groups
          WHERE id = $1
          LIMIT 1
        `, [groupId]);
        const group = groupRes.rows[0];
        if (!group) return;
        if (group.owner === userLogin) {
          send(ws, { type: 'error', message: 'Владелец не может выйти из группы' });
          return;
        }

        await pool.query(`DELETE FROM group_members WHERE groupId = $1 AND login = $2`, [groupId, userLogin]);
        await pool.query(`DELETE FROM group_unread WHERE groupId = $1 AND login = $2`, [groupId, userLogin]);

        const membersRes = await pool.query(`SELECT login FROM group_members WHERE groupId = $1`, [groupId]);
        for (const member of membersRes.rows) {
          const dialogs = await getDialogList(member.login);
          sendToUser(member.login, { type: 'dialogs', ...dialogs });
        }
        const dialogs = await getDialogList(userLogin);
        send(ws, { type: 'dialogs', ...dialogs });
        return;
      }

      if (data.type === 'get_messages') {
        if (!requireActionAllowed(ws, clientIp, 'get_messages')) return;
        const peerLogin = sanitizeLogin(data.with);
        if (!peerLogin || peerLogin === userLogin) return;
        if (!(await areFriends(userLogin, peerLogin))) return;

        const messages = await getMessagesForUsers(userLogin, peerLogin);
        send(ws, { type: 'messages', with: peerLogin, messages });

        const now = Date.now();
        const readResult = await pool.query(`
          UPDATE messages
          SET deliveredAt = COALESCE(deliveredAt, $3),
              readAt = COALESCE(readAt, $3)
          WHERE fromUser = $1 AND toUser = $2 AND readAt IS NULL
          RETURNING id
        `, [peerLogin, userLogin, now]);

        if (readResult.rows.length) {
          await notifyReceiptUpdate(peerLogin, userLogin, readResult.rows.map(row => row.id), 'read');
        }

        await pool.query(`DELETE FROM unread WHERE fromUser = $1 AND toUser = $2`, [peerLogin, userLogin]);
        send(ws, { type: 'unread_update', unread: await getUnreadMap(userLogin) });
        return;
      }

      if (data.type === 'call_start') {
        if (!requireActionAllowed(ws, clientIp, 'call_start')) return;
        const targetLogin = sanitizeLogin(data.to);
        if (!targetLogin || targetLogin === userLogin) return;
        if (!(await areFriends(userLogin, targetLogin))) return;

        const busy = activeCalls.has(userLogin) || activeCalls.has(targetLogin) || pendingCalls.has(userLogin) || pendingCalls.has(targetLogin);
        if (busy) {
          send(ws, { type: 'call_ended', reason: 'busy', with: targetLogin });
          return;
        }

        pendingCalls.set(userLogin, targetLogin);
        pendingCalls.set(targetLogin, userLogin);

        const sent = sendToUser(targetLogin, {
          type: 'incoming_call',
          from: userLogin,
          fromNick: me.nickname,
          avatar: buildAvatar(userLogin, me.nickname, me.avatarImage)
        });

        if (!sent) {
          clearPendingBetween(userLogin, targetLogin);
          send(ws, { type: 'call_ended', reason: 'offline', with: targetLogin });
        }
        return;
      }

      if (data.type === 'call_response') {
        if (!requireActionAllowed(ws, clientIp, 'call_response')) return;
        const otherLogin = sanitizeLogin(data.with);
        const accepted = Boolean(data.accepted);
        if (!otherLogin) return;
        if (pendingCalls.get(userLogin) !== otherLogin || pendingCalls.get(otherLogin) !== userLogin) return;

        clearPendingBetween(userLogin, otherLogin);

        if (!accepted) {
          sendToUser(otherLogin, { type: 'call_ended', reason: 'declined', with: userLogin });
          send(ws, { type: 'call_ended', reason: 'declined', with: otherLogin });
          return;
        }

        activeCalls.set(userLogin, otherLogin);
        activeCalls.set(otherLogin, userLogin);

        const iceServers = getIceServers();
        send(ws, { type: 'call_accepted', with: otherLogin, initiator: false, iceServers });
        sendToUser(otherLogin, { type: 'call_accepted', with: userLogin, initiator: true, iceServers });
        return;
      }

      if (data.type === 'call_end') {
        if (!requireActionAllowed(ws, clientIp, 'call_end')) return;
        const otherLogin = sanitizeLogin(data.with);
        if (!otherLogin) return;
        const wasActive = activeCalls.get(userLogin) === otherLogin || activeCalls.get(otherLogin) === userLogin;
        const wasPending = pendingCalls.get(userLogin) === otherLogin || pendingCalls.get(otherLogin) === userLogin;
        if (!wasActive && !wasPending) return;
        clearPendingBetween(userLogin, otherLogin);
        clearActiveBetween(userLogin, otherLogin);
        send(ws, { type: 'call_ended', reason: 'ended', with: otherLogin });
        sendToUser(otherLogin, { type: 'call_ended', reason: 'ended', with: userLogin });
        return;
      }

      if (data.type === 'call_signal') {
        if (!requireActionAllowed(ws, clientIp, 'call_signal')) return;
        const targetLogin = sanitizeLogin(data.to);
        const signal = data.signal && typeof data.signal === 'object' ? data.signal : null;
        if (!targetLogin || !signal) return;
        const activePeer = activeCalls.get(userLogin);
        if (activePeer !== targetLogin || activeCalls.get(targetLogin) !== userLogin) return;
        sendToUser(targetLogin, { type: 'call_signal', from: userLogin, signal });
        return;
      }

      if (data.type === 'get_user_profile') {
        const targetLogin = sanitizeLogin(data.login);
        if (!targetLogin) return;
        const isSelf = targetLogin === userLogin;
        const allowed = isSelf || await areFriends(userLogin, targetLogin);
        if (!allowed) {
          send(ws, { type: 'error', message: 'Профиль недоступен' });
          return;
        }
        const profile = await getUserPublic(targetLogin, userLogin);
        if (profile) send(ws, { type: 'user_profile', user: profile });
        return;
      }

      if (data.type === 'remove_friend') {
        const otherLogin = typeof data.with === 'string' ? data.with.trim() : '';
        if (!otherLogin || otherLogin === userLogin) return;

        await pool.query(`
          DELETE FROM friends
          WHERE (user1 = $1 AND user2 = $2) OR (user1 = $2 AND user2 = $1)
        `, [userLogin, otherLogin]);

        send(ws, { type: 'friends_list', friends: await getFriendUsers(userLogin) });
        sendToUser(otherLogin, { type: 'friends_list', friends: await getFriendUsers(otherLogin) });
        send(ws, { type: 'friend_removed', with: otherLogin });
        sendToUser(otherLogin, { type: 'friend_removed', with: userLogin });
        await broadcastOnlineFriends();
        return;
      }

      if (data.type === 'message') {
        if (!requireActionAllowed(ws, clientIp, 'message')) return;
        const targetLogin = sanitizeLogin(data.to);
        const messageText = sanitizeText(data.text);
        const attachment = sanitizeAttachmentPayload(data.attachment);
        const replyTo = sanitizeReplyPayload(data.replyTo);
        if (!targetLogin || (!messageText && !attachment)) return;
        if (!(await userExists(targetLogin))) return;
        if (!(await areFriends(userLogin, targetLogin))) {
          send(ws, { type: 'error', message: 'Личные сообщения доступны только друзьям' });
          return;
        }

        const messageTime = Date.now();
        const insertResult = await pool.query(`
          INSERT INTO messages (fromUser, toUser, text, time, edited, editedAt, deliveredAt, readAt, attachment, replyTo)
          VALUES ($1, $2, $3, $4, FALSE, NULL, NULL, NULL, $5::jsonb, $6::jsonb)
          RETURNING id
        `, [userLogin, targetLogin, messageText, messageTime, attachment ? JSON.stringify(attachment) : null, replyTo ? JSON.stringify(replyTo) : null]);

        await pool.query(`
          INSERT INTO unread (fromUser, toUser, count)
          VALUES ($1, $2, 1)
          ON CONFLICT (fromUser, toUser)
          DO UPDATE SET count = unread.count + 1
        `, [userLogin, targetLogin]);

        const unreadResult = await pool.query(`SELECT count FROM unread WHERE fromUser = $1 AND toUser = $2`, [userLogin, targetLogin]);
        const unreadCount = unreadResult.rows[0]?.count || 0;
        const messageId = Number(insertResult.rows[0].id);
        let deliveredAt = null;

        const msgData = {
          type: 'message',
          id: messageId,
          from: userLogin,
          to: targetLogin,
          text: messageText,
          time: messageTime,
          edited: false,
          editedAt: null,
          deliveredAt: null,
          readAt: null,
          receiptStatus: 'pending',
          attachment,
          replyTo,
          fromNick: me.nickname,
          avatar: buildAvatar(userLogin, me.nickname, me.avatarImage),
          unread: unreadCount,
          clientMsgId: typeof data.clientMsgId === 'string' ? data.clientMsgId : null
        };

        sendToUser(userLogin, msgData);
        const deliveredNow = sendToUser(targetLogin, msgData);

        if (deliveredNow) {
          deliveredAt = Date.now();
          await pool.query(`UPDATE messages SET deliveredAt = $1 WHERE id = $2 AND deliveredAt IS NULL`, [deliveredAt, messageId]);
          sendToUser(userLogin, {
            type: 'receipt_update',
            with: targetLogin,
            ids: [messageId],
            status: 'sent'
          });
        }
        return;
      }

      if (data.type === 'delete_message') {
        if (!requireActionAllowed(ws, clientIp, 'delete_message')) return;
        const id = Number(data.id);
        if (!Number.isFinite(id)) return;

        const existing = await pool.query(`
          SELECT id, fromUser, toUser
          FROM messages
          WHERE id = $1
          LIMIT 1
        `, [id]);

        const message = existing.rows[0];
        if (!message || message.fromuser !== userLogin) return;

        await pool.query(`DELETE FROM messages WHERE id = $1`, [id]);

        const payload = {
          type: 'message_deleted',
          id,
          from: message.fromuser,
          to: message.touser
        };

        sendToUser(message.fromuser, payload);
        sendToUser(message.touser, payload);
        return;
      }

      if (data.type === 'typing') {
        if (!requireActionAllowed(ws, clientIp, 'typing')) return;
        if (!data.to || data.to === userLogin) return;
        if (!(await areFriends(userLogin, sanitizeLogin(data.to)))) return;
        sendToUser(data.to, {
          type: 'typing',
          from: userLogin,
          fromNick: me.nickname,
          active: Boolean(data.active)
        });
        return;
      }

      if (data.type === 'edit_message') {
        if (!requireActionAllowed(ws, clientIp, 'edit_message')) return;
        const messageId = Number(data.id);
        const newText = sanitizeText(data.text);
        if (!messageId || !newText) return;

        const messageResult = await pool.query(`SELECT id, fromUser, toUser FROM messages WHERE id = $1 LIMIT 1`, [messageId]);
        const message = messageResult.rows[0];
        if (!message) {
          send(ws, { type: 'error', message: 'Сообщение не найдено' });
          return;
        }
        if (message.fromuser !== userLogin) {
          send(ws, { type: 'error', message: 'Можно редактировать только свои сообщения' });
          return;
        }

        const editedAt = Date.now();
        await pool.query(`UPDATE messages SET text = $1, edited = TRUE, editedAt = $2 WHERE id = $3`, [newText, editedAt, messageId]);

        const payload = {
          type: 'message_edited',
          id: messageId,
          text: newText,
          edited: true,
          editedAt,
          from: userLogin,
          to: message.touser
        };

        sendToUser(userLogin, payload);
        sendToUser(message.touser, payload);
        return;
      }

      if (data.type === 'read') {
        if (!requireActionAllowed(ws, clientIp, 'read')) return;
        const peerLogin = sanitizeLogin(data.from);
        if (!peerLogin) return;
        if (!(await areFriends(userLogin, peerLogin))) return;

        const now = Date.now();
        const readResult = await pool.query(`
          UPDATE messages
          SET deliveredAt = COALESCE(deliveredAt, $3),
              readAt = COALESCE(readAt, $3)
          WHERE fromUser = $1 AND toUser = $2 AND readAt IS NULL
          RETURNING id
        `, [peerLogin, userLogin, now]);

        if (readResult.rows.length) {
          await notifyReceiptUpdate(peerLogin, userLogin, readResult.rows.map(row => row.id), 'read');
        }

        await pool.query(`DELETE FROM unread WHERE fromUser = $1 AND toUser = $2`, [peerLogin, userLogin]);
        send(ws, { type: 'unread_update', unread: await getUnreadMap(userLogin) });
        return;
      }

    } catch (err) {
      console.error('WS message error:', err);
      send(ws, { type: 'error', message: 'Ошибка сервера' });
    }
  });

  ws.on('close', async () => {
    const info = clients.get(ws);
    clients.delete(ws);

    if (userLogin) {
      const pendingPeer = pendingCalls.get(userLogin);
      if (pendingPeer) {
        clearPendingBetween(userLogin, pendingPeer);
        sendToUser(pendingPeer, { type: 'call_ended', reason: 'cancelled', with: userLogin });
      }
      const activePeer = activeCalls.get(userLogin);
      if (activePeer) {
        clearActiveBetween(userLogin, activePeer);
        sendToUser(activePeer, { type: 'call_ended', reason: 'ended', with: userLogin });
      }
    }

    if (info?.sessionId && userLogin) {
      await pool.query(`DELETE FROM sessions WHERE id = $1 AND login = $2 AND revoked = TRUE`, [info.sessionId, userLogin]).catch(() => {});
    }

    try {
      await broadcastOnlineFriends();
    } catch (err) {
      console.error('broadcastOnlineFriends on close error:', err);
    }
  });
});

const PORT = process.env.PORT || 3000;
initDb().then(() => {
  server.listen(PORT, () => {
    console.log('Server started on port ' + PORT);
  });
}).catch(err => {
  console.error('Database init error:', err);
  process.exit(1);
});