const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Load .env if present
try { require('dotenv').config(); } catch {}

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
  call_end: 60,
  group_call_start: 10,
  group_call_join: 20,
  group_call_leave: 30,
  group_call_signal: 600
};
const MAX_MESSAGE_LENGTH = 4000;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_FILENAME_LENGTH = 180;
const MAX_GROUP_NAME_LENGTH = 48;
const CHAT_HISTORY_LIMIT = 200;
const MAX_NICKNAME_LENGTH = 32;
const LOGIN_RE = /^[a-zA-Z0-9_\-.]{3,32}$/;

// pending 2FA logins: login -> { userData, ua, ip }
const pending2FA = new Map();
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

async function issueSessionToken(login, userAgent = '', ip = '') {
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;
  const sessionId = crypto.randomBytes(24).toString('base64url');
  const nonce = crypto.randomBytes(16).toString('base64url');
  const payload = `${login}.${expiresAt}.${sessionId}.${nonce}`;
  const signature = signSessionPayload(payload);

  await pool.query(`
    INSERT INTO sessions (id, login, sessionHash, createdAt, expiresAt, revoked, userAgent, ip)
    VALUES ($1, $2, $3, $4, $5, FALSE, $6, $7)
  `, [sessionId, login, hashSessionId(sessionId), now, expiresAt, userAgent.slice(0, 512), ip.slice(0, 64)]);

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
    return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
  }
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'microphone=(self)');
  res.setHeader('Content-Security-Policy', "default-src 'self' data: blob:; connect-src 'self' wss: ws:; img-src 'self' data: blob:; media-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  next();
});


app.use('/uploads', express.static(uploadsDir, { maxAge: '7d' }));
app.use(express.static(publicDir));
app.use(express.static(__dirname));

app.post('/api/upload', async (req, res) => {
  try {
    const auth = await requireAuthFromRequest(req);
    if (!auth?.login) return res.status(401).json({ error: 'UNAUTHORIZED' });

    const userLogin = auth.login;
    const chatType = String(req.query.chatType || 'dm').trim();
    const to = sanitizeLogin(req.query.to);
    const groupId = Number(req.query.groupId);

    if (chatType === 'dm') {
      if (!to || to === userLogin) return res.status(400).json({ error: 'BAD_TARGET' });
      if (!(await areFriends(userLogin, to))) return res.status(403).json({ error: 'FORBIDDEN' });
    } else if (chatType === 'group') {
      if (!Number.isFinite(groupId) || groupId <= 0) return res.status(400).json({ error: 'BAD_GROUP' });
      if (!(await isGroupMember(groupId, userLogin))) return res.status(403).json({ error: 'FORBIDDEN' });
    } else {
      return res.status(400).json({ error: 'BAD_CHAT_TYPE' });
    }

    const rawHeaderName = typeof req.headers['x-file-name'] === 'string' ? req.headers['x-file-name'] : 'file';
    const originalName = sanitizeFilename(decodeURIComponent(rawHeaderName));
    const mimeType = normalizeMimeType(req.headers['content-type'], originalName);
    const contentLength = Number(req.headers['content-length'] || 0);
    if (Number.isFinite(contentLength) && contentLength > MAX_FILE_SIZE) {
      return res.status(413).json({ error: 'FILE_TOO_LARGE' });
    }

    const fileBuffer = await readRequestBody(req, MAX_FILE_SIZE);
    if (!fileBuffer.length) return res.status(400).json({ error: 'EMPTY_FILE' });

    const ext = getExtension(originalName);
    const diskName = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}${ext}`;
    await fsp.writeFile(path.join(uploadsDir, diskName), fileBuffer);

    const attachment = sanitizeAttachmentPayload({
      name: originalName,
      url: `/uploads/${diskName}`,
      size: fileBuffer.length,
      mimeType
    });

    res.json({ ok: true, attachment });
  } catch (error) {
    if (error?.code === 'FILE_TOO_LARGE') return res.status(413).json({ error: 'FILE_TOO_LARGE' });
    console.error('Upload failed:', error);
    res.status(500).json({ error: 'UPLOAD_FAILED' });
  }
});

app.get('/', (req, res) => {
  if (fs.existsSync(publicIndex)) {
    return res.sendFile(publicIndex);
  }
  return res.sendFile(rootIndex);
});

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL not found in environment variables');
  process.exit(1);
}

let databaseUrl = process.env.DATABASE_URL;

try {
  const url = new URL(databaseUrl);
  url.searchParams.delete('sslmode');
  databaseUrl = url.toString();
} catch (e) {
  console.error('Invalid DATABASE_URL:', e);
}

const pool = new Pool({
  connectionString: databaseUrl,
  ssl: { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      login TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      nickname TEXT NOT NULL,
      avatarImage TEXT,
      bannerImage TEXT,
      status TEXT NOT NULL DEFAULT 'online'
    )
  `);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS bannerImage TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'online'`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      text TEXT NOT NULL,
      time BIGINT NOT NULL,
      edited BOOLEAN NOT NULL DEFAULT FALSE,
      editedAt BIGINT,
      attachment JSONB
    )
  `);

  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS editedAt BIGINT`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS deliveredAt BIGINT`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS readAt BIGINT`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment JSONB`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS replyTo JSONB`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS friends (
      user1 TEXT NOT NULL,
      user2 TEXT NOT NULL,
      UNIQUE(user1, user2)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS friend_requests (
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      UNIQUE(fromUser, toUser)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS unread (
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      UNIQUE(fromUser, toUser)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_groups (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      ownerLogin TEXT NOT NULL,
      createdAt BIGINT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_members (
      groupId BIGINT NOT NULL,
      userLogin TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      joinedAt BIGINT NOT NULL DEFAULT 0,
      UNIQUE(groupId, userLogin)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_messages (
      id BIGSERIAL PRIMARY KEY,
      groupId BIGINT NOT NULL,
      fromUser TEXT NOT NULL,
      text TEXT NOT NULL,
      time BIGINT NOT NULL,
      edited BOOLEAN NOT NULL DEFAULT FALSE,
      editedAt BIGINT,
      attachment JSONB
    )
  `);

  await pool.query(`ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS edited BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS editedAt BIGINT`);
  await pool.query(`ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS attachment JSONB`);
  await pool.query(`ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS replyTo JSONB`);

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
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sessionHash TEXT`);
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS createdAt BIGINT NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS expiresAt BIGINT NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS userAgent TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip TEXT NOT NULL DEFAULT ''`);
  await pool.query(`CREATE INDEX IF NOT EXISTS sessions_login_idx ON sessions(login)`);
  await pool.query(`DELETE FROM sessions WHERE revoked = TRUE OR expiresAt < $1`, [Date.now()]);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_security (
      login TEXT PRIMARY KEY,
      totp_secret TEXT,
      twofa_enabled BOOLEAN NOT NULL DEFAULT FALSE
    )
  `);
  await pool.query(`ALTER TABLE user_security ADD COLUMN IF NOT EXISTS totp_secret TEXT`);
  await pool.query(`ALTER TABLE user_security ADD COLUMN IF NOT EXISTS twofa_enabled BOOLEAN NOT NULL DEFAULT FALSE`);
}

const clients = new Map();
const pendingCalls = new Map();
const activeCalls = new Map();
// groupId (number) -> Set of logins currently in the call
const activeGroupCalls = new Map();

function send(ws, data) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  }
}

function sendToUser(login, data) {
  let delivered = false;
  for (const [ws, info] of clients) {
    if (info.login === login && ws.readyState === WebSocket.OPEN) {
      send(ws, data);
      delivered = true;
    }
  }
  return delivered;
}

function getCallState(login) {
  return { pendingWith: pendingCalls.get(login) || null, activeWith: activeCalls.get(login) || null };
}

function isUserBusy(login) {
  const state = getCallState(login);
  return Boolean(state.pendingWith || state.activeWith);
}

function clearPendingBetween(a, b) {
  if (pendingCalls.get(a) === b) pendingCalls.delete(a);
  if (pendingCalls.get(b) === a) pendingCalls.delete(b);
}

function clearActiveBetween(a, b) {
  if (activeCalls.get(a) === b) activeCalls.delete(a);
  if (activeCalls.get(b) === a) activeCalls.delete(b);
}

function clearAnyCallState(login) {
  const pendingPeer = pendingCalls.get(login);
  if (pendingPeer) clearPendingBetween(login, pendingPeer);
  for (const [key, value] of pendingCalls) {
    if (value === login) pendingCalls.delete(key);
  }
  const activePeer = activeCalls.get(login);
  if (activePeer) clearActiveBetween(login, activePeer);
}

function getMessageReceiptStatus(message) {
  if (message?.readat) return 'read';
  if (message?.deliveredat) return 'sent';
  return 'pending';
}

async function notifyReceiptUpdate(senderLogin, peerLogin, ids, status) {
  if (!senderLogin || !peerLogin || !Array.isArray(ids) || !ids.length) return;
  sendToUser(senderLogin, {
    type: 'receipt_update',
    with: peerLogin,
    ids: ids.map(Number),
    status
  });
}


async function loginSocket(ws, user, userAgent = '', ip = '') {
  const normalizedStatus = normalizeStatus(user.status);
  const token = await issueSessionToken(user.login, userAgent, ip);
  const verifiedToken = await verifySessionToken(token);

  clients.set(ws, {
    login: user.login,
    nickname: user.nickname,
    avatarImage: user.avatarimage,
    bannerImage: user.bannerimage,
    status: normalizedStatus,
    sessionId: verifiedToken?.sessionId || null
  });

  send(ws, {
    type: 'login_ok',
    login: user.login,
    nickname: user.nickname,
    status: normalizedStatus,
    avatar: buildAvatar(user.login, user.nickname, user.avatarimage),
    banner: user.bannerimage || null,
    friends: await getFriendUsers(user.login),
    unread: await getUnreadMap(user.login),
    groups: await getGroupsForUser(user.login),
    token,
    iceServers: getIceServers()
  });

  const requests = await pool.query(`SELECT fromUser FROM friend_requests WHERE toUser = $1`, [user.login]);
  for (const r of requests.rows) {
    send(ws, { type: 'friend_request', from: r.fromuser });
  }
}

async function userExists(login) {
  if (!login) return false;
  const result = await pool.query(`SELECT 1 FROM users WHERE login = $1 LIMIT 1`, [login]);
  return Boolean(result.rows.length);
}

async function areFriends(userA, userB) {
  if (!userA || !userB || userA === userB) return false;
  const result = await pool.query(`
    SELECT 1 FROM friends
    WHERE (user1 = $1 AND user2 = $2) OR (user1 = $2 AND user2 = $1)
    LIMIT 1
  `, [userA, userB]);
  return Boolean(result.rows.length);
}

function requireActionAllowed(ws, ip, action) {
  if (!recordActionAttempt(ip, action)) return true;
  send(ws, { type: 'error', message: 'Слишком много действий. Попробуй чуть позже.' });
  return false;
}

function avatarColor(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  return `hsl(${Math.abs(hash) % 360},70%,55%)`;
}

function buildAvatar(login, nickname, avatarImage = null) {
  return {
    letter: (nickname?.[0] || login?.[0] || '?').toUpperCase(),
    color: avatarColor(login || nickname || '?'),
    image: avatarImage || null
  };
}

function normalizeStatus(status) {
  return ['online', 'idle', 'dnd', 'invisible'].includes(status) ? status : 'online';
}

function getEffectiveStatus(targetLogin, rawStatus, viewerLogin = null) {
  const isOnline = [...clients.values()].some(c => c.login === targetLogin);
  if (!isOnline) return 'offline';
  const normalized = normalizeStatus(rawStatus);
  if (normalized === 'invisible' && viewerLogin !== targetLogin) return 'offline';
  return normalized;
}

async function getUserPublic(login, viewerLogin = null) {
  const result = await pool.query(`SELECT login, nickname, avatarImage, bannerImage, status FROM users WHERE login = $1`, [login]);
  const user = result.rows[0];
  if (!user) return null;
  return {
    login: user.login,
    nickname: user.nickname,
    status: getEffectiveStatus(user.login, user.status, viewerLogin),
    avatar: buildAvatar(user.login, user.nickname, user.avatarimage),
    banner: user.bannerimage || null
  };
}

async function getFriends(login) {
  const result = await pool.query(`
    SELECT user1 AS friend FROM friends WHERE user2 = $1
    UNION
    SELECT user2 AS friend FROM friends WHERE user1 = $1
  `, [login]);
  return result.rows.map(r => r.friend);
}

async function getFriendUsers(login) {
  const friends = await getFriends(login);
  if (!friends.length) return [];
  const users = await Promise.all(friends.map(friendLogin => getUserPublic(friendLogin, login)));
  return users.filter(Boolean);
}

async function getUnreadMap(login) {
  const result = await pool.query(`SELECT fromUser, count FROM unread WHERE toUser = $1`, [login]);
  const unread = {};
  for (const row of result.rows) unread[row.fromuser] = row.count;
  return unread;
}

async function getChatHistory(userA, userB) {
  const result = await pool.query(`
    SELECT id, fromUser, toUser, text, time, edited, editedAt, deliveredAt, readAt, attachment, replyTo
    FROM (
      SELECT id, fromUser, toUser, text, time, edited, editedAt, deliveredAt, readAt, attachment, replyTo
      FROM messages
      WHERE (fromUser = $1 AND toUser = $2)
         OR (fromUser = $2 AND toUser = $1)
      ORDER BY time DESC, id DESC
      LIMIT $3
    ) recent_messages
    ORDER BY time ASC, id ASC
  `, [userA, userB, CHAT_HISTORY_LIMIT]);

  const senders = new Map();
  const messages = [];

  for (const row of result.rows) {
    let sender = senders.get(row.fromuser);
    if (!sender) {
      sender = await getUserPublic(row.fromuser, userA);
      senders.set(row.fromuser, sender);
    }
    messages.push({
      id: Number(row.id),
      from: row.fromuser,
      to: row.touser,
      text: row.text,
      time: Number(row.time),
      edited: Boolean(row.edited),
      editedAt: row.editedat ? Number(row.editedat) : null,
      deliveredAt: row.deliveredat ? Number(row.deliveredat) : null,
      readAt: row.readat ? Number(row.readat) : null,
      receiptStatus: getMessageReceiptStatus(row),
      attachment: sanitizeAttachmentPayload(row.attachment),
      replyTo: sanitizeReplyPayload(row.replyto),
      avatar: sender?.avatar || buildAvatar(row.fromuser, row.fromuser)
    });
  }
  return messages;
}


async function isGroupMember(groupId, login) {
  const result = await pool.query(`
    SELECT 1 FROM group_members WHERE groupId = $1 AND userLogin = $2 LIMIT 1
  `, [groupId, login]);
  return Boolean(result.rows.length);
}

async function getGroupMembers(groupId, viewerLogin = null) {
  const result = await pool.query(`
    SELECT gm.userLogin, gm.role, u.nickname, u.avatarImage, u.status
    FROM group_members gm
    JOIN users u ON u.login = gm.userLogin
    WHERE gm.groupId = $1
    ORDER BY CASE WHEN gm.role = 'owner' THEN 0 ELSE 1 END, u.nickname ASC, u.login ASC
  `, [groupId]);

  return result.rows.map(row => ({
    login: row.userlogin,
    nickname: row.nickname,
    role: row.role,
    status: getEffectiveStatus(row.userlogin, row.status, viewerLogin),
    avatar: buildAvatar(row.userlogin, row.nickname, row.avatarimage)
  }));
}

async function getGroupPublic(groupId, viewerLogin = null) {
  const result = await pool.query(`
    SELECT id, name, ownerLogin, createdAt
    FROM chat_groups
    WHERE id = $1
    LIMIT 1
  `, [groupId]);
  const group = result.rows[0];
  if (!group) return null;

  const members = await getGroupMembers(Number(group.id), viewerLogin);
  return {
    id: Number(group.id),
    name: group.name,
    ownerLogin: group.ownerlogin,
    createdAt: Number(group.createdat),
    members
  };
}

async function getGroupsForUser(login) {
  const result = await pool.query(`
    SELECT g.id
    FROM chat_groups g
    JOIN group_members gm ON gm.groupId = g.id
    WHERE gm.userLogin = $1
    ORDER BY g.createdAt DESC, g.id DESC
  `, [login]);

  const groups = [];
  for (const row of result.rows) {
    const group = await getGroupPublic(Number(row.id), login);
    if (group) groups.push(group);
  }
  return groups;
}

async function getGroupHistory(groupId, viewerLogin = null) {
  const result = await pool.query(`
    SELECT id, groupId, fromUser, text, time, edited, editedAt, attachment, replyTo
    FROM (
      SELECT id, groupId, fromUser, text, time, edited, editedAt, attachment, replyTo
      FROM group_messages
      WHERE groupId = $1
      ORDER BY time DESC, id DESC
      LIMIT $2
    ) recent_group_messages
    ORDER BY time ASC, id ASC
  `, [groupId, CHAT_HISTORY_LIMIT]);

  const senders = new Map();
  const messages = [];
  for (const row of result.rows) {
    let sender = senders.get(row.fromuser);
    if (!sender) {
      sender = await getUserPublic(row.fromuser, viewerLogin);
      senders.set(row.fromuser, sender);
    }
    messages.push({
      id: Number(row.id),
      groupId: Number(row.groupid),
      from: row.fromuser,
      text: row.text,
      time: Number(row.time),
      edited: Boolean(row.edited),
      editedAt: row.editedat ? Number(row.editedat) : null,
      fromNick: sender?.nickname || row.fromuser,
      attachment: sanitizeAttachmentPayload(row.attachment),
      replyTo: sanitizeReplyPayload(row.replyto),
      avatar: sender?.avatar || buildAvatar(row.fromuser, row.fromuser)
    });
  }
  return messages;
}

async function sendGroupList(login) {
  sendToUser(login, { type: 'groups_list', groups: await getGroupsForUser(login) });
}

async function sendGroupToMembers(groupId, data) {
  const result = await pool.query(`SELECT userLogin FROM group_members WHERE groupId = $1`, [groupId]);
  for (const row of result.rows) {
    sendToUser(row.userlogin, data);
  }
}

// Send only to currently online group members (no DB query, uses activeGroupCalls participants)
function sendToGroupMembers(groupId, data) {
  const members = activeGroupCalls.get(groupId);
  if (!members) return;
  for (const login of members) sendToUser(login, data);
}


async function broadcastOnlineFriends() {
  for (const [ws, info] of clients) {
    const friendLogins = await getFriends(info.login);
    const onlineMap = new Map();

    for (const [, other] of clients) {
      if (!friendLogins.includes(other.login)) continue;

      const effectiveStatus = getEffectiveStatus(other.login, other.status, info.login);
      if (effectiveStatus === 'offline') continue;

      if (!onlineMap.has(other.login)) {
        onlineMap.set(other.login, {
          login: other.login,
          nickname: other.nickname,
          status: effectiveStatus,
          avatar: buildAvatar(other.login, other.nickname, other.avatarImage),
          banner: other.bannerImage || null
        });
      }
    }

    send(ws, { type: 'online_friends', users: Array.from(onlineMap.values()) });
  }
}


server.on('upgrade', (req, socket, head) => {
  if (isProduction() && !isSecureRequest(req)) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  const origin = req.headers.origin;
  const host = req.headers.host;
  if (origin && host) {
    try {
      const originUrl = new URL(origin);
      if (originUrl.host !== host) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
        return;
      }
    } catch {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }
  }
});

wss.on('connection', (ws, req) => {
  let userLogin = null;
  const clientIp = getClientIp(req);

  ws.on('message', async msg => {
    let data;
    try {
      data = JSON.parse(msg);
    } catch {
      return;
    }

    try {

      if (data.type === 'register') {
        const login = sanitizeLogin(data.login);
        const password = typeof data.password === 'string' ? data.password : '';

        if (!login || !password) {
          send(ws, { type: 'error', message: 'Введите логин и пароль' });
          return;
        }
        if (password.length < 6) {
          send(ws, { type: 'error', message: 'Пароль слишком короткий' });
          return;
        }

        const exists = await pool.query(`SELECT login FROM users WHERE login = $1`, [login]);
        if (exists.rows.length) {
          send(ws, { type: 'error', message: 'Логин занят' });
          return;
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        await pool.query(`INSERT INTO users (login, password, nickname, avatarImage, status) VALUES ($1, $2, $3, $4, $5)`, [login, hashedPassword, login, null, 'online']);
        send(ws, { type: 'register_ok' });
        return;
      }

      if (data.type === 'login') {
        const login = sanitizeLogin(data.login);
        const password = typeof data.password === 'string' ? data.password : '';

        if (isRateLimited(clientIp)) {
          send(ws, { type: 'error', message: 'Слишком много попыток входа. Попробуй чуть позже.' });
          return;
        }

        if (!login || !password) {
          send(ws, { type: 'error', message: 'Введите логин и пароль' });
          return;
        }

        const result = await pool.query(`SELECT login, password, nickname, avatarImage, bannerImage, status FROM users WHERE login = $1`, [login]);
        const user = result.rows[0];

        if (!user) {
          recordAuthAttempt(clientIp, false);
          send(ws, { type: 'error', message: 'Неверный логин или пароль' });
          return;
        }

        let ok = false;
        if (typeof user.password === 'string' && user.password.startsWith('$2')) {
          ok = await bcrypt.compare(password, user.password);
        } else {
          ok = password === user.password;
          if (ok) {
            const upgradedHash = await bcrypt.hash(password, 12);
            await pool.query(`UPDATE users SET password = $1 WHERE login = $2`, [upgradedHash, user.login]);
          }
        }

        if (!ok) {
          recordAuthAttempt(clientIp, false);
          send(ws, { type: 'error', message: 'Неверный логин или пароль' });
          return;
        }

        recordAuthAttempt(clientIp, true);
        userLogin = user.login;
        const ua = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : '';

        // Check if 2FA is enabled for this user
        const secRow = await pool.query(`SELECT totp_secret, twofa_enabled FROM user_security WHERE login = $1`, [user.login]);
        const sec = secRow.rows[0];
        if (sec?.twofa_enabled && sec?.totp_secret) {
          pending2FA.set(user.login, { userData: user, ua, ip: clientIp });
          send(ws, { type: 'twofa_required', login: user.login });
          return;
        }

        await loginSocket(ws, user, ua, clientIp);
        await broadcastOnlineFriends();
        return;
      }

      if (data.type === 'login_2fa_verify') {
        const loginVal = sanitizeLogin(data.login);
        const token = typeof data.code === 'string' ? data.code.replace(/\s/g, '').trim() : '';
        if (!loginVal || !token) return;
        const pending = pending2FA.get(loginVal);
        if (!pending) { send(ws, { type: 'error', message: 'Сессия истекла. Войдите заново.' }); return; }
        // Trusted device bypass — client already verified locally within 1 hour
        if (token !== '__trusted__') {
          const secRow = await pool.query(`SELECT totp_secret FROM user_security WHERE login = $1`, [loginVal]);
          const secret = secRow.rows[0]?.totp_secret;
          if (!secret) { pending2FA.delete(loginVal); send(ws, { type: 'error', message: 'Ошибка 2FA.' }); return; }
          const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 2 });
          if (!valid) { send(ws, { type: 'error', message: 'Неверный код. Попробуй ещё раз.' }); return; }
        }
        pending2FA.delete(loginVal);
        userLogin = pending.userData.login;
        await loginSocket(ws, pending.userData, pending.ua, pending.ip);
        await broadcastOnlineFriends();
        return;
      }

      if (data.type === 'auth_token') {
        const verified = await verifySessionToken(typeof data.token === 'string' ? data.token : '');
        if (!verified) {
          send(ws, { type: 'auth_expired' });
          return;
        }

        const result = await pool.query(`SELECT login, nickname, avatarImage, bannerImage, status FROM users WHERE login = $1`, [verified.login]);
        const user = result.rows[0];
        if (!user) {
          send(ws, { type: 'auth_expired' });
          return;
        }

        userLogin = user.login;
        const ua2 = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : '';
        // Update userAgent/ip for re-auth (token reconnect)
        await pool.query(`UPDATE sessions SET userAgent = $1, ip = $2 WHERE id = $3`, [ua2.slice(0, 512), clientIp.slice(0, 64), verified.sessionId]);
        await loginSocket(ws, user, ua2, clientIp);
        await broadcastOnlineFriends();
        return;
      }

      if (!userLogin) return;
      if (data.type === 'logout') {
        const sessionId = clients.get(ws)?.sessionId || null;
        if (sessionId) {
          await pool.query(`UPDATE sessions SET revoked = TRUE WHERE id = $1`, [sessionId]);
        }
        send(ws, { type: 'logged_out' });
        try { ws.close(); } catch {}
        return;
      }

      if (data.type === 'get_sessions') {
        const rows = await pool.query(
          `SELECT id, createdAt, expiresAt, userAgent, ip FROM sessions WHERE login = $1 AND revoked = FALSE AND expiresAt > $2 ORDER BY createdAt DESC`,
          [userLogin, Date.now()]
        );
        const currentSessionId = clients.get(ws)?.sessionId || null;
        send(ws, {
          type: 'sessions_list',
          sessions: rows.rows.map(r => ({
            id: r.id,
            createdAt: Number(r.createdat),
            expiresAt: Number(r.expiresat),
            userAgent: r.useragent || '',
            ip: r.ip || '',
            current: r.id === currentSessionId
          }))
        });
        return;
      }

      if (data.type === 'revoke_session') {
        const targetId = typeof data.sessionId === 'string' ? data.sessionId : '';
        if (!targetId) return;
        // Only allow revoking own sessions
        const check = await pool.query(`SELECT id FROM sessions WHERE id = $1 AND login = $2`, [targetId, userLogin]);
        if (!check.rows.length) return;
        await pool.query(`UPDATE sessions SET revoked = TRUE WHERE id = $1`, [targetId]);
        // If the target session is currently connected, force disconnect
        for (const [client, info] of clients.entries()) {
          if (info.sessionId === targetId && client !== ws) {
            send(client, { type: 'logged_out' });
            try { client.close(); } catch {}
          }
        }
        send(ws, { type: 'session_revoked', sessionId: targetId });
        return;
      }

      // ── SECURITY ─────────────────────────────────────────────────────────────
      if (data.type === 'change_password') {
        const oldPass = typeof data.oldPassword === 'string' ? data.oldPassword : '';
        const newPass = typeof data.newPassword === 'string' ? data.newPassword : '';
        if (!oldPass || !newPass || newPass.length < 6) {
          send(ws, { type: 'security_error', message: 'Пароль должен быть не менее 6 символов.' });
          return;
        }
        const uRow = await pool.query(`SELECT password FROM users WHERE login = $1`, [userLogin]);
        const u = uRow.rows[0];
        if (!u) return;
        const ok = await bcrypt.compare(oldPass, u.password);
        if (!ok) { send(ws, { type: 'security_error', message: 'Неверный текущий пароль.' }); return; }
        const hash = await bcrypt.hash(newPass, 12);
        await pool.query(`UPDATE users SET password = $1 WHERE login = $2`, [hash, userLogin]);
        send(ws, { type: 'security_ok', action: 'password_changed' });
        return;
      }

      if (data.type === 'get_security_info') {
        const row = await pool.query(`SELECT totp_secret, twofa_enabled FROM user_security WHERE login = $1`, [userLogin]);
        const s = row.rows[0];
        send(ws, { type: 'security_info', twofa_enabled: !!s?.twofa_enabled });
        return;
      }

      if (data.type === 'totp_setup_start') {
        // Generate a new secret and return QR code
        const secret = speakeasy.generateSecret({ name: `Squadovka (${userLogin})`, length: 20 });
        // Store temp secret (not enabled yet)
        await pool.query(`
          INSERT INTO user_security (login, totp_secret, twofa_enabled)
          VALUES ($1, $2, FALSE)
          ON CONFLICT (login) DO UPDATE SET totp_secret = $2
        `, [userLogin, secret.base32]);
        const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
        send(ws, { type: 'totp_setup_qr', qr: qrDataUrl, secret: secret.base32 });
        return;
      }

      if (data.type === 'totp_setup_verify') {
        const token = typeof data.code === 'string' ? data.code.replace(/\s/g, '').trim() : '';
        if (!token) return;
        const row = await pool.query(`SELECT totp_secret FROM user_security WHERE login = $1`, [userLogin]);
        const secret = row.rows[0]?.totp_secret;
        if (!secret) { send(ws, { type: 'security_error', message: 'Сначала запросите QR-код.' }); return; }
        const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 2 });
        if (!valid) { send(ws, { type: 'security_error', message: 'Неверный код. Убедись что время на устройстве точное и попробуй ещё раз.' }); return; }
        await pool.query(`UPDATE user_security SET twofa_enabled = TRUE WHERE login = $1`, [userLogin]);
        send(ws, { type: 'security_ok', action: '2fa_enabled' });
        return;
      }

      if (data.type === 'disable_2fa') {
        await pool.query(`UPDATE user_security SET twofa_enabled = FALSE, totp_secret = NULL WHERE login = $1`, [userLogin]);
        send(ws, { type: 'security_ok', action: '2fa_disabled' });
        return;
      }
      // ─────────────────────────────────────────────────────────────────────────

      const me = clients.get(ws);
      if (!me) return;

      if (data.type === 'update_avatar') {
        if (!requireActionAllowed(ws, clientIp, 'update_avatar')) return;
        const image = typeof data.image === 'string' ? data.image : '';
        if (!/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(image)) {
          send(ws, { type: 'error', message: 'Неверный формат аватара' });
          return;
        }
        if (image.length > 1400000) {
          send(ws, { type: 'error', message: 'Аватар слишком большой' });
          return;
        }
        const rawSizeEstimate = Math.floor((image.split(',')[1]?.length || 0) * 0.75);
        if (rawSizeEstimate > 1024 * 1024) {
          send(ws, { type: 'error', message: 'Аватар слишком большой' });
          return;
        }

        await pool.query(`UPDATE users SET avatarImage = $1 WHERE login = $2`, [image, userLogin]);
        const updatedResult = await pool.query(`SELECT login, nickname, avatarImage, bannerImage, status FROM users WHERE login = $1`, [userLogin]);
        const updatedUser = updatedResult.rows[0];

        if (updatedUser) {
          clients.set(ws, {
            login: updatedUser.login,
            nickname: updatedUser.nickname,
            avatarImage: updatedUser.avatarimage,
            bannerImage: updatedUser.bannerimage,
            status: normalizeStatus(updatedUser.status)
          });

          for (const [clientWs, info] of clients) {
            const publicUser = await getUserPublic(updatedUser.login, info.login);
            send(clientWs, { type: 'profile_updated', user: publicUser });
            if (info.login === updatedUser.login) {
              send(clientWs, {
                type: 'my_profile_updated',
                nickname: updatedUser.nickname,
                status: normalizeStatus(updatedUser.status),
                avatar: buildAvatar(updatedUser.login, updatedUser.nickname, updatedUser.avatarimage),
                banner: updatedUser.bannerimage || null
              });
            }
          }
          await broadcastOnlineFriends();
        }
        return;
      }

      if (data.type === 'update_banner') {
        if (!requireActionAllowed(ws, clientIp, 'update_banner')) return;
        const image = typeof data.image === 'string' ? data.image : '';
        if (!/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(image)) {
          send(ws, { type: 'error', message: 'Неверный формат баннера' });
          return;
        }
        if (image.length > 2100000) {
          send(ws, { type: 'error', message: 'Баннер слишком большой' });
          return;
        }
        const rawSizeEstimate = Math.floor((image.split(',')[1]?.length || 0) * 0.75);
        if (rawSizeEstimate > 1536 * 1024) {
          send(ws, { type: 'error', message: 'Баннер слишком большой' });
          return;
        }

        await pool.query(`UPDATE users SET bannerImage = $1 WHERE login = $2`, [image, userLogin]);
        const updatedResult = await pool.query(`SELECT login, nickname, avatarImage, bannerImage, status FROM users WHERE login = $1`, [userLogin]);
        const updatedUser = updatedResult.rows[0];

        if (updatedUser) {
          clients.set(ws, {
            login: updatedUser.login,
            nickname: updatedUser.nickname,
            avatarImage: updatedUser.avatarimage,
            bannerImage: updatedUser.bannerimage,
            status: normalizeStatus(updatedUser.status)
          });

          for (const [clientWs, info] of clients) {
            const publicUser = await getUserPublic(updatedUser.login, info.login);
            send(clientWs, { type: 'profile_updated', user: publicUser });
            if (info.login === updatedUser.login) {
              send(clientWs, {
                type: 'my_profile_updated',
                nickname: updatedUser.nickname,
                status: normalizeStatus(updatedUser.status),
                avatar: buildAvatar(updatedUser.login, updatedUser.nickname, updatedUser.avatarimage),
                banner: updatedUser.bannerimage || null
              });
            }
          }
          await broadcastOnlineFriends();
        }
        return;
      }

      if (data.type === 'update_profile') {
        if (!requireActionAllowed(ws, clientIp, 'update_profile')) return;
        const newNickname = sanitizeName(data.nickname, MAX_NICKNAME_LENGTH);
        const newStatus = normalizeStatus(typeof data.status === 'string' ? data.status : 'online');
        if (!newNickname) {
          send(ws, { type: 'error', message: 'Введите имя профиля' });
          return;
        }

        await pool.query(`UPDATE users SET nickname = $1, status = $2 WHERE login = $3`, [newNickname, newStatus, userLogin]);
        const updatedResult = await pool.query(`SELECT login, nickname, avatarImage, bannerImage, status FROM users WHERE login = $1`, [userLogin]);
        const updatedUser = updatedResult.rows[0];
        clients.set(ws, {
          login: updatedUser.login,
          nickname: updatedUser.nickname,
          avatarImage: updatedUser.avatarimage,
          bannerImage: updatedUser.bannerimage,
          status: normalizeStatus(updatedUser.status)
        });

        for (const [clientWs, info] of clients) {
          const publicUser = await getUserPublic(updatedUser.login, info.login);
          send(clientWs, { type: 'profile_updated', user: publicUser });
          if (info.login === updatedUser.login) {
            send(clientWs, {
              type: 'my_profile_updated',
              nickname: updatedUser.nickname,
              status: normalizeStatus(updatedUser.status),
              avatar: buildAvatar(updatedUser.login, updatedUser.nickname, updatedUser.avatarimage)
            });
          }
        }
        await broadcastOnlineFriends();
        return;
      }

      if (data.type === 'get_messages') {
        if (!requireActionAllowed(ws, clientIp, 'get_messages')) return;
        const peerLogin = sanitizeLogin(data.with);
        if (!peerLogin) return;
        if (!(await areFriends(userLogin, peerLogin))) {
          send(ws, { type: 'error', message: 'Личные сообщения доступны только друзьям' });
          return;
        }

        const deliveredAt = Date.now();
        const deliveredResult = await pool.query(`
          UPDATE messages
          SET deliveredAt = COALESCE(deliveredAt, $3)
          WHERE fromUser = $1 AND toUser = $2 AND deliveredAt IS NULL
          RETURNING id
        `, [peerLogin, userLogin, deliveredAt]);

        if (deliveredResult.rows.length) {
          await notifyReceiptUpdate(peerLogin, userLogin, deliveredResult.rows.map(row => row.id), 'sent');
        }

        send(ws, { type: 'chat_history', with: peerLogin, messages: await getChatHistory(userLogin, peerLogin) });
        return;
      }

      if (data.type === 'create_group') {
        if (!requireActionAllowed(ws, clientIp, 'create_group')) return;
        const name = sanitizeName(data.name, MAX_GROUP_NAME_LENGTH);
        const memberLogins = Array.isArray(data.members) ? data.members.map(sanitizeLogin).filter(Boolean) : [];
        if (!name) {
          send(ws, { type: 'error', message: 'Введите название группы' });
          return;
        }

        const uniqueMembers = Array.from(new Set([userLogin, ...memberLogins.filter(v => v !== userLogin)]));
        const existingUsers = await pool.query(`SELECT login FROM users WHERE login = ANY($1::text[])`, [uniqueMembers]);
        const existingSet = new Set(existingUsers.rows.map(r => r.login));
        const finalMembers = uniqueMembers.filter(loginItem => existingSet.has(loginItem));

        const createdAt = Date.now();
        const created = await pool.query(`
          INSERT INTO chat_groups (name, ownerLogin, createdAt)
          VALUES ($1, $2, $3)
          RETURNING id
        `, [name, userLogin, createdAt]);

        const groupId = Number(created.rows[0].id);

        for (const member of finalMembers) {
          await pool.query(`
            INSERT INTO group_members (groupId, userLogin, role, joinedAt)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (groupId, userLogin) DO NOTHING
          `, [groupId, member, member === userLogin ? 'owner' : 'member', createdAt]);
        }

        const group = await getGroupPublic(groupId, userLogin);
        await sendGroupToMembers(groupId, { type: 'group_created', group });
        for (const member of finalMembers) await sendGroupList(member);
        return;
      }

      if (data.type === 'get_group_messages') {
        if (!requireActionAllowed(ws, clientIp, 'get_group_messages')) return;
        const groupId = Number(data.groupId);
        if (!Number.isFinite(groupId) || !(await isGroupMember(groupId, userLogin))) return;
        send(ws, { type: 'group_history', groupId, messages: await getGroupHistory(groupId, userLogin) });
        return;
      }

      if (data.type === 'group_message') {
        if (!requireActionAllowed(ws, clientIp, 'group_message')) return;
        const groupId = Number(data.groupId);
        const messageText = sanitizeText(data.text);
        const attachment = sanitizeAttachmentPayload(data.attachment);
        const replyTo = sanitizeReplyPayload(data.replyTo);
        if (!groupId || (!messageText && !attachment)) return;
        if (!(await isGroupMember(groupId, userLogin))) return;

        const messageTime = Date.now();
        const insertResult = await pool.query(`
          INSERT INTO group_messages (groupId, fromUser, text, time, edited, editedAt, attachment, replyTo)
          VALUES ($1, $2, $3, $4, FALSE, NULL, $5::jsonb, $6::jsonb)
          RETURNING id
        `, [groupId, userLogin, messageText, messageTime, attachment ? JSON.stringify(attachment) : null, replyTo ? JSON.stringify(replyTo) : null]);

        const msgData = {
          type: 'group_message',
          id: Number(insertResult.rows[0].id),
          groupId,
          from: userLogin,
          text: messageText,
          time: messageTime,
          edited: false,
          editedAt: null,
          attachment,
          replyTo,
          fromNick: me.nickname,
          avatar: buildAvatar(userLogin, me.nickname, me.avatarImage)
        };

        await sendGroupToMembers(groupId, msgData);
        return;
      }

      if (data.type === 'edit_group_message') {
        if (!requireActionAllowed(ws, clientIp, 'edit_group_message')) return;
        const messageId = Number(data.id);
        const newText = sanitizeText(data.text);
        if (!messageId || !newText) return;

        const messageResult = await pool.query(`
          SELECT id, groupId, fromUser FROM group_messages WHERE id = $1 LIMIT 1
        `, [messageId]);
        const message = messageResult.rows[0];
        if (!message || message.fromuser !== userLogin) return;
        if (!(await isGroupMember(Number(message.groupid), userLogin))) return;

        const editedAt = Date.now();
        await pool.query(`UPDATE group_messages SET text = $1, edited = TRUE, editedAt = $2 WHERE id = $3`, [newText, editedAt, messageId]);

        await sendGroupToMembers(Number(message.groupid), {
          type: 'group_message_edited',
          id: messageId,
          groupId: Number(message.groupid),
          text: newText,
          edited: true,
          editedAt,
          from: userLogin
        });
        return;
      }

      if (data.type === 'delete_group_message') {
        if (!requireActionAllowed(ws, clientIp, 'delete_group_message')) return;
        const messageId = Number(data.id);
        if (!Number.isFinite(messageId)) return;

        const existing = await pool.query(`
          SELECT id, groupId, fromUser FROM group_messages WHERE id = $1 LIMIT 1
        `, [messageId]);
        const message = existing.rows[0];
        if (!message || message.fromuser !== userLogin) return;

        await pool.query(`DELETE FROM group_messages WHERE id = $1`, [messageId]);
        await sendGroupToMembers(Number(message.groupid), {
          type: 'group_message_deleted',
          id: messageId,
          groupId: Number(message.groupid),
          from: userLogin
        });
        return;
      }

      if (data.type === 'update_group') {
        if (!requireActionAllowed(ws, clientIp, 'update_group')) return;
        const groupId = Number(data.groupId);
        const name = sanitizeName(data.name, MAX_GROUP_NAME_LENGTH);
        if (!Number.isFinite(groupId) || !name) return;

        const groupResult = await pool.query(`SELECT ownerLogin FROM chat_groups WHERE id = $1 LIMIT 1`, [groupId]);
        const group = groupResult.rows[0];
        if (!group || group.ownerlogin !== userLogin) return;

        await pool.query(`UPDATE chat_groups SET name = $1 WHERE id = $2`, [name, groupId]);
        const updated = await getGroupPublic(groupId, userLogin);
        await sendGroupToMembers(groupId, { type: 'group_updated', group: updated });
        const members = updated?.members || [];
        for (const member of members) await sendGroupList(member.login);
        return;
      }

      if (data.type === 'add_group_members') {
        if (!requireActionAllowed(ws, clientIp, 'add_group_members')) return;
        const groupId = Number(data.groupId);
        const members = Array.isArray(data.members) ? data.members.map(sanitizeLogin).filter(Boolean) : [];
        if (!Number.isFinite(groupId) || !members.length) return;

        const groupResult = await pool.query(`SELECT ownerLogin FROM chat_groups WHERE id = $1 LIMIT 1`, [groupId]);
        const group = groupResult.rows[0];
        if (!group || group.ownerlogin !== userLogin) return;

        const existingUsers = await pool.query(`SELECT login FROM users WHERE login = ANY($1::text[])`, [members]);
        for (const row of existingUsers.rows) {
          await pool.query(`
            INSERT INTO group_members (groupId, userLogin, role, joinedAt)
            VALUES ($1, $2, 'member', $3)
            ON CONFLICT (groupId, userLogin) DO NOTHING
          `, [groupId, row.login, Date.now()]);
        }

        const updated = await getGroupPublic(groupId, userLogin);
        await sendGroupToMembers(groupId, { type: 'group_updated', group: updated });
        for (const member of updated?.members || []) await sendGroupList(member.login);
        return;
      }

      if (data.type === 'remove_group_member') {
        if (!requireActionAllowed(ws, clientIp, 'remove_group_member')) return;
        const groupId = Number(data.groupId);
        const targetLogin = sanitizeLogin(data.userLogin);
        if (!Number.isFinite(groupId) || !targetLogin) return;

        const groupResult = await pool.query(`SELECT ownerLogin FROM chat_groups WHERE id = $1 LIMIT 1`, [groupId]);
        const group = groupResult.rows[0];
        if (!group || group.ownerlogin !== userLogin || targetLogin === userLogin) return;

        await pool.query(`DELETE FROM group_members WHERE groupId = $1 AND userLogin = $2`, [groupId, targetLogin]);

        const updated = await getGroupPublic(groupId, userLogin);
        if (updated) {
          await sendGroupToMembers(groupId, { type: 'group_updated', group: updated });
          for (const member of updated.members) await sendGroupList(member.login);
        }
        sendToUser(targetLogin, { type: 'group_left', groupId });
        await sendGroupList(targetLogin);
        return;
      }

      if (data.type === 'leave_group') {
        if (!requireActionAllowed(ws, clientIp, 'leave_group')) return;
        const groupId = Number(data.groupId);
        if (!Number.isFinite(groupId) || !(await isGroupMember(groupId, userLogin))) return;

        const groupResult = await pool.query(`SELECT ownerLogin FROM chat_groups WHERE id = $1 LIMIT 1`, [groupId]);
        const group = groupResult.rows[0];
        if (!group) return;

        if (group.ownerlogin === userLogin) {
          await pool.query(`DELETE FROM group_messages WHERE groupId = $1`, [groupId]);
          await pool.query(`DELETE FROM group_members WHERE groupId = $1`, [groupId]);
          await pool.query(`DELETE FROM chat_groups WHERE id = $1`, [groupId]);
          sendToUser(userLogin, { type: 'group_left', groupId });
          await sendGroupList(userLogin);
          return;
        }

        await pool.query(`DELETE FROM group_members WHERE groupId = $1 AND userLogin = $2`, [groupId, userLogin]);
        await sendGroupToMembers(groupId, { type: 'group_updated', group: await getGroupPublic(groupId, userLogin) });
        sendToUser(userLogin, { type: 'group_left', groupId });
        await sendGroupList(userLogin);
        return;
      }


      if (data.type === 'friend_request') {
        if (!requireActionAllowed(ws, clientIp, 'friend_request')) return;
        const targetLogin = sanitizeLogin(data.to);
        if (!targetLogin || targetLogin === userLogin) return;

        const target = await pool.query(`SELECT login FROM users WHERE login = $1`, [targetLogin]);
        if (!target.rows.length) {
          send(ws, { type: 'error', message: 'Пользователь не найден' });
          return;
        }

        const alreadyFriends = await pool.query(`
          SELECT 1 FROM friends
          WHERE (user1 = $1 AND user2 = $2) OR (user1 = $2 AND user2 = $1)
          LIMIT 1
        `, [userLogin, targetLogin]);

        if (alreadyFriends.rows.length) {
          send(ws, { type: 'error', message: 'Вы уже друзья' });
          return;
        }

        await pool.query(`
          INSERT INTO friend_requests (fromUser, toUser)
          VALUES ($1, $2)
          ON CONFLICT (fromUser, toUser) DO NOTHING
        `, [userLogin, targetLogin]);

        sendToUser(targetLogin, { type: 'friend_request', from: userLogin, fromNick: me.nickname });
        return;
      }


      if (data.type === 'friend_accept') {
        const fromLogin = sanitizeLogin(data.from);
        if (!fromLogin || fromLogin === userLogin) return;

        const requestExists = await pool.query(`SELECT 1 FROM friend_requests WHERE fromUser = $1 AND toUser = $2 LIMIT 1`, [fromLogin, userLogin]);
        if (!requestExists.rows.length) return;

        await pool.query(`INSERT INTO friends (user1, user2) VALUES ($1, $2) ON CONFLICT (user1, user2) DO NOTHING`, [fromLogin, userLogin]);
        await pool.query(`DELETE FROM friend_requests WHERE fromUser = $1 AND toUser = $2`, [fromLogin, userLogin]);

        const acceptedMe = await getUserPublic(userLogin);
        sendToUser(fromLogin, { type: 'friend_accept', from: userLogin, fromNick: me.nickname, friend: acceptedMe });

        send(ws, { type: 'friends_list', friends: await getFriendUsers(userLogin) });
        sendToUser(fromLogin, { type: 'friends_list', friends: await getFriendUsers(fromLogin) });
        await broadcastOnlineFriends();
        return;
      }


      if (data.type === 'call_start') {
        if (!requireActionAllowed(ws, clientIp, 'call_start')) return;
        const targetLogin = sanitizeLogin(data.to);
        if (!targetLogin || targetLogin === userLogin) return;
        if (!(await areFriends(userLogin, targetLogin))) {
          send(ws, { type: 'error', message: 'Звонки доступны только друзьям' });
          return;
        }
        if (!sendToUser(targetLogin, { type: 'call_probe' })) {
          send(ws, { type: 'call_unavailable', reason: 'offline', to: targetLogin });
          return;
        }
        if (isUserBusy(userLogin) || isUserBusy(targetLogin)) {
          send(ws, { type: 'call_unavailable', reason: 'busy', to: targetLogin });
          return;
        }
        pendingCalls.set(userLogin, targetLogin);
        pendingCalls.set(targetLogin, userLogin);
        send(ws, { type: 'call_outgoing', to: targetLogin });
        sendToUser(targetLogin, {
          type: 'call_incoming',
          from: userLogin,
          fromNick: me.nickname,
          avatar: buildAvatar(userLogin, me.nickname, me.avatarImage)
        });
        return;
      }

      if (data.type === 'call_accept') {
        if (!requireActionAllowed(ws, clientIp, 'call_response')) return;
        const otherLogin = sanitizeLogin(data.with);
        if (!otherLogin || pendingCalls.get(userLogin) !== otherLogin || pendingCalls.get(otherLogin) !== userLogin) return;
        clearPendingBetween(userLogin, otherLogin);
        activeCalls.set(userLogin, otherLogin);
        activeCalls.set(otherLogin, userLogin);
        send(ws, { type: 'call_joined', with: otherLogin });
        sendToUser(otherLogin, { type: 'call_accepted', by: userLogin });
        return;
      }

      if (data.type === 'call_decline') {
        if (!requireActionAllowed(ws, clientIp, 'call_response')) return;
        const otherLogin = sanitizeLogin(data.with);
        if (!otherLogin) return;
        const wasPending = pendingCalls.get(userLogin) === otherLogin || pendingCalls.get(otherLogin) === userLogin;
        if (!wasPending) return;
        clearPendingBetween(userLogin, otherLogin);
        send(ws, { type: 'call_ended', reason: 'declined', with: otherLogin });
        sendToUser(otherLogin, { type: 'call_ended', reason: 'declined', with: userLogin });
        return;
      }

      if (data.type === 'call_cancel') {
        if (!requireActionAllowed(ws, clientIp, 'call_end')) return;
        const otherLogin = sanitizeLogin(data.with);
        if (!otherLogin) return;
        const wasPending = pendingCalls.get(userLogin) === otherLogin || pendingCalls.get(otherLogin) === userLogin;
        if (!wasPending) return;
        clearPendingBetween(userLogin, otherLogin);
        send(ws, { type: 'call_ended', reason: 'cancelled', with: otherLogin });
        sendToUser(otherLogin, { type: 'call_ended', reason: 'cancelled', with: userLogin });
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

      // ── GROUP CALLS ──────────────────────────────────────────────────────────
      if (data.type === 'group_call_start') {
        if (!requireActionAllowed(ws, clientIp, 'group_call_start')) return;
        const groupId = Number(data.groupId);
        if (!Number.isFinite(groupId) || groupId <= 0) return;
        if (!(await isGroupMember(groupId, userLogin))) return;
        if (!activeGroupCalls.has(groupId)) activeGroupCalls.set(groupId, new Set());
        const members = activeGroupCalls.get(groupId);
        members.add(userLogin);
        // Notify all group members about the call
        await sendGroupToMembers(groupId, {
          type: 'group_call_state',
          groupId,
          participants: [...members],
          startedBy: userLogin
        });
        return;
      }

      if (data.type === 'group_call_join') {
        if (!requireActionAllowed(ws, clientIp, 'group_call_join')) return;
        const groupId = Number(data.groupId);
        if (!Number.isFinite(groupId) || groupId <= 0) return;
        if (!(await isGroupMember(groupId, userLogin))) return;
        if (!activeGroupCalls.has(groupId)) return; // no active call to join
        const members = activeGroupCalls.get(groupId);
        const existingParticipants = [...members];
        members.add(userLogin);
        // Tell the new joiner who is already in the call
        send(ws, { type: 'group_call_joined', groupId, participants: existingParticipants });
        // Tell existing participants about the new joiner
        for (const peer of existingParticipants) {
          sendToUser(peer, { type: 'group_call_peer_joined', groupId, login: userLogin });
        }
        await sendGroupToMembers(groupId, { type: 'group_call_state', groupId, participants: [...members] });
        return;
      }

      if (data.type === 'group_call_leave') {
        if (!requireActionAllowed(ws, clientIp, 'group_call_leave')) return;
        const groupId = Number(data.groupId);
        if (!Number.isFinite(groupId) || groupId <= 0) return;
        const members = activeGroupCalls.get(groupId);
        if (!members || !members.has(userLogin)) return;
        members.delete(userLogin);
        for (const peer of members) {
          sendToUser(peer, { type: 'group_call_peer_left', groupId, login: userLogin });
        }
        if (members.size === 0) {
          activeGroupCalls.delete(groupId);
          await sendGroupToMembers(groupId, { type: 'group_call_ended', groupId });
        } else {
          await sendGroupToMembers(groupId, { type: 'group_call_state', groupId, participants: [...members] });
        }
        return;
      }

      if (data.type === 'group_call_signal') {
        if (!requireActionAllowed(ws, clientIp, 'group_call_signal')) return;
        const groupId = Number(data.groupId);
        const targetLogin = sanitizeLogin(data.to);
        const signal = data.signal && typeof data.signal === 'object' ? data.signal : null;
        if (!Number.isFinite(groupId) || !targetLogin || !signal) return;
        const members = activeGroupCalls.get(groupId);
        if (!members || !members.has(userLogin) || !members.has(targetLogin)) return;
        sendToUser(targetLogin, { type: 'group_call_signal', groupId, from: userLogin, signal });
        return;
      }
      // ─────────────────────────────────────────────────────────────────────────


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
      // Clean up group calls
      for (const [groupId, members] of activeGroupCalls.entries()) {
        if (members.has(userLogin)) {
          members.delete(userLogin);
          for (const member of members) {
            sendToUser(member, { type: 'group_call_peer_left', groupId, login: userLogin });
          }
          if (members.size === 0) {
            activeGroupCalls.delete(groupId);
          } else {
            sendToGroupMembers(groupId, { type: 'group_call_state', groupId, participants: [...members] });
          }
        }
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
