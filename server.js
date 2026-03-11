const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const publicDir = path.join(__dirname, 'public');
const rootIndex = path.join(__dirname, 'index.html');
const publicIndex = path.join(publicDir, 'index.html');

app.use(express.static(publicDir));
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  if (require('fs').existsSync(publicIndex)) {
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
      status TEXT NOT NULL DEFAULT 'online'
    )
  `);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'online'`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      text TEXT NOT NULL,
      time BIGINT NOT NULL,
      edited BOOLEAN NOT NULL DEFAULT FALSE,
      editedAt BIGINT
    )
  `);

  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS editedAt BIGINT`);

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
      editedAt BIGINT
    )
  `);

  await pool.query(`ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS edited BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS editedAt BIGINT`);
}

const clients = new Map();
const inCall = new Map();

function send(ws, data) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  }
}

function sendToUser(login, data) {
  for (const [ws, info] of clients) {
    if (info.login === login) {
      send(ws, data);
    }
  }
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
  const result = await pool.query(`SELECT login, nickname, avatarImage, status FROM users WHERE login = $1`, [login]);
  const user = result.rows[0];
  if (!user) return null;
  return {
    login: user.login,
    nickname: user.nickname,
    status: getEffectiveStatus(user.login, user.status, viewerLogin),
    avatar: buildAvatar(user.login, user.nickname, user.avatarimage)
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
    SELECT id, fromUser, toUser, text, time, edited, editedAt
    FROM messages
    WHERE (fromUser = $1 AND toUser = $2)
       OR (fromUser = $2 AND toUser = $1)
    ORDER BY time ASC, id ASC
  `, [userA, userB]);

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
    SELECT id, groupId, fromUser, text, time, edited, editedAt
    FROM group_messages
    WHERE groupId = $1
    ORDER BY time ASC, id ASC
  `, [groupId]);

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
          avatar: buildAvatar(other.login, other.nickname, other.avatarImage)
        });
      }
    }

    send(ws, { type: 'online_friends', users: Array.from(onlineMap.values()) });
  }
}

function isBusy(login) {
  return inCall.has(login);
}

function clearCall(login) {
  const peer = inCall.get(login);
  inCall.delete(login);
  if (peer && inCall.get(peer) === login) inCall.delete(peer);
}

wss.on('connection', ws => {
  let userLogin = null;

  ws.on('message', async msg => {
    let data;
    try {
      data = JSON.parse(msg);
    } catch {
      return;
    }

    try {
      if (data.type === 'register') {
        const login = typeof data.login === 'string' ? data.login.trim() : '';
        const password = typeof data.password === 'string' ? data.password : '';

        if (!login || !password) {
          send(ws, { type: 'error', message: 'Введите логин и пароль' });
          return;
        }

        const exists = await pool.query(`SELECT login FROM users WHERE login = $1`, [login]);
        if (exists.rows.length) {
          send(ws, { type: 'error', message: 'Логин занят' });
          return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(`INSERT INTO users (login, password, nickname, avatarImage, status) VALUES ($1, $2, $3, $4, $5)`, [login, hashedPassword, login, null, 'online']);
        send(ws, { type: 'register_ok' });
        return;
      }

      if (data.type === 'login') {
        const login = typeof data.login === 'string' ? data.login.trim() : '';
        const password = typeof data.password === 'string' ? data.password : '';

        if (!login || !password) {
          send(ws, { type: 'error', message: 'Введите логин и пароль' });
          return;
        }

        const result = await pool.query(`SELECT login, password, nickname, avatarImage, status FROM users WHERE login = $1`, [login]);
        const user = result.rows[0];

        if (!user) {
          send(ws, { type: 'error', message: 'Неверный логин или пароль' });
          return;
        }

        let ok = false;
        if (typeof user.password === 'string' && user.password.startsWith('$2')) {
          ok = await bcrypt.compare(password, user.password);
        } else {
          ok = password === user.password;
          if (ok) {
            const upgradedHash = await bcrypt.hash(password, 10);
            await pool.query(`UPDATE users SET password = $1 WHERE login = $2`, [upgradedHash, user.login]);
            user.password = upgradedHash;
          }
        }

        if (!ok) {
          send(ws, { type: 'error', message: 'Неверный логин или пароль' });
          return;
        }

        userLogin = user.login;
        clients.set(ws, {
          login: user.login,
          nickname: user.nickname,
          avatarImage: user.avatarimage,
          status: normalizeStatus(user.status)
        });

        send(ws, {
          type: 'login_ok',
          login: user.login,
          nickname: user.nickname,
          status: normalizeStatus(user.status),
          avatar: buildAvatar(user.login, user.nickname, user.avatarimage),
          friends: await getFriendUsers(user.login),
          unread: await getUnreadMap(user.login),
          groups: await getGroupsForUser(user.login)
        });

        const requests = await pool.query(`SELECT fromUser FROM friend_requests WHERE toUser = $1`, [user.login]);
        for (const r of requests.rows) {
          send(ws, { type: 'friend_request', from: r.fromuser });
        }

        await broadcastOnlineFriends();
        return;
      }

      if (!userLogin) return;
      const me = clients.get(ws);

      if (data.type === 'update_avatar') {
        const image = typeof data.image === 'string' ? data.image : '';
        if (!image.startsWith('data:image/')) {
          send(ws, { type: 'error', message: 'Неверный формат аватара' });
          return;
        }
        if (image.length > 1400000) {
          send(ws, { type: 'error', message: 'Аватар слишком большой' });
          return;
        }

        await pool.query(`UPDATE users SET avatarImage = $1 WHERE login = $2`, [image, userLogin]);
        const updatedResult = await pool.query(`SELECT login, nickname, avatarImage, status FROM users WHERE login = $1`, [userLogin]);
        const updatedUser = updatedResult.rows[0];

        if (updatedUser) {
          clients.set(ws, {
            login: updatedUser.login,
            nickname: updatedUser.nickname,
            avatarImage: updatedUser.avatarimage,
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
        }
        return;
      }

      if (data.type === 'update_profile') {
        const newNickname = typeof data.nickname === 'string' ? data.nickname.trim().slice(0, 32) : '';
        const newStatus = normalizeStatus(typeof data.status === 'string' ? data.status : 'online');
        if (!newNickname) {
          send(ws, { type: 'error', message: 'Введите имя профиля' });
          return;
        }

        await pool.query(`UPDATE users SET nickname = $1, status = $2 WHERE login = $3`, [newNickname, newStatus, userLogin]);
        const updatedResult = await pool.query(`SELECT login, nickname, avatarImage, status FROM users WHERE login = $1`, [userLogin]);
        const updatedUser = updatedResult.rows[0];
        clients.set(ws, {
          login: updatedUser.login,
          nickname: updatedUser.nickname,
          avatarImage: updatedUser.avatarimage,
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
        if (!data.with) return;
        send(ws, { type: 'chat_history', with: data.with, messages: await getChatHistory(userLogin, data.with) });
        return;
      }

      if (data.type === 'create_group') {
        const name = typeof data.name === 'string' ? data.name.trim().slice(0, 48) : '';
        const memberLogins = Array.isArray(data.members) ? data.members.filter(v => typeof v === 'string').map(v => v.trim()).filter(Boolean) : [];
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
        const groupId = Number(data.groupId);
        if (!Number.isFinite(groupId) || !(await isGroupMember(groupId, userLogin))) return;
        send(ws, { type: 'group_history', groupId, messages: await getGroupHistory(groupId, userLogin) });
        return;
      }

      if (data.type === 'group_message') {
        const groupId = Number(data.groupId);
        if (!Number.isFinite(groupId) || !(await isGroupMember(groupId, userLogin))) return;
        const messageText = typeof data.text === 'string' ? data.text.trim() : '';
        if (!messageText) return;

        const messageTime = Date.now();
        const insertResult = await pool.query(`
          INSERT INTO group_messages (groupId, fromUser, text, time, edited, editedAt)
          VALUES ($1, $2, $3, $4, FALSE, NULL)
          RETURNING id
        `, [groupId, userLogin, messageText, messageTime]);

        const msgData = {
          type: 'group_message',
          id: Number(insertResult.rows[0].id),
          groupId,
          from: userLogin,
          text: messageText,
          time: messageTime,
          edited: false,
          editedAt: null,
          fromNick: me.nickname,
          avatar: buildAvatar(userLogin, me.nickname, me.avatarImage)
        };
        await sendGroupToMembers(groupId, msgData);
        return;
      }

      if (data.type === 'edit_group_message') {
        const messageId = Number(data.id);
        const newText = typeof data.text === 'string' ? data.text.trim() : '';
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
        const groupId = Number(data.groupId);
        const name = typeof data.name === 'string' ? data.name.trim().slice(0, 48) : '';
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
        const groupId = Number(data.groupId);
        const members = Array.isArray(data.members) ? data.members.filter(v => typeof v === 'string').map(v => v.trim()).filter(Boolean) : [];
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
        const groupId = Number(data.groupId);
        const targetLogin = typeof data.userLogin === 'string' ? data.userLogin.trim() : '';
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
        if (!data.to || data.to === userLogin) return;

        const target = await pool.query(`SELECT login FROM users WHERE login = $1`, [data.to]);
        if (!target.rows.length) {
          send(ws, { type: 'error', message: 'Пользователь не найден' });
          return;
        }

        const alreadyFriends = await pool.query(`
          SELECT 1 FROM friends
          WHERE (user1 = $1 AND user2 = $2) OR (user1 = $2 AND user2 = $1)
          LIMIT 1
        `, [userLogin, data.to]);

        if (alreadyFriends.rows.length) {
          send(ws, { type: 'error', message: 'Вы уже друзья' });
          return;
        }

        await pool.query(`
          INSERT INTO friend_requests (fromUser, toUser)
          VALUES ($1, $2)
          ON CONFLICT (fromUser, toUser) DO NOTHING
        `, [userLogin, data.to]);

        sendToUser(data.to, { type: 'friend_request', from: userLogin, fromNick: me.nickname });
        return;
      }

      if (data.type === 'friend_accept') {
        if (!data.from || !data.to) return;

        await pool.query(`INSERT INTO friends (user1, user2) VALUES ($1, $2) ON CONFLICT (user1, user2) DO NOTHING`, [data.from, data.to]);
        await pool.query(`DELETE FROM friend_requests WHERE fromUser = $1 AND toUser = $2`, [data.to, data.from]);

        const acceptedMe = await getUserPublic(userLogin);
        sendToUser(data.to, { type: 'friend_accept', from: userLogin, fromNick: me.nickname, friend: acceptedMe });

        send(ws, { type: 'friends_list', friends: await getFriendUsers(userLogin) });
        sendToUser(data.to, { type: 'friends_list', friends: await getFriendUsers(data.to) });
        await broadcastOnlineFriends();
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
        if (!data.to || typeof data.text !== 'string' || !data.text.trim()) return;

        const messageText = data.text.trim();
        const messageTime = Date.now();
        const insertResult = await pool.query(`
          INSERT INTO messages (fromUser, toUser, text, time, edited, editedAt)
          VALUES ($1, $2, $3, $4, FALSE, NULL)
          RETURNING id
        `, [userLogin, data.to, messageText, messageTime]);

        await pool.query(`
          INSERT INTO unread (fromUser, toUser, count)
          VALUES ($1, $2, 1)
          ON CONFLICT (fromUser, toUser)
          DO UPDATE SET count = unread.count + 1
        `, [userLogin, data.to]);

        const unreadResult = await pool.query(`SELECT count FROM unread WHERE fromUser = $1 AND toUser = $2`, [userLogin, data.to]);
        const unreadCount = unreadResult.rows[0]?.count || 0;

        const msgData = {
          type: 'message',
          id: Number(insertResult.rows[0].id),
          from: userLogin,
          to: data.to,
          text: messageText,
          time: messageTime,
          edited: false,
          editedAt: null,
          fromNick: me.nickname,
          avatar: buildAvatar(userLogin, me.nickname, me.avatarImage),
          unread: unreadCount,
          clientMsgId: typeof data.clientMsgId === 'string' ? data.clientMsgId : null
        };

        sendToUser(userLogin, msgData);
        sendToUser(data.to, msgData);
        return;
      }

      if (data.type === 'delete_message') {
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
        if (!data.to || data.to === userLogin) return;
        sendToUser(data.to, {
          type: 'typing',
          from: userLogin,
          fromNick: me.nickname,
          active: Boolean(data.active)
        });
        return;
      }

      if (data.type === 'edit_message') {
        const messageId = Number(data.id);
        const newText = typeof data.text === 'string' ? data.text.trim() : '';
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
        if (!data.from) return;
        await pool.query(`DELETE FROM unread WHERE fromUser = $1 AND toUser = $2`, [data.from, userLogin]);
        send(ws, { type: 'unread_update', unread: await getUnreadMap(userLogin) });
        return;
      }

      const callTypes = new Set(['call_offer','call_answer','call_ice','call_cancel','call_decline','call_end','call_busy']);
      if (callTypes.has(data.type)) {
        const to = data.to;
        if (!to || to === userLogin) return;

        const targetOnline = [...clients.values()].some(c => c.login === to);

        if (data.type === 'call_offer') {
          if (!targetOnline) {
            send(ws, { type: 'error', message: 'Пользователь не в сети' });
            return;
          }
          if (isBusy(userLogin) || isBusy(to)) {
            sendToUser(userLogin, { type: 'call_busy' });
            return;
          }
          inCall.set(userLogin, to);
          inCall.set(to, userLogin);
        }

        if ((data.type === 'call_answer' || data.type === 'call_ice') && inCall.get(userLogin) !== to) return;

        if (data.type === 'call_cancel' || data.type === 'call_decline' || data.type === 'call_end' || data.type === 'call_busy') {
          clearCall(userLogin);
          clearCall(to);
        }

        sendToUser(to, { ...data, from: userLogin, fromNick: me.nickname });
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

    if (info?.login) {
      const peer = inCall.get(info.login);
      if (peer) sendToUser(peer, { type: 'call_end', from: info.login });
      clearCall(info.login);
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
