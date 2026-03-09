const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ================= DATABASE ================= */

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
      avatarImage TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      text TEXT NOT NULL,
      time BIGINT NOT NULL,
      deleted BOOLEAN NOT NULL DEFAULT FALSE
    )
  `);

  await pool.query(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE
  `);

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
}

/* ================= CLIENTS ================= */

const clients = new Map();
const inCall = new Map();

/* ================= HELPERS ================= */

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

async function getUserPublic(login) {
  const result = await pool.query(
    `
    SELECT login, nickname, avatarImage
    FROM users
    WHERE login = $1
    `,
    [login]
  );

  const user = result.rows[0];
  if (!user) return null;

  return {
    login: user.login,
    nickname: user.nickname,
    avatar: buildAvatar(user.login, user.nickname, user.avatarimage)
  };
}

async function getFriends(login) {
  const result = await pool.query(
    `
    SELECT user1 AS friend FROM friends WHERE user2 = $1
    UNION
    SELECT user2 AS friend FROM friends WHERE user1 = $1
    `,
    [login]
  );

  return result.rows.map(r => r.friend);
}

async function getFriendUsers(login) {
  const friends = await getFriends(login);
  if (!friends.length) return [];

  const users = await Promise.all(friends.map(friendLogin => getUserPublic(friendLogin)));
  return users.filter(Boolean);
}

async function getUnreadMap(login) {
  const result = await pool.query(
    `
    SELECT fromUser, count
    FROM unread
    WHERE toUser = $1
    `,
    [login]
  );

  const unread = {};
  for (const row of result.rows) {
    unread[row.fromuser] = row.count;
  }
  return unread;
}

async function getChatHistory(userA, userB) {
  const result = await pool.query(
    `
    SELECT id, fromUser, toUser, text, time, deleted
    FROM messages
    WHERE (fromUser = $1 AND toUser = $2)
       OR (fromUser = $2 AND toUser = $1)
    ORDER BY time ASC, id ASC
    `,
    [userA, userB]
  );

  const messages = [];
  for (const row of result.rows) {
    const sender = await getUserPublic(row.fromuser);
    messages.push({
      id: row.id,
      from: row.fromuser,
      to: row.touser,
      text: row.text,
      time: Number(row.time),
      avatar: sender?.avatar || buildAvatar(row.fromuser, row.fromuser),
      deleted: !!row.deleted
    });
  }

  return messages;
}

async function broadcastOnlineFriends() {
  for (const [ws, info] of clients) {
    const friendLogins = await getFriends(info.login);
    const online = [];

    for (const [, other] of clients) {
      if (friendLogins.includes(other.login)) {
        online.push({
          login: other.login,
          nickname: other.nickname,
          avatar: buildAvatar(other.login, other.nickname, other.avatarImage)
        });
      }
    }

    send(ws, { type: 'online_friends', users: online });
  }
}

function isBusy(login) {
  return inCall.has(login);
}

function clearCall(login) {
  const peer = inCall.get(login);
  inCall.delete(login);
  if (peer && inCall.get(peer) === login) {
    inCall.delete(peer);
  }
}

/* ================= WEBSOCKET ================= */

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
      /* REGISTER */
      if (data.type === 'register') {
        const login = typeof data.login === 'string' ? data.login.trim() : '';
        const password = typeof data.password === 'string' ? data.password : '';

        if (!login || !password) {
          send(ws, { type: 'error', message: 'Введите логин и пароль' });
          return;
        }

        const exists = await pool.query(
          `SELECT login FROM users WHERE login = $1`,
          [login]
        );

        if (exists.rows.length) {
          send(ws, { type: 'error', message: 'Логин занят' });
          return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query(
          `
          INSERT INTO users (login, password, nickname, avatarImage)
          VALUES ($1, $2, $3, $4)
          `,
          [login, hashedPassword, login, null]
        );

        send(ws, { type: 'register_ok' });
        return;
      }

      /* LOGIN */
      if (data.type === 'login') {
        const login = typeof data.login === 'string' ? data.login.trim() : '';
        const password = typeof data.password === 'string' ? data.password : '';

        if (!login || !password) {
          send(ws, { type: 'error', message: 'Введите логин и пароль' });
          return;
        }

        const result = await pool.query(
          `
          SELECT login, password, nickname, avatarImage
          FROM users
          WHERE login = $1
          `,
          [login]
        );

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
            await pool.query(
              `
              UPDATE users
              SET password = $1
              WHERE login = $2
              `,
              [upgradedHash, user.login]
            );
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
          avatarImage: user.avatarimage
        });

        send(ws, {
          type: 'login_ok',
          login: user.login,
          nickname: user.nickname,
          avatar: buildAvatar(user.login, user.nickname, user.avatarimage),
          friends: await getFriendUsers(user.login),
          unread: await getUnreadMap(user.login)
        });

        const requests = await pool.query(
          `
          SELECT fromUser
          FROM friend_requests
          WHERE toUser = $1
          `,
          [user.login]
        );

        for (const r of requests.rows) {
          send(ws, {
            type: 'friend_request',
            from: r.fromuser
          });
        }

        await broadcastOnlineFriends();
        return;
      }

      if (!userLogin) return;

      const me = clients.get(ws);

      /* UPDATE AVATAR */
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

        await pool.query(
          `
          UPDATE users
          SET avatarImage = $1
          WHERE login = $2
          `,
          [image, userLogin]
        );

        const updatedResult = await pool.query(
          `
          SELECT login, nickname, avatarImage
          FROM users
          WHERE login = $1
          `,
          [userLogin]
        );

        const updatedUser = updatedResult.rows[0];

        if (updatedUser) {
          clients.set(ws, {
            login: updatedUser.login,
            nickname: updatedUser.nickname,
            avatarImage: updatedUser.avatarimage
          });

          const payload = {
            type: 'avatar_updated',
            login: updatedUser.login,
            nickname: updatedUser.nickname,
            avatar: buildAvatar(
              updatedUser.login,
              updatedUser.nickname,
              updatedUser.avatarimage
            )
          };

          for (const [clientWs] of clients) {
            send(clientWs, payload);
          }

          send(ws, {
            type: 'friends_list',
            friends: await getFriendUsers(userLogin)
          });

          await broadcastOnlineFriends();
        }

        return;
      }

      /* LOAD CHAT HISTORY */
      if (data.type === 'get_messages') {
        if (!data.with) return;

        send(ws, {
          type: 'chat_history',
          with: data.with,
          messages: await getChatHistory(userLogin, data.with)
        });
        return;
      }

      /* FRIEND REQUEST */
      if (data.type === 'friend_request') {
        if (!data.to || data.to === userLogin) return;

        const target = await pool.query(
          `SELECT login FROM users WHERE login = $1`,
          [data.to]
        );

        if (!target.rows.length) {
          send(ws, { type: 'error', message: 'Пользователь не найден' });
          return;
        }

        const alreadyFriends = await pool.query(
          `
          SELECT 1
          FROM friends
          WHERE (user1 = $1 AND user2 = $2)
             OR (user1 = $2 AND user2 = $1)
          LIMIT 1
          `,
          [userLogin, data.to]
        );

        if (alreadyFriends.rows.length) {
          send(ws, { type: 'error', message: 'Вы уже друзья' });
          return;
        }

        await pool.query(
          `
          INSERT INTO friend_requests (fromUser, toUser)
          VALUES ($1, $2)
          ON CONFLICT (fromUser, toUser) DO NOTHING
          `,
          [userLogin, data.to]
        );

        sendToUser(data.to, {
          type: 'friend_request',
          from: userLogin,
          fromNick: me.nickname
        });

        return;
      }

      /* FRIEND ACCEPT */
      if (data.type === 'friend_accept') {
        if (!data.from || !data.to) return;

        await pool.query(
          `
          INSERT INTO friends (user1, user2)
          VALUES ($1, $2)
          ON CONFLICT (user1, user2) DO NOTHING
          `,
          [data.from, data.to]
        );

        await pool.query(
          `
          DELETE FROM friend_requests
          WHERE fromUser = $1 AND toUser = $2
          `,
          [data.to, data.from]
        );

        sendToUser(data.to, {
          type: 'friend_accept',
          from: userLogin,
          fromNick: me.nickname
        });

        send(ws, {
          type: 'friends_list',
          friends: await getFriendUsers(userLogin)
        });

        sendToUser(data.to, {
          type: 'friends_list',
          friends: await getFriendUsers(data.to)
        });

        await broadcastOnlineFriends();
        return;
      }

      /* MESSAGE */
      if (data.type === 'message') {
        if (!data.to || typeof data.text !== 'string' || !data.text.trim()) return;

        const messageText = data.text.trim();
        const messageTime = Date.now();

        const insertResult = await pool.query(
          `
          INSERT INTO messages (fromUser, toUser, text, time)
          VALUES ($1, $2, $3, $4)
          RETURNING id
          `,
          [userLogin, data.to, messageText, messageTime]
        );

        await pool.query(
          `
          INSERT INTO unread (fromUser, toUser, count)
          VALUES ($1, $2, 1)
          ON CONFLICT (fromUser, toUser)
          DO UPDATE SET count = unread.count + 1
          `,
          [userLogin, data.to]
        );

        const unreadResult = await pool.query(
          `
          SELECT count
          FROM unread
          WHERE fromUser = $1 AND toUser = $2
          `,
          [userLogin, data.to]
        );

        const unreadCount = unreadResult.rows[0]?.count || 0;

        const msgData = {
          id: insertResult.rows[0]?.id,
          type: 'message',
          from: userLogin,
          to: data.to,
          text: messageText,
          time: messageTime,
          fromNick: me.nickname,
          avatar: buildAvatar(userLogin, me.nickname, me.avatarImage),
          unread: unreadCount,
          deleted: false
        };

        sendToUser(userLogin, msgData);
        sendToUser(data.to, msgData);
        return;
      }


      /* DELETE MESSAGE */
      if (data.type === 'delete_message') {
        const messageId = Number(data.id);
        if (!Number.isFinite(messageId)) return;

        const existing = await pool.query(
          `
          SELECT id, fromUser, toUser
          FROM messages
          WHERE id = $1
          LIMIT 1
          `,
          [messageId]
        );

        const message = existing.rows[0];
        if (!message) return;
        if (message.fromuser !== userLogin) return;

        await pool.query(
          `
          UPDATE messages
          SET text = $1, deleted = TRUE
          WHERE id = $2
          `,
          ['__deleted__', messageId]
        );

        const payload = {
          type: 'message_deleted',
          id: messageId,
          from: message.fromuser,
          to: message.touser,
          text: '__deleted__'
        };

        sendToUser(message.fromuser, payload);
        sendToUser(message.touser, payload);
        return;
      }

      /* READ */
      if (data.type === 'read') {
        if (!data.from) return;

        await pool.query(
          `
          DELETE FROM unread
          WHERE fromUser = $1 AND toUser = $2
          `,
          [data.from, userLogin]
        );

        send(ws, {
          type: 'unread_update',
          unread: await getUnreadMap(userLogin)
        });
        return;
      }

      /* CALLS */
      const callTypes = new Set([
        'call_offer',
        'call_answer',
        'call_ice',
        'call_cancel',
        'call_decline',
        'call_end',
        'call_busy'
      ]);

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

        if (
          (data.type === 'call_answer' || data.type === 'call_ice') &&
          inCall.get(userLogin) !== to
        ) {
          return;
        }

        if (
          data.type === 'call_cancel' ||
          data.type === 'call_decline' ||
          data.type === 'call_end' ||
          data.type === 'call_busy'
        ) {
          clearCall(userLogin);
          clearCall(to);
        }

        sendToUser(to, {
          ...data,
          from: userLogin,
          fromNick: me.nickname
        });

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

      if (peer) {
        sendToUser(peer, {
          type: 'call_end',
          from: info.login
        });
      }

      clearCall(info.login);
    }

    try {
      await broadcastOnlineFriends();
    } catch (err) {
      console.error('broadcastOnlineFriends on close error:', err);
    }
  });
});

/* START */
const PORT = process.env.PORT || 3000;

initDb()
  .then(() => {
    server.listen(PORT, () => {
      console.log('Server started on port ' + PORT);
    });
  })
  .catch(err => {
    console.error('Database init error:', err);
    process.exit(1);
  });