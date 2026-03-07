const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Отдаём index.html и остальные файлы из текущей папки.
app.use(express.static(__dirname));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '/public/index.html'));
});

/* ================= DATABASE ================= */

const db = new Database(path.join(__dirname, 'chat.db'));

db.pragma('journal_mode = WAL');

/* USERS */
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
  login TEXT PRIMARY KEY,
  password TEXT NOT NULL,
  nickname TEXT NOT NULL,
  avatarImage TEXT
)
`).run();

try {
  db.prepare(`ALTER TABLE users ADD COLUMN avatarImage TEXT`).run();
} catch {}

/* MESSAGES */
db.prepare(`
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fromUser TEXT NOT NULL,
  toUser TEXT NOT NULL,
  text TEXT NOT NULL,
  time INTEGER NOT NULL
)
`).run();

/* FRIENDS */
db.prepare(`
CREATE TABLE IF NOT EXISTS friends (
  user1 TEXT NOT NULL,
  user2 TEXT NOT NULL,
  UNIQUE(user1, user2)
)
`).run();

/* FRIEND REQUESTS */
db.prepare(`
CREATE TABLE IF NOT EXISTS friend_requests (
  fromUser TEXT NOT NULL,
  toUser TEXT NOT NULL,
  UNIQUE(fromUser, toUser)
)
`).run();

/* UNREAD */
db.prepare(`
CREATE TABLE IF NOT EXISTS unread (
  fromUser TEXT,
  toUser TEXT,
  count INTEGER,
  UNIQUE(fromUser, toUser)
)
`).run();

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
    if (info.login === login) send(ws, data);
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

function getUserPublic(login) {
  const user = db.prepare(`
    SELECT login, nickname, avatarImage
    FROM users
    WHERE login = ?
  `).get(login);

  if (!user) return null;

  return {
    login: user.login,
    nickname: user.nickname,
    avatar: buildAvatar(user.login, user.nickname, user.avatarImage)
  };
}

function getFriends(login) {
  return db.prepare(`
    SELECT user1 AS friend FROM friends WHERE user2 = ?
    UNION
    SELECT user2 AS friend FROM friends WHERE user1 = ?
  `).all(login, login).map(r => r.friend);
}

function getFriendUsers(login) {
  const friends = getFriends(login);
  if (!friends.length) return [];

  return friends
    .map(friendLogin => getUserPublic(friendLogin))
    .filter(Boolean);
}

function getUnreadMap(login) {
  const rows = db.prepare(`
    SELECT fromUser, count FROM unread WHERE toUser = ?
  `).all(login);

  const result = {};
  for (const row of rows) result[row.fromUser] = row.count;
  return result;
}

function getChatHistory(userA, userB) {
  const rows = db.prepare(`
    SELECT id, fromUser, toUser, text, time
    FROM messages
    WHERE (fromUser = ? AND toUser = ?)
       OR (fromUser = ? AND toUser = ?)
    ORDER BY time ASC, id ASC
  `).all(userA, userB, userB, userA);

  return rows.map(row => {
    const sender = getUserPublic(row.fromUser);
    return {
      id: row.id,
      from: row.fromUser,
      to: row.toUser,
      text: row.text,
      time: row.time,
      avatar: sender?.avatar || buildAvatar(row.fromUser, row.fromUser)
    };
  });
}

function broadcastOnlineFriends() {
  for (const [ws, info] of clients) {
    const friends = getFriends(info.login);
    const online = [];

    for (const [, other] of clients) {
      if (friends.includes(other.login)) {
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

  ws.on('message', msg => {
    let data;
    try { data = JSON.parse(msg); } catch { return; }

    /* REGISTER */
    if (data.type === 'register') {
      const exists = db.prepare(`SELECT login FROM users WHERE login = ?`).get(data.login);

      if (exists) {
        send(ws, { type: 'error', message: 'Логин занят' });
        return;
      }

      db.prepare(`
        INSERT INTO users (login, password, nickname, avatarImage)
        VALUES (?, ?, ?, NULL)
      `).run(data.login, data.password, data.login);

      send(ws, { type: 'register_ok' });
      return;
    }

    /* LOGIN */
    if (data.type === 'login') {
      const user = db.prepare(`
        SELECT login, nickname, avatarImage FROM users
        WHERE login = ? AND password = ?
      `).get(data.login, data.password);

      if (!user) {
        send(ws, { type: 'error', message: 'Неверный логин или пароль' });
        return;
      }

      userLogin = user.login;
      clients.set(ws, user);

      send(ws, {
        type: 'login_ok',
        login: user.login,
        nickname: user.nickname,
        avatar: buildAvatar(user.login, user.nickname, user.avatarImage),
        friends: getFriendUsers(user.login),
        unread: getUnreadMap(user.login)
      });

      const requests = db.prepare(`
        SELECT fromUser FROM friend_requests
        WHERE toUser = ?
      `).all(user.login);

      for (const r of requests) {
        send(ws, {
          type: 'friend_request',
          from: r.fromUser
        });
      }

      broadcastOnlineFriends();
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

      db.prepare(`
        UPDATE users
        SET avatarImage = ?
        WHERE login = ?
      `).run(image, userLogin);

      const updatedUser = db.prepare(`
        SELECT login, nickname, avatarImage
        FROM users
        WHERE login = ?
      `).get(userLogin);

      if (updatedUser) {
        clients.set(ws, updatedUser);

        const payload = {
          type: 'avatar_updated',
          login: updatedUser.login,
          nickname: updatedUser.nickname,
          avatar: buildAvatar(updatedUser.login, updatedUser.nickname, updatedUser.avatarImage)
        };

        for (const [clientWs] of clients) {
          send(clientWs, payload);
        }

        send(ws, {
          type: 'friends_list',
          friends: getFriendUsers(userLogin)
        });

        broadcastOnlineFriends();
      }

      return;
    }

    /* LOAD CHAT HISTORY */
    if (data.type === 'get_messages') {
      if (!data.with) return;
      send(ws, {
        type: 'chat_history',
        with: data.with,
        messages: getChatHistory(userLogin, data.with)
      });
      return;
    }

    /* FRIEND REQUEST */
    if (data.type === 'friend_request') {
      if (!data.to || data.to === userLogin) return;

      db.prepare(`
        INSERT OR IGNORE INTO friend_requests (fromUser, toUser)
        VALUES (?, ?)
      `).run(userLogin, data.to);

      sendToUser(data.to, {
        type: 'friend_request',
        from: userLogin,
        fromNick: me.nickname
      });

      return;
    }

    /* FRIEND ACCEPT */
    if (data.type === 'friend_accept') {
      db.prepare(`
        INSERT OR IGNORE INTO friends (user1, user2)
        VALUES (?, ?)
      `).run(data.from, data.to);

      db.prepare(`
        DELETE FROM friend_requests
        WHERE fromUser = ? AND toUser = ?
      `).run(data.to, data.from);

      sendToUser(data.to, {
        type: 'friend_accept',
        from: userLogin,
        fromNick: me.nickname
      });

      // Обновляем списки друзей у обеих сторон.
      send(ws, {
        type: 'friends_list',
        friends: getFriendUsers(userLogin)
      });
      sendToUser(data.to, {
        type: 'friends_list',
        friends: getFriendUsers(data.to)
      });

      broadcastOnlineFriends();
      return;
    }

    /* MESSAGE */
    if (data.type === 'message') {
      const messageTime = Date.now();

      db.prepare(`
        INSERT INTO messages (fromUser, toUser, text, time)
        VALUES (?, ?, ?, ?)
      `).run(userLogin, data.to, data.text, messageTime);

      db.prepare(`
        INSERT INTO unread (fromUser, toUser, count)
        VALUES (?, ?, 1)
        ON CONFLICT(fromUser, toUser)
        DO UPDATE SET count = count + 1
      `).run(userLogin, data.to);

      const unreadCount = db.prepare(`
        SELECT count FROM unread
        WHERE fromUser = ? AND toUser = ?
      `).get(userLogin, data.to)?.count || 0;

      const msgData = {
        type: 'message',
        from: userLogin,
        to: data.to,
        text: data.text,
        time: messageTime,
        fromNick: me.nickname,
        avatar: buildAvatar(userLogin, me.nickname, me.avatarImage),
        unread: unreadCount
      };

      sendToUser(userLogin, msgData);
      sendToUser(data.to, msgData);
      return;
    }

    /* READ */
    if (data.type === 'read') {
      db.prepare(`
        DELETE FROM unread
        WHERE fromUser = ? AND toUser = ?
      `).run(data.from, userLogin);

      send(ws, {
        type: 'unread_update',
        unread: getUnreadMap(userLogin)
      });
      return;
    }

    /* CALLS */
    const callTypes = new Set([
      'call_offer', 'call_answer', 'call_ice',
      'call_cancel', 'call_decline', 'call_end', 'call_busy'
    ]);

    if (callTypes.has(data.type)) {
      const to = data.to;
      if (!to) return;

      if (data.type === 'call_offer') {
        if (isBusy(to)) {
          sendToUser(userLogin, { type: 'call_busy' });
          return;
        }

        inCall.set(userLogin, to);
        inCall.set(to, userLogin);
      }

      if (
        data.type === 'call_cancel' ||
        data.type === 'call_decline' ||
        data.type === 'call_end'
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
  });

  ws.on('close', () => {
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

    broadcastOnlineFriends();
  });
});

/* START */
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('Server started on port ' + PORT);
});
