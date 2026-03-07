const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Database = require('better-sqlite3');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.static('public'));

/* ================= DATABASE ================= */

const db = new Database('chat.db');

/* USERS */
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
  login TEXT PRIMARY KEY,
  password TEXT NOT NULL,
  nickname TEXT NOT NULL
)
`).run();

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
  return `hsl(${hash % 360},70%,55%)`;
}

function getFriends(login) {
  return db.prepare(`
    SELECT user1 AS friend FROM friends WHERE user2 = ?
    UNION
    SELECT user2 AS friend FROM friends WHERE user1 = ?
  `).all(login, login).map(r => r.friend);
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
          avatar: {
            letter: other.nickname[0].toUpperCase(),
            color: avatarColor(other.login)
          }
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

      const exists = db.prepare(
        `SELECT login FROM users WHERE login = ?`
      ).get(data.login);

      if (exists) {
        send(ws,{ type:'error', message:'Логин занят' });
        return;
      }

      db.prepare(`
        INSERT INTO users (login,password,nickname)
        VALUES (?,?,?)
      `).run(data.login,data.password,data.login);

      send(ws,{ type:'register_ok' });
      return;
    }

    /* LOGIN */

    if (data.type === 'login') {

      const user = db.prepare(`
        SELECT login,nickname FROM users
        WHERE login=? AND password=?
      `).get(data.login,data.password);

      if (!user) {
        send(ws,{ type:'error', message:'Неверный логин или пароль' });
        return;
      }

      userLogin = user.login;

      clients.set(ws,user);

      send(ws,{
        type:'login_ok',
        login:user.login,
        nickname:user.nickname,
        avatar:{
          letter:user.nickname[0].toUpperCase(),
          color:avatarColor(user.login)
        }
      });

      /* отправляем заявки */

      const requests = db.prepare(`
        SELECT fromUser FROM friend_requests
        WHERE toUser=?
      `).all(user.login);

      for (const r of requests) {
        send(ws,{
          type:'friend_request',
          from:r.fromUser
        });
      }

      broadcastOnlineFriends();
      return;
    }

    if (!userLogin) return;

    const me = clients.get(ws);

    /* FRIEND REQUEST */

    if (data.type === 'friend_request') {

      db.prepare(`
        INSERT OR IGNORE INTO friend_requests (fromUser,toUser)
        VALUES (?,?)
      `).run(userLogin,data.to);

      sendToUser(data.to,{
        type:'friend_request',
        from:userLogin,
        fromNick:me.nickname
      });

      return;
    }

    /* FRIEND ACCEPT */

    if (data.type === 'friend_accept') {

      db.prepare(`
        INSERT OR IGNORE INTO friends (user1,user2)
        VALUES (?,?)
      `).run(data.from,data.to);

      db.prepare(`
        DELETE FROM friend_requests
        WHERE fromUser=? AND toUser=?
      `).run(data.to,data.from);

      sendToUser(data.to,{
        type:'friend_accept',
        from:userLogin,
        fromNick:me.nickname
      });

      broadcastOnlineFriends();
      return;
    }

    /* MESSAGE */

    if (data.type === 'message') {

      db.prepare(`
        INSERT INTO messages (fromUser,toUser,text,time)
        VALUES (?,?,?,?)
      `).run(userLogin,data.to,data.text,Date.now());

      db.prepare(`
        INSERT INTO unread (fromUser,toUser,count)
        VALUES (?,?,1)
        ON CONFLICT(fromUser,toUser)
        DO UPDATE SET count=count+1
      `).run(userLogin,data.to);

      const unreadCount = db.prepare(`
        SELECT count FROM unread
        WHERE fromUser=? AND toUser=?
      `).get(userLogin,data.to)?.count || 0;

      const msgData={
        ...data,
        from:userLogin,
        fromNick:me.nickname,
        avatar:{
          letter:userLogin[0].toUpperCase(),
          color:avatarColor(userLogin)
        },
        unread:unreadCount
      };

      sendToUser(userLogin,msgData);
      sendToUser(data.to,msgData);

      return;
    }

    /* READ */

    if (data.type === 'read') {

      db.prepare(`
        DELETE FROM unread
        WHERE fromUser=? AND toUser=?
      `).run(data.from,userLogin);

      return;
    }

    /* CALLS */

    const callTypes=new Set([
      "call_offer","call_answer","call_ice",
      "call_cancel","call_decline","call_end","call_busy"
    ]);

    if (callTypes.has(data.type)) {

      const to=data.to;
      if(!to) return;

      if(data.type==="call_offer"){

        if(isBusy(to)){
          sendToUser(userLogin,{type:"call_busy"});
          return;
        }

        inCall.set(userLogin,to);
        inCall.set(to,userLogin);
      }

      if(
        data.type==="call_cancel"||
        data.type==="call_decline"||
        data.type==="call_end"
      ){
        clearCall(userLogin);
        clearCall(to);
      }

      sendToUser(to,{
        ...data,
        from:userLogin,
        fromNick:me.nickname
      });

      return;
    }

  });

  ws.on('close',()=>{

    const info=clients.get(ws);
    clients.delete(ws);

    if(info?.login){

      const peer=inCall.get(info.login);

      if(peer){
        sendToUser(peer,{
          type:"call_end",
          from:info.login
        });
      }

      clearCall(info.login);
    }

    broadcastOnlineFriends();

  });

});

/* START */

const PORT=process.env.PORT||3000;

server.listen(PORT,()=>{
  console.log("Server started on port "+PORT);
});