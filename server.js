const http = require('http');
const { WebSocketServer } = require('ws');

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Lesha & Ariana signaling server OK');
});

const wss = new WebSocketServer({ server });

let peers = {}; // { edinburgh: ws, moscow: ws }

wss.on('connection', (ws) => {
  let myRole = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // Register as caller or receiver
    if (msg.type === 'register') {
      myRole = msg.role; // 'edinburgh' or 'moscow'
      peers[myRole] = ws;
      console.log(`${myRole} connected`);
      // Tell both sides who is online
      broadcast({ type: 'presence', online: Object.keys(peers) });
      return;
    }

    // Forward any signaling message to the other peer
    const otherRole = Object.keys(peers).find(r => r !== myRole && peers[r] === peers[r]);
    const other = Object.values(peers).find(p => p !== ws && p.readyState === 1);
    if (other) other.send(JSON.stringify(msg));
  });

  ws.on('close', () => {
    if (myRole) {
      delete peers[myRole];
      console.log(`${myRole} disconnected`);
      broadcast({ type: 'presence', online: Object.keys(peers) });
    }
  });

  ws.on('error', () => {});
});

function broadcast(msg) {
  const str = JSON.stringify(msg);
  Object.values(peers).forEach(ws => {
    if (ws.readyState === 1) ws.send(str);
  });
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
