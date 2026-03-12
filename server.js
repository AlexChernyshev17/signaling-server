const http = require('http');
const { WebSocketServer } = require('ws');
const https = require('https');

// ── FCM V1 via Service Account ───────────────────────────────
const SERVICE_ACCOUNT = {
  project_id: "pozvonimnepozvoni-f49f8",
  client_email: "firebase-adminsdk-fbsvc@pozvonimnepozvoni-f49f8.iam.gserviceaccount.com",
  private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCYjFST7s5nWovg\ncuNwm2Pe2iV0EMYXkihQJ9/SB9m/5TjiEhxzO5wYIpMsP2+n9QbeQbkX24iio9yZ\nw/vQcVOJYBYl5jqmQkJCca0P32LLiCA5YE9893Xwy8nYylL9cA4fUQjyvolQ9Fpy\nMJgZ/DEB/gwBKBc7c19o4yeIgv8vJ4zhngbEgLiFhj/TnCi27iH/NubGzv4/5kUe\nSsVSsD2xkcKKHkpKWI1MWH9H9cIauCJR9bu64R9dhfHbaYBemNIRSGlhGO6WAuew\nT0e6iRGsTEXm6Ic362P8hWAfMtBuJZoP2iJyfBlHDX3BAVWDPlf3118trCaBHEhH\nP94fvy0PAgMBAAECggEAJS6fNueQO7TgPzcBpOLbNuhpFJ86CWjAlrkBXwo20wUm\nFkRf1t6Cr4dN5A0aRA//OpE+ckg6R5o1HO2eJTJaMDPRci9pwDiKOfPHQQUr6Xwm\njpWhCk6u2qBxdHvsOoXji1KPIcu7YJYOraKWkE7eCyRG/Mku0HjQmpozepyjYnSb\nEy/fMm9w4SVNmkzlVF383nac8FLj4SuDwCXJgYvHeJSscbGZZbLghGYaW89EeOhY\ngjFwojMIlal5Zzai77HyzQssE6g1xeVEVOmbFyFQgeVATfw8luTzskOHC9+w/0ia\nBCzXiHCv3BwP5VthLVC07xggBmrZlD08xsZDDivU8QKBgQDIvv4jWTzGKNoCNNhY\ngCGdhObeIquORzQpvOiX5k+j3vnWHSqrcjCXEpEpTQLM5D0xVS+e1pwPU55w8p9f\nwxGltzcyhVlD/s/23sxvY/4PbkO4GUP6TBtmZPeq7faBEuohtVSuxbQuP8fwEFBu\nNAB9ouV7gELeOj73csHNnSdP8wKBgQDCiTVG51xhoy85v4vTA6/PofgoEbos0kZl\nrruLUIkZMRzb8ecqsug9IvKYErSk4zIg3VTkQuzHVVqeGQb96/8i4Wxy2LswLpir\nnXWjupIxuV+rFD6uA0gtK3yBwiGYvXJCJB16xRrdM4E7/63RaCXfuEHfmRu3Ykm7\nTo/rlEWRdQKBgQC652iCzOEStpJUH5OWwqWJnWW+SJVmANGGUsZUNzDLKB2AxuMl\ngUnQPo883uDOl2qJ9gBCaRogAwCvtJXCeUKDAhS4SwOTlTlXZpT82SKAh28xhwSN\nlDKmoTcexDQQdOXcwJG5r4VU0jl7QBVCpdQXJYV3+TFI6v4ZMZVTtRAXFQKBgHXV\niIjvQVz+7G8tYDOsCwVY1ajnu/7ES9HxujYTzUeOIS305BJQFi5aCdolknhCCi4w\nAujUxPmk8OPMwxhxp7RoGTmjoBb6Uo25LfXD4CPwZkuJUsIyyLhbm+o5PgJ31krL\n93NTCwer1/8QyyeJz08pG/Wll01IYuLrHnAS+uS1AoGAM98oeWw4Xgb9BGipkOP6\nla593YcLU2o9QwrigMdO8ihhxIPLwcx30cMMeq++62kXEggjLFaecAdA7zS226AV\ndCrQ8VPZt6KowNvllFOx/hIo/d1EgsgA0cMIrqwv9+OTP9OUsICnkwx2kS25uUua\nzbOi1hzJv91AMhBUm895fRg=\n-----END PRIVATE KEY-----\n"
};

// Simple JWT for Google OAuth2
function makeJWT() {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: SERVICE_ACCOUNT.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600
  })).toString('base64url');

  const crypto = require('crypto');
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(`${header}.${payload}`);
  const sig = sign.sign(SERVICE_ACCOUNT.private_key, 'base64url');
  return `${header}.${payload}.${sig}`;
}

let fcmToken = null, fcmTokenExpiry = 0;

async function getFCMToken() {
  if (fcmToken && Date.now() < fcmTokenExpiry) return fcmToken;
  const jwt = makeJWT();
  const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;
  return new Promise((res, rej) => {
    const req = https.request({
      hostname: 'oauth2.googleapis.com', path: '/token', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': body.length }
    }, r => {
      let d = ''; r.on('data', c => d += c);
      r.on('end', () => {
        const j = JSON.parse(d);
        fcmToken = j.access_token;
        fcmTokenExpiry = Date.now() + (j.expires_in - 60) * 1000;
        res(fcmToken);
      });
    });
    req.on('error', rej); req.write(body); req.end();
  });
}

async function sendPush(fcmRegistrationToken, callerName) {
  if (!fcmRegistrationToken) return;
  try {
    const token = await getFCMToken();
    const body = JSON.stringify({
      message: {
        token: fcmRegistrationToken,
        notification: { title: '💌 Вас зовут на свидание!', body: 'Открой приложение' },
        webpush: {
          notification: {
            title: '💌 Вас зовут на свидание!',
            body: 'Открой приложение',
            icon: '/apple-touch-icon.png',
            badge: '/apple-touch-icon.png',
            vibrate: [200, 100, 200],
            requireInteraction: true,
            actions: [{ action: 'answer', title: 'Ответить' }]
          },
          fcm_options: { link: 'https://alexchernyshev17.github.io/PozvoniMnePozvoni/' }
        }
      }
    });
    https.request({
      hostname: 'fcm.googleapis.com',
      path: `/v1/projects/${SERVICE_ACCOUNT.project_id}/messages:send`,
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, r => { let d=''; r.on('data',c=>d+=c); r.on('end',()=>console.log('FCM:', d)); }).on('error', e => console.error('FCM error:', e)).end(body);
  } catch(e) { console.error('Push failed:', e.message); }
}

// ── WebSocket Server ─────────────────────────────────────────
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Lesha & Ariana signaling OK');
});

const wss = new WebSocketServer({ server });
let peers = {}; // role -> { ws, fcmToken, name }

wss.on('connection', ws => {
  let myRole = null;

  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'register') {
      myRole = msg.role;
      peers[myRole] = { ws, fcmToken: msg.fcmToken || null, name: msg.name || myRole };
      console.log(`${myRole} connected, fcm: ${!!msg.fcmToken}`);
      broadcastPresence();
      return;
    }

    if (msg.type === 'fcm_token') {
      if (peers[myRole]) peers[myRole].fcmToken = msg.token;
      return;
    }

    // Forward to other peer
    const other = Object.values(peers).find(p => p.ws !== ws && p.ws.readyState === 1);

    if (msg.type === 'offer') {
      // Send push to offline/background peer
      const otherPeer = Object.values(peers).find(p => p.ws !== ws);
      if (otherPeer && otherPeer.fcmToken) {
        sendPush(otherPeer.fcmToken, '');
      }
    }

    if (other) other.ws.send(JSON.stringify(msg));
  });

  ws.on('close', () => {
    if (myRole) { delete peers[myRole]; broadcastPresence(); }
  });
  ws.on('error', () => {});
});

function broadcastPresence() {
  const count = peers.filter(p => p.ws.readyState === 1).length;
  const str = JSON.stringify({ type: 'presence', count });
  peers.forEach(p => { if (p.ws.readyState === 1) p.ws.send(str); });
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server on port ${PORT}`));
