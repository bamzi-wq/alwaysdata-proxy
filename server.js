const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const UUID_RAW = process.env.UUID || '';
const UUID = UUID_RAW.toLowerCase().replace(/-/g, '');
const UUID_BUF = Buffer.from(UUID, 'hex');
const TROJAN_HASH = crypto.createHash('sha224').update(UUID_RAW).digest('hex');

const WS_PATH = process.env.WS_PATH || '/ws';
const TR_PATH = process.env.TR_PATH || WS_PATH + '-tr';
const HU_PATH = process.env.HU_PATH || WS_PATH + '-hu';
const SUB_PATH = process.env.SUB_PATH || '/sub-change-me';
const DOMAIN = process.env.DOMAIN || '';
const PORT = process.env.PORT || 8100;
const HOST = process.env.IP || '::';

const q = p => encodeURIComponent(p);
const links = [
  `vless://${UUID_RAW}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=${q(WS_PATH)}#AD-VLESS-WS`,
  `trojan://${UUID_RAW}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=${q(TR_PATH)}#AD-Trojan-WS`,
  `vless://${UUID_RAW}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=httpupgrade&host=${DOMAIN}&path=${q(HU_PATH)}#AD-VLESS-HU`,
];

// ---------- parsers ----------
function parseVless(b) {
  if (b.length < 24) return null;
  if (!b.subarray(1, 17).equals(UUID_BUF)) return null;
  let i = 18 + b[17];
  if (b[i++] !== 1) return null; // TCP only
  const port = b.readUInt16BE(i); i += 2;
  const atyp = b[i++];
  let host;
  if (atyp === 1) { host = [...b.subarray(i, i + 4)].join('.'); i += 4; }
  else if (atyp === 2) { const l = b[i++]; host = b.subarray(i, i + l).toString(); i += l; }
  else if (atyp === 3) {
    const p = []; for (let k = 0; k < 16; k += 2) p.push(b.readUInt16BE(i + k).toString(16));
    host = p.join(':'); i += 16;
  } else return null;
  return { host, port, payload: b.subarray(i), respHead: Buffer.from([b[0], 0]) };
}

function parseTrojan(b) {
  if (b.length < 62) return null;
  if (b.subarray(0, 56).toString() !== TROJAN_HASH) return null;
  let i = 58;                       // skip hash + CRLF
  if (b[i++] !== 1) return null;    // TCP only
  const atyp = b[i++];
  let host;
  if (atyp === 1) { host = [...b.subarray(i, i + 4)].join('.'); i += 4; }
  else if (atyp === 3) { const l = b[i++]; host = b.subarray(i, i + l).toString(); i += l; }
  else if (atyp === 4) {
    const p = []; for (let k = 0; k < 16; k += 2) p.push(b.readUInt16BE(i + k).toString(16));
    host = p.join(':'); i += 16;
  } else return null;
  const port = b.readUInt16BE(i); i += 2;
  i += 2;                           // CRLF
  return { host, port, payload: b.subarray(i), respHead: null };
}

// ---------- shared session ----------
function session(proto, send, close) {
  let remote = null;
  return {
    data(chunk) {
      if (remote) return remote.write(chunk);
      const r = proto === 'trojan' ? parseTrojan(chunk) : parseVless(chunk);
      if (!r) return close();
      remote = net.connect(r.port, r.host);
      remote.setNoDelay(true);
      let head = r.respHead;
      remote.on('data', d => {
        if (head) { send(Buffer.concat([head, d])); head = null; }
        else send(d);
      });
      remote.on('error', close);
      remote.on('close', close);
      if (r.payload.length) remote.write(r.payload);
    },
    end() { if (remote) remote.destroy(); },
  };
}

// ---------- http ----------
const server = http.createServer((req, res) => {
  if (req.url === SUB_PATH) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end(Buffer.from(links.join('\n')).toString('base64'));
  }
  if (req.url === '/health') return res.end('ok');
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<!doctype html><title>Notes</title><h1>Personal notes</h1><p>Coming soon.</p>');
});

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const p = req.url.split('?')[0];

  if (p === WS_PATH || p === TR_PATH) {
    const proto = p === TR_PATH ? 'trojan' : 'vless';
    return wss.handleUpgrade(req, socket, head, ws => {
      const s = session(proto, d => { if (ws.readyState === 1) ws.send(d); }, () => ws.close());
      ws.on('message', d => s.data(Buffer.from(d)));
      ws.on('close', () => s.end());
      ws.on('error', () => s.end());
    });
  }

  if (p === HU_PATH) {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
    socket.setNoDelay(true);
    const s = session('vless', d => { if (socket.writable) socket.write(d); }, () => socket.destroy());
    if (head && head.length) s.data(head);
    socket.on('data', d => s.data(d));
    socket.on('close', () => s.end());
    socket.on('error', () => s.end());
    return;
  }

  socket.destroy();
});

process.on('uncaughtException', e => console.error('uncaught:', e.message));
process.on('unhandledRejection', e => console.error('unhandled:', e));

server.listen(PORT, HOST, () => console.log('listening', HOST, PORT));
