const http = require('http');
const net = require('net');
const { WebSocketServer } = require('ws');

const UUID = (process.env.UUID || '').toLowerCase().replace(/-/g, '');
const WS_PATH = process.env.WS_PATH || '/ws';
const SUB_PATH = process.env.SUB_PATH || '/sub-change-me';
const DOMAIN = process.env.DOMAIN || '';
const PORT = process.env.PORT || 8100;
const HOST = process.env.IP || '::';

const link = `vless://${process.env.UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=${encodeURIComponent(WS_PATH)}#Alwaysdata`;

const server = http.createServer((req, res) => {
  if (req.url === SUB_PATH) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end(Buffer.from(link).toString('base64'));
  }
  if (req.url === '/health') return res.end('ok');
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<!doctype html><title>Notes</title><h1>Personal notes</h1><p>Coming soon.</p>');
});

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  if (req.url.split('?')[0] !== WS_PATH) return socket.destroy();
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws));
});

wss.on('connection', ws => {
  let remote = null;
  ws.on('message', data => {
    if (remote) return remote.write(data);
    const b = Buffer.from(data);
    if (b.length < 24) return ws.close();
    const ver = b[0];
    if (b.subarray(1, 17).toString('hex') !== UUID) return ws.close();
    let i = 18 + b[17];
    if (b[i++] !== 1) return ws.close();            // TCP only
    const port = b.readUInt16BE(i); i += 2;
    const atyp = b[i++];
    let host;
    if (atyp === 1) { host = [...b.subarray(i, i + 4)].join('.'); i += 4; }
    else if (atyp === 2) { const l = b[i++]; host = b.subarray(i, i + l).toString(); i += l; }
    else if (atyp === 3) {
      const p = []; for (let k = 0; k < 16; k += 2) p.push(b.readUInt16BE(i + k).toString(16));
      host = p.join(':'); i += 16;
    } else return ws.close();

    remote = net.connect(port, host);
    remote.setNoDelay(true);
    let first = true;
    remote.on('data', d => {
      if (ws.readyState !== 1) return;
      if (first) { first = false; ws.send(Buffer.concat([Buffer.from([ver, 0]), d])); }
      else ws.send(d);
    });
    remote.on('error', () => ws.close());
    remote.on('close', () => ws.close());
    const payload = b.subarray(i);
    if (payload.length) remote.write(payload);
  });
  ws.on('close', () => remote && remote.destroy());
  ws.on('error', () => remote && remote.destroy());
});

server.listen(PORT, HOST, () => console.log('listening', HOST, PORT));