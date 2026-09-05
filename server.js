// Node relay: WebSocket (client bridge) <-> raw TCP (Telegram DC).
// Port of deno-relay.ts to Node for GitHub Codespaces (no Deno needed).
import { createServer } from "node:http";
import net from "node:net";
import { WebSocketServer } from "ws";

const PORT = parseInt(process.env.PORT || "8000", 10);

const DC_TABLE = {
  "1": "149.154.175.50", "2": "149.154.161.144", "3": "149.154.175.100",
  "4": "91.108.4.220", "5": "91.108.56.124", "203": "91.105.192.100",
};

function toBytes(data) {
  if (typeof data === "string") return Buffer.from(data, "utf8");
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (Buffer.isBuffer(data)) return data;
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  return Buffer.alloc(0);
}

async function obfuscatedPacket(tag = 0xeeeeeeee) {
  let raw;
  for (let attempt = 0; attempt < 128; attempt++) {
    raw = new Uint8Array(64);
    crypto.getRandomValues(raw);
    new DataView(raw.buffer).setUint32(56, tag, true);
    const first = raw[3] * 0x1000000 + raw[2] * 0x10000 + raw[1] * 0x100 + raw[0];
    const second = raw[7] * 0x1000000 + raw[6] * 0x10000 + raw[5] * 0x100 + raw[4];
    if (raw[0] === 0xef) continue;
    if ([0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0x02010316, 0xdddddddd, 0xeeeeeeee].includes(first)) continue;
    if (second === 0) continue;
    break;
  }
  const key = raw.subarray(8, 40);
  const counter = raw.subarray(40, 56);
  let frame;
  if (tag === 0xefefefef) {
    frame = new Uint8Array(21);
    frame[0] = 5;
    frame.set([0xf1, 0x8e, 0x7e, 0xbe], 1);
    frame.set(crypto.getRandomValues(new Uint8Array(16)), 5);
  } else {
    frame = new Uint8Array(24);
    new DataView(frame.buffer).setUint32(0, 20, true);
    frame.set([0xf1, 0x8e, 0x7e, 0xbe], 4);
    frame.set(crypto.getRandomValues(new Uint8Array(16)), 8);
  }
  const aesKey = await crypto.subtle.importKey("raw", key, { name: "AES-CTR" }, false, ["encrypt"]);
  const combined = new Uint8Array(64 + frame.length);
  combined.set(raw, 0);
  combined.set(frame, 64);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-CTR", counter, length: 128 },
    aesKey,
    combined,
  ));
  const send = new Uint8Array(64 + frame.length);
  send.set(raw.subarray(0, 56), 0);
  send.set(encrypted.subarray(56), 56);
  const temp = new Uint8Array(48);
  for (let i = 0; i < 48; i++) temp[i] = raw[55 - i];
  return { send, dKey: temp.subarray(0, 32), dCounter: temp.subarray(32, 48) };
}

function hex(b) {
  return Array.from(b.slice(0, 80)).map((v) => v.toString(16).padStart(2, "0")).join("");
}

function connectHost(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port });
    const to = setTimeout(() => { sock.destroy(); reject(new Error("connect timeout")); }, timeoutMs);
    sock.on("connect", () => { clearTimeout(to); resolve(sock); });
    sock.on("error", (e) => { clearTimeout(to); reject(e); });
  });
}

async function tgProbe(dc, port, tag, timeoutMs) {
  let conn;
  try {
    conn = await connectHost(dc, port, timeoutMs);
  } catch (e) {
    return "CONNECT_ERR=" + e.message;
  }
  const { send, dKey, dCounter } = await obfuscatedPacket(tag);
  conn.write(Buffer.from(send));
  let out = "OPENED sent=" + send.length;
  try {
    const data = await new Promise((resolve) => {
      const to = setTimeout(() => { cleanup(); resolve(null); }, timeoutMs);
      const chunks = [];
      const onData = (c) => {
        chunks.push(c);
        if (chunks.length >= 1) { clearTimeout(to); cleanup(); resolve(Buffer.concat(chunks)); }
      };
      const onEnd = () => { clearTimeout(to); cleanup(); resolve(Buffer.from([])); };
      const onErr = (e) => { clearTimeout(to); cleanup(); resolve(null); };
      function cleanup() { conn.removeListener("data", onData); conn.removeListener("end", onEnd); conn.removeListener("error", onErr); }
      conn.on("data", onData);
      conn.on("end", onEnd);
      conn.on("error", onErr);
    });
    if (data === null) out += " read_err=timeout";
    else if (data.length === 0) out += " read=0 done=true";
    else {
      out += " read=" + data.length + " head=" + hex(data);
      try {
        const dAes = await crypto.subtle.importKey("raw", dKey, { name: "AES-CTR" }, false, ["decrypt"]);
        const dec = new Uint8Array(await crypto.subtle.decrypt(
          { name: "AES-CTR", counter: dCounter, length: 128 },
          dAes,
          data,
        ));
        const rlen = dec.length >= 4 ? new DataView(dec.buffer).getInt32(0, true) : -1;
        out += " dec_len=" + dec.length + " rlen=" + rlen + " dec=" + hex(dec);
        if (dec.length >= 8 && dec[4] === 0x63 && dec[5] === 0x24 && dec[6] === 0x16 && dec[7] === 0x05) {
          out += " RESPQ=YES";
        }
      } catch (de) {
        out += " dec_err=" + de.message;
      }
    }
  } catch (e) {
    out += " read_err=" + e.message;
  }
  try { conn.destroy(); } catch {}
  return out;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/tgchk") {
    const dc = url.searchParams.get("dc") || "149.154.175.50";
    const port = parseInt(url.searchParams.get("port") || "443", 10);
    const tag = url.searchParams.get("mtp") === "abr" ? 0xefefefef : 0xeeeeeeee;
    const timeoutMs = parseInt(url.searchParams.get("t") || "10000", 10);
    try {
      const out = await tgProbe(dc, port, tag, timeoutMs);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("TGCHK " + out);
    } catch (e) {
      res.writeHead(502, { "content-type": "text/plain" });
      res.end("TGCHK_ERR: " + e.message);
    }
    return;
  }
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("node tg-relay ok");
});

const wss = new WebSocketServer({ server });

wss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://x");
  let host = null;
  let port = 443;
  if (url.pathname === "/apiws") {
    const dst = url.searchParams.get("dst");
    const dc = url.searchParams.get("dc") || "";
    host = dst || DC_TABLE[dc] || null;
  } else if (url.pathname === "/ws") {
    host = url.searchParams.get("host");
  }
  if (url.searchParams.has("port")) {
    const p = parseInt(url.searchParams.get("port") || "443", 10);
    if (p >= 1 && p <= 65535) port = p;
  }
  if (!host) {
    try { ws.close(1011, "bad params"); } catch {}
    return;
  }
  let conn;
  let closed = false;
  const pending = [];
  ws.on("message", (data) => {
    const b = toBytes(data);
    if (b.length === 0) return;
    if (conn && !conn.destroyed) {
      conn.write(b, () => {});
      return;
    }
    pending.push(b);
  });
  connectHost(host, port, 10000).then((sock) => {
    conn = sock;
    if (closed) { try { sock.destroy(); } catch {} return; }
    if (pending.length) {
      for (const b of pending) sock.write(b, () => {});
      pending.length = 0;
    }
    sock.on("data", (c) => { if (!closed) { try { ws.send(c); } catch {} } });
    sock.on("close", () => { if (!closed) { closed = true; try { ws.close(1000); } catch {} } });
    sock.on("error", () => {});
  }).catch(() => {
    try { ws.close(1011, "connect failed"); } catch {}
  });
  ws.on("close", () => { closed = true; try { conn && conn.destroy(); } catch {} });
  ws.on("error", () => { closed = true; try { conn && conn.destroy(); } catch {} });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("tg-relay listening on :" + PORT);
});