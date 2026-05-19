const express = require('express');
const app = express();
app.use(express.json());

const PSK = process.env.PSK || '';

const STRIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-real-ip",
  "forwarded",
  "via",
  "x-mhr-hop",
  "accept-encoding",          // ← force uncompressed responses
]);

function sanitizeHeaders(h) {
  const out = {};
  if (!h || typeof h !== "object") return out;
  for (const [k, v] of Object.entries(h)) {
    if (!k) continue;
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = String(v ?? "");
  }
  return out;
}

function decodeBase64ToBytes(input) {
  return Buffer.from(input, 'base64');
}

function encodeBytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

app.get('/', (req, res) => {
  res.json({ ok: true, status: "healthy", message: "Exit node is running." });
});

app.post('/', async (req, res) => {
  try {
    const body = req.body;
    if (!body || typeof body !== "object") return res.status(400).json({ e: "bad_json" });
    if (!PSK) return res.status(500).json({ e: "server_psk_missing" });

    const k = String(body.k ?? "");
    const u = String(body.u ?? "");
    const m = String(body.m ?? "GET").toUpperCase();
    const h = sanitizeHeaders(body.h);
    const b64 = body.b;

    if (k !== PSK) return res.status(401).json({ e: "unauthorized" });
    if (!/^https?:\/\//i.test(u)) return res.status(400).json({ e: "bad_url" });

    // Self‑loop detection
    try {
      const targetHost = new URL(u).hostname.toLowerCase();
      const origin = `http://${req.headers.host}`;
      const workerHost = new URL(req.url, origin).hostname.toLowerCase();
      if (targetHost === workerHost) {
        return res.status(508).json({ e: "loop_detected", detail: "self-loop" });
      }
    } catch (_) {}

    // GAS loop detection
    if (req.headers["x-mhr-hop"] && /\/macros\/s\//i.test(u)) {
      return res.status(508).json({ e: "loop_detected", detail: "GAS-loop" });
    }

    let requestBody;
    if (typeof b64 === "string" && b64.length > 0) {
      requestBody = decodeBase64ToBytes(b64);
    }

   const hWithUA = { ...h, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36' };
const resp = await fetch(u, {
    method: m,
    headers: hWithUA,
    body: requestBody,
    redirect: "manual",
});
    const data = new Uint8Array(await resp.arrayBuffer());
    const responseBodyBase64 = encodeBytesToBase64(data);

    // Build response headers – skip any encoding/length headers
    const respHeaders = {};
    resp.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (lower === "content-encoding" || lower === "transfer-encoding" || lower === "content-length") return;
      respHeaders[key] = value;
    });

    return res.json({ s: resp.status, h: respHeaders, b: responseBodyBase64 });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ e: message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('MasterHttpRelay running on port ' + PORT);
});
