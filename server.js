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
  // "accept-encoding",  // ← REMOVED – allow compression
]);

// … sanitizeHeaders, decodeBase64ToBytes, encodeBytesToBase64 (unchanged) …

app.get('/', (req, res) => {
  res.json({ ok: true, status: "healthy", message: "Everything is OK." });
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

    // Loop detections (unchanged) …

    let requestBody;
    if (typeof b64 === "string" && b64.length > 0) {
      requestBody = decodeBase64ToBytes(b64);
    }

    const resp = await fetch(u, {
      method: m,
      headers: h,
      body: requestBody,
      redirect: "manual",
      compress: false   // ⬅️ KEY CHANGE
    });

    const data = new Uint8Array(await resp.arrayBuffer());
    const responseBodyBase64 = encodeBytesToBase64(data);

    const respHeaders = {};
    resp.headers.forEach((value, key) => {
      respHeaders[key] = value;
    });

    // Do NOT delete content-encoding / transfer-encoding / content-length

    return res.json({
      s: resp.status,
      h: respHeaders,
      b: responseBodyBase64,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ e: message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('MasterHttpRelay running on port ' + PORT);
});
