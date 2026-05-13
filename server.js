// MasterHttpRelay – standalone relay server (no ngrok needed)
const express = require('express');
const app = express();

// Your pre-shared secret – set this via Render environment variable
const PSK = process.env.PSK || '';

// Headers to strip (same list as the Cloudflare Worker)
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
  "accept-encoding",
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

// Health check (GET)
app.get('/', (req, res) => {
  res.json({
    ok: true,
    status: "healthy",
    message: "Everything is OK. Worker is deployed and reachable.",
    usage: "Send POST with relay payload for actual proxy requests.",
  });
});

// Relay endpoint (POST)
app.post('/', async (req, res) => {
  try {
    // Method guard – only POST is allowed for relay (GET already handled)
    if (req.method !== 'POST') {
      return res.status(405).json({
        e: "method_not_allowed",
        message: "Use POST for relay requests. GET is only a health check.",
      });
    }

    // Parse body (Express has JSON middleware; we'll add it globally)
    const body = req.body;
    if (!body || typeof body !== "object") {
      return res.status(400).json({ e: "bad_json" });
    }

    // Check PSK is set on the server
    if (!PSK) {
      return res.status(500).json({ e: "server_psk_missing" });
    }

    const k = String(body.k ?? "");
    const u = String(body.u ?? "");
    const m = String(body.m ?? "GET").toUpperCase();
    const h = sanitizeHeaders(body.h);
    const b64 = body.b;

    // PSK authentication
    if (k !== PSK) return res.status(401).json({ e: "unauthorized" });

    // URL validation
    if (!/^https?:\/\//i.test(u))
      return res.status(400).json({ e: "bad_url" });

    // ── Loop detection (self-loop) ──
    try {
      const targetHost = new URL(u).hostname.toLowerCase();
      const workerHost = new URL(req.url, http://${req.headers.host}).hostname.toLowerCase());
      if (targetHost === workerHost) {
        return res.status(508).json({
          e: "loop_detected",
          detail: "target URL resolves to this Worker",
        });
      }
    } catch (_) {
      // Malformed URL already caught above, but ignore parse errors here
    }

    // ── GAS loop detection ──
    const hopHeader = req.headers["x-mhr-hop"];
    if (hopHeader && /\/macros\/s\//i.test(u)) {
      return res.status(508).json({
        e: "loop_detected",
        detail: "GAS→Worker→GAS relay loop",
      });
    }

    // ── Build the request body ──
    let requestBody;
    if (typeof b64 === "string" && b64.length > 0) {
      requestBody = Buffer.from(b64, 'base64');
    }

    // ── Relay the request ──
    const resp = await fetch(u, {
      method: m,
      headers: h,
      body: requestBody,
      redirect: "manual",
    });

    // Read response body as binary and encode to base64
    const arrayBuffer = await resp.arrayBuffer();
    const responseBodyBase64 = Buffer.from(arrayBuffer).toString('base64');

    // Collect response headers
    const respHeaders = {};
    resp.headers.forEach((value, key) => {
      respHeaders[key] = value;
    });

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

// Global middleware to parse JSON bodies
app.use(express.json());

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(MasterHttpRelay running on port ${PORT});
});
