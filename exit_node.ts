import express, { Request, Response } from 'express';

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
  "accept-encoding",
]);

function sanitizeHeaders(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h || typeof h !== "object") return out;
  for (const [k, v] of Object.entries(h)) {
    if (!k) continue;
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = String(v ?? "");
  }
  return out;
}

function decodeBase64ToBytes(input: string): Uint8Array {
  return new Uint8Array(Buffer.from(input, 'base64'));
}

function encodeBytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

// Health check
app.get('/', (req: Request, res: Response) => {
  res.status(200).json({
    ok: true,
    status: "healthy",
    message: "Everything is OK. Worker is deployed and reachable.",
    usage: "Send POST with relay payload for actual proxy requests.",
  });
});

// Relay handler (exact logic from the original Worker)
app.post('/', async (req: Request, res: Response) => {
  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ e: "method_not_allowed" });
    }

    const body = req.body;
    if (!body || typeof body !== "object") {
      return res.status(400).json({ e: "bad_json" });
    }

    if (!PSK) {
      return res.status(500).json({ e: "server_psk_missing" });
    }

    const k = String(body.k ?? "");
    const u = String(body.u ?? "");
    const m = String(body.m ?? "GET").toUpperCase();
    const h = sanitizeHeaders(body.h);
    const b64 = body.b;

    if (k !== PSK) return res.status(401).json({ e: "unauthorized" });
    if (!/^https?:\/\//i.test(u)) return res.status(400).json({ e: "bad_url" });

    // Self-loop detection
    try {
      const targetHost = new URL(u).hostname.toLowerCase();
      const origin = http://${req.headers.host};
      const workerHost = new URL(req.url, origin).hostname.toLowerCase();
      if (targetHost === workerHost) {
        return res.status(508).json({ e: "loop_detected", detail: "self-loop" });
      }
    } catch (_) { /* ignore */ }

    // GAS loop detection
    const hopHeader = req.headers["x-mhr-hop"];
    if (hopHeader && /\/macros\/s\//i.test(u)) {
      return res.status(508).json({ e: "loop_detected", detail: "GAS→Worker→GAS relay loop" });
    }

    let requestBody: Uint8Array | undefined;
    if (typeof b64 === "string" && b64.length > 0) {
      requestBody = decodeBase64ToBytes(b64);
    }

    const resp = await fetch(u, {
      method: m,
      headers: h,
      body: requestBody,
      redirect: "manual",
    });

    const data = new Uint8Array(await resp.arrayBuffer());
    const responseBodyBase64 = encodeBytesToBase64(data);

    const respHeaders: Record<string, string> = {};
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('Exit node listening on port ' + PORT);
});
