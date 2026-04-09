/**
 * FlowHive Defense Core — Next.js Edge Middleware v2.1 (Enterprise Asenkron)
 * ========================================================================
 * Her isteği FlowHive API'ye asenkron olarak rapor eder. Kullanıcıyı bekletmez.
 * Cihaz parmak izi, yerel hız sınırı (Rate Limit) ve WAF özelliklerini barındırır.
 */

import { NextResponse } from "next/server";

// ─── Yapılandırma ─────────────────────────────────────────────────────────────
const FLOWHIVE_API_URL = process.env.FLOWHIVE_API_URL || "https://davida-unslain-allen.ngrok-free.dev/api/trigger-alert";
const FLOWHIVE_TOKEN = process.env.FLOWHIVE_TOKEN || "";

/** Bu prefix'lere sahip rotalar middleware'den geçmez (Gereksiz SOC yükünü önler) */
const BYPASS_PREFIXES = [
  "/_next/static",
  "/_next/image",
  "/favicon.ico",
  "/robots.txt",
  "/sitemap.xml",
];

/** Tek bir IP'nin kara listeye alınmadan önce kaç saniyede kaç istek yapabileceği. */
const RATE_LIMIT_WINDOW_MS = 60_000;   // 1 dakika
const RATE_LIMIT_MAX       = 200;      // 1 dakikada maksimum istek

// ─── In-Edge Hafıza Hız Sınırlayıcı (Anti-Flood) ──────────────────────────────
/** @type {Map<string, {count: number, resetAt: number}>} */
const _edgeRateMap = new Map();

function checkEdgeRateLimit(ip) {
  const now  = Date.now();
  let entry  = _edgeRateMap.get(ip);

  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    _edgeRateMap.set(ip, entry);
  }

  entry.count++;

  // Hafıza sızıntısını önle: 10.000'den fazla girişi temizle
  if (_edgeRateMap.size > 10_000) {
    for (const [k, v] of _edgeRateMap) {
      if (now > v.resetAt) _edgeRateMap.delete(k);
    }
  }

  return entry.count > RATE_LIMIT_MAX;
}

// ─── Tehdit Sınıflandırıcı (Regex WAF) ────────────────────────────────────────
/**
 * Gelen isteğin URL, metod ve başlıklarına bakarak tehdit türünü belirler.
 * @param {import("next/server").NextRequest} req
 * @returns {{ type: string; confidence: number }}
 */
function classifyThreat(req) {
  const method  = req.method.toUpperCase();
  const path    = new URL(req.url).pathname.toLowerCase();
  const query   = new URL(req.url).search.toLowerCase();
  const ua      = (req.headers.get("user-agent") || "").toLowerCase();
  const referer = (req.headers.get("referer")    || "").toLowerCase();

  // SQL Injection belirtileri
  const sqliPatterns = /(\bselect\b|\bunion\b|\bdrop\b|\binsert\b|'--|;--|0x[0-9a-f]+)/i;
  if (sqliPatterns.test(query) || sqliPatterns.test(referer)) {
    return { type: "SQL Injection (SQLi)", confidence: 0.96 };
  }

  // XSS belirtileri
  const xssPatterns = /(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)/i;
  if (xssPatterns.test(query) || xssPatterns.test(referer)) {
    return { type: "Cross-Site Scripting (XSS)", confidence: 0.94 };
  }

  // Path Traversal / LFI
  const lfiPatterns = /(\.\.\/|\.\.\\|\/etc\/passwd|\/proc\/self|\\windows\\system32)/i;
  if (lfiPatterns.test(path) || lfiPatterns.test(query)) {
    return { type: "Local File Inclusion (LFI)", confidence: 0.97 };
  }

  // Brute force: login/auth endpoint'lerine POST
  if (method === "POST" && /\/(login|auth|signin|wp-login|admin|password|token)/.test(path)) {
    return { type: "Brute Force Password Attack", confidence: 0.88 };
  }

  // Scanner/bot tespiti
  const scannerUA = /(nikto|sqlmap|nmap|masscan|zgrab|nuclei|burpsuite|dirbuster|gobuster)/i;
  if (scannerUA.test(ua)) {
    return { type: "Vulnerability Scanner", confidence: 0.99 };
  }

  // API Abuse tespiti
  if (path.startsWith("/api") && method === "OPTIONS") {
    return { type: "API Probe / CORS Abuse", confidence: 0.75 };
  }

  // Temiz trafik (BENIGN)
  return { type: "BENIGN", confidence: 0.0 };
}

// ─── Cihaz Parmak İzi (Edge Crypto) ───────────────────────────────────────────
/**
 * Tarayıcı başlıklarından deterministik ama geri döndürülemez bir ID üretir.
 * @param {string} ip
 * @param {import("next/server").NextRequest} req
 * @returns {Promise<string>}
 */
async function computeDeviceFingerprint(ip, req) {
  const ua       = req.headers.get("user-agent")       || "";
  const lang     = req.headers.get("accept-language")  || "";
  const encoding = req.headers.get("accept-encoding")  || "";

  const raw = `${ip}|${ua}|${lang}|${encoding}`;

  // SubtleCrypto: Edge runtime'da çalışır, harici kütüphane gerektirmez.
  const encoded = new TextEncoder().encode(raw);
  const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  const hex     = hashArr.map((b) => b.toString(16).padStart(2, "0")).join("");
  return `DEV-${hex.slice(0, 16).toUpperCase()}`;
}

// ─── Engelleme Yanıtı ─────────────────────────────────────────────────────────
function blockedResponse(ip, deviceId) {
  const html = `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>403 — Erişim Engellendi | FlowHive Defense</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      background: #0a0a0a; color: #e0e0e0; font-family: 'Courier New', monospace;
    }
    .card {
      background: #111; border: 1px solid #ff3333; border-radius: 8px;
      padding: 2rem 3rem; max-width: 480px; text-align: center;
      box-shadow: 0 0 40px rgba(255,51,51,0.3);
    }
    h1 { font-size: 4rem; color: #ff3333; letter-spacing: 4px; }
    h2 { font-size: 1rem; color: #ff9900; margin: 0.5rem 0 1.5rem; }
    p  { font-size: 0.85rem; line-height: 1.7; color: #888; }
    code { color: #ff9900; background: #1a1a1a; padding: 2px 6px; border-radius: 3px; }
    .badge {
      display: inline-block; margin-top: 1.5rem;
      padding: 4px 12px; border: 1px solid #ff3333;
      border-radius: 4px; font-size: 0.75rem; color: #ff3333;
      letter-spacing: 1px;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>403</h1>
    <h2>⛔ ACCESS DENIED — FlowHive Defense Active</h2>
    <p>
      Your IP address <code>${ip}</code> or device fingerprint
      <code>${deviceId.slice(0, 12)}…</code> has been flagged and blocked
      by our AI-powered intrusion detection system.
    </p>
    <p style="margin-top:1rem;">
      If you believe this is an error, contact the site administrator
      and provide your reference ID: <code>${deviceId}</code>
    </p>
    <span class="badge">FLOWHIVE DEFENSE CORE v2.1</span>
  </div>
</body>
</html>`;

  return new NextResponse(html, {
    status: 403,
    headers: {
      "Content-Type":              "text/html; charset=utf-8",
      "X-FlowHive-Blocked":        "true",
      "X-FlowHive-Device":         deviceId,
      "Cache-Control":             "no-store, no-cache",
      "X-Robots-Tag":              "noindex",
    },
  });
}

// ─── Ana Middleware (DİKKAT: event parametresi eklendi) ───────────────────────
export async function middleware(req, event) {
  const url = new URL(req.url);

  // 1. Statik/sistem rotalarını atla
  if (BYPASS_PREFIXES.some((p) => url.pathname.startsWith(p))) {
    return NextResponse.next();
  }

  // 2. İstemci IP'sini al
  const forwarded = req.headers.get("x-forwarded-for");
  const ip        = forwarded ? forwarded.split(",")[0].trim() : "0.0.0.0";

  // 3. Edge hız sınırı (API çağrısına bile gerek kalmadan hızlı red)
  if (checkEdgeRateLimit(ip)) {
    return blockedResponse(ip, "RATE-LIMITED");
  }

  // 4. Cihaz parmak izi
  let deviceId;
  try {
    deviceId = await computeDeviceFingerprint(ip, req);
  } catch {
    deviceId = `DEV-FALLBACK-${ip.replace(/\./g, "")}`;
  }

  // 5. Tehdit sınıflandırması
  const threat = classifyThreat(req);

  // 6. FlowHive API'ye raporla (ASENKRON)
  // Sadece temiz olmayan (BENIGN harici) ve güven skoru yüksek trafikleri raporla
  if (threat.type !== "BENIGN" && threat.confidence > 0.60) {
    const headers = { "Content-Type": "application/json" };
    if (FLOWHIVE_TOKEN) headers["Authorization"] = FLOWHIVE_TOKEN;

    const payload = JSON.stringify({
      source_ip:      ip,
      destination_ip: `${req.headers.get("host") || "unknown-host"}`,
      threat_type:    threat.type,
      confidence:     threat.confidence,
      device_id:      deviceId,
    });

    // event.waitUntil ile isteği arka planda atıyoruz, böylece Vercel kullanıcıyı sitenin açılması için bekletmiyor!
    event.waitUntil(
      fetch(FLOWHIVE_API_URL, {
        method: "POST",
        headers,
        body: payload,
      }).then(res => {
        // Eğer arka planda SOC "Bu adamı hemen engelle!" (403) derse,
        // Bu adamı bir sonraki tıklamasında engellemek için Edge Hafızasına yazabiliriz.
        if (res.status === 403) {
            _edgeRateMap.set(ip, { count: 999, resetAt: Date.now() + 3600000 }); // 1 saat ban
        }
      }).catch(err => {
        console.warn(`[FlowHive] Telemetri gönderilemedi: ${err?.message}`);
      })
    );
  }

  // 7. Güvenlik başlıklarını ekleyerek isteği ilet (Site normal bir şekilde hızlıca açılır)
  const response = NextResponse.next();
  response.headers.set("X-FlowHive-Inspected",    "true");
  response.headers.set("X-FlowHive-Device",       deviceId);
  response.headers.set("X-Content-Type-Options",  "nosniff");
  response.headers.set("X-Frame-Options",         "DENY");
  response.headers.set("Referrer-Policy",         "strict-origin-when-cross-origin");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );

  return response;
}

// ─── Matcher ──────────────────────────────────────────────────────────────────
export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
