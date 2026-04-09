/**
 * FLOWHIVE NEXUS — ADVANCED EDGE SHIELD v3.5
 * ==========================================
 * Özellikler:
 * - Asenkron Tehdit Raporlama (Kullanıcıyı yavaşlatmaz)
 * - SubtleCrypto ile Deterministik Cihaz Parmak İzi (Fingerprinting)
 * - Dual-Stack Ban Kontrolü (Hem IP hem Cihaz Kimliği)
 * - Yerel Hafıza Caching (Banlanan IP'leri Edge üzerinde tutar)
 */

import { NextResponse } from "next/server";

// ─── YAPILANDIRMA ─────────────────────────────────────────────────────────────
// Ngrok veya Sunucu adresini buraya yaz (Sonunda / olmasın)
const SOC_API_BASE = "https://davida-unslain-allen.ngrok-free.dev";

/** SOC yükünü azaltmak için bu yollar middleware tarafından taranmaz */
const BYPASS_ROUTES = [
  "/_next/static", "/_next/image", "/favicon.ico", "/robots.txt", "/sitemap.xml",
];

/** Vercel Edge Hafızası (Saldırganları geçici olarak RAM'de tutar) */
const _edgeBlockCache = new Map();

// ─── TEHDİT ANALİZ MOTORU (WAF) ────────────────────────────────────────────────
function classifyThreat(req) {
  const url = new URL(req.url);
  const path = url.pathname.toLowerCase();
  const query = url.search.toLowerCase();
  const ua = (req.headers.get("user-agent") || "").toLowerCase();

  // SQL Injection Koruması
  if (/(%27)|(\')|(--)|(%23)|(#)|(\bselect\b|\bunion\b|\bdrop\b)/i.test(query)) {
    return { type: "SQL Injection", confidence: 0.96 };
  }

  // XSS Koruması
  if (/(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)/i.test(query)) {
    return { type: "Cross-Site Scripting (XSS)", confidence: 0.94 };
  }

  // Brute Force (Giriş denemeleri)
  if (req.method === "POST" && /\/(login|auth|admin|signin)/.test(path)) {
    return { type: "Brute Force Attempt", confidence: 0.85 };
  }

  // Bot & Scanner Tespiti
  if (/(nikto|sqlmap|nmap|burp|dirbuster|gobuster|python-requests)/i.test(ua)) {
    return { type: "Vulnerability Scanner", confidence: 0.99 };
  }

  return { type: "BENIGN", confidence: 0.0 };
}

// ─── CİHAZ PARMAK İZİ OLUŞTURUCU ───────────────────────────────────────────────
async function getDeviceID(ip, req) {
  const ua = req.headers.get("user-agent") || "";
  const lang = req.headers.get("accept-language") || "";
  const raw = `${ip}|${ua}|${lang}`;

  const encoded = new TextEncoder().encode(raw);
  const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  const hex = hashArr.map((b) => b.toString(16).padStart(2, "0")).join("");
  return `DEV-${hex.slice(0, 16).toUpperCase()}`;
}

// ─── ANA MIDDLEWARE ────────────────────────────────────────────────────────────
export async function middleware(req, event) {
  const url = new URL(req.url);

  // 1. Statik dosyaları atla
  if (BYPASS_ROUTES.some((p) => url.pathname.startsWith(p))) {
    return NextResponse.next();
  }

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0] || "127.0.0.1";
  const deviceId = await getDeviceID(ip, req);

  // 2. Yerel Hafıza (Edge Cache) Kontrolü
  // Eğer bu IP son 1 saat içinde 403 aldıysa, Python'a sormadan direk engelle
  if (_edgeBlockCache.has(ip) && _edgeBlockCache.get(ip) > Date.now()) {
    return blockedResponse(ip, deviceId);
  }

  try {
    // 3. SOC Merkezine Ban Kontrolü Sor (Dual Control: IP + DeviceID)
    const checkController = new AbortController();
    const timeoutId = setTimeout(() => checkController.abort(), 600); // 600ms içinde cevap gelmezse sal gitsin (Fail-Open)
    
    const checkRes = await fetch(`${SOC_API_BASE}/api/check-ip/${ip}?device_id=${deviceId}`, {
      signal: checkController.signal
    });
    clearTimeout(timeoutId);
    
    const status = await checkRes.json();

    if (status.status === "banned") {
      // Edge hafızasına al (1 saat boyunca bir daha sorma)
      _edgeBlockCache.set(ip, Date.now() + 3600000);
      return blockedResponse(ip, deviceId);
    }

  } catch (err) {
    console.warn("[FlowHive] SOC Offline, bypassing check...");
  }

  // 4. Tehdit Sınıflandırması
  const threat = classifyThreat(req);

  // 5. Arka Planda Raporlama (BEKLEMESİZ)
  // Sadece şüpheli hareketleri (BENIGN olmayan) raporla
  if (threat.type !== "BENIGN") {
    event.waitUntil(
      fetch(`${SOC_API_BASE}/api/trigger-alert`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_ip: ip,
          destination_ip: req.headers.get("host") || "Vercel_Edge",
          threat_type: threat.type,
          confidence: threat.confidence,
          device_id: deviceId
        })
      }).then(res => {
        // Eğer raporlama sırasında backend "bu adam aslında banlıymış" derse hafızaya ekle
        if (res.status === 403) _edgeBlockCache.set(ip, Date.now() + 3600000);
      }).catch(() => {})
    );
  }

  // 6. Güvenli başlıklarla siteyi aç
  const response = NextResponse.next();
  response.headers.set("X-FlowHive-Inspected", "true");
  response.headers.set("X-FlowHive-Device", deviceId);
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  
  return response;
}

// ─── ENGELLEME EKRANI ─────────────────────────────────────────────────────────
function blockedResponse(ip, deviceId) {
  const html = `
    <div style="background:#030712; color:#ef4444; height:100vh; display:flex; flex-direction:column; justify-content:center; align-items:center; font-family:monospace; text-align:center; padding:20px;">
        <h1 style="font-size:60px; margin:0;">403</h1>
        <h2 style="letter-spacing:5px; border:1px solid #ef4444; padding:10px;">ACCESS DENIED</h2>
        <p style="color:#94a3b8; font-size:18px; margin-top:20px;">Your IP (${ip}) or Device ID has been blacklisted by <b>FlowHive SOC</b>.</p>
        <div style="margin-top:40px; color:#475569; font-size:12px;">Ref ID: ${deviceId}</div>
    </div>`;

  return new NextResponse(html, {
    status: 403,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}

// ─── MATCHER ──────────────────────────────────────────────────────────────────
export const config = {
  matcher: "/((?!api|_next/static|_next/image|favicon.ico).*)",
};
