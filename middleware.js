/**
 * FLOWHIVE NEXUS — ADVANCED EDGE SHIELD v4.0
 * ==========================================
 * - Supabase Direct Edge Query (Ultra-Fast Ban Checking)
 * - TLS & Network Level Fingerprinting Simulation
 * - Fail-Open Resilience Architecture
 */

import { NextResponse } from "next/server";

// ─── YAPILANDIRMA ─────────────────────────────────────────────────────────────
const SOC_API_BASE = "http://localhost:8000"; // Python API (Eğer ngrok kullanıyorsan değiştir)
const SUPABASE_URL = "https://qipykhxrdwuijxolzcwd.supabase.co";
const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFpcHlraHhyZHd1aWp4b2x6Y3dkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODAxMTMzMTAsImV4cCI6MjA5NTY4OTMxMH0.9cnkPBbQEIa8Bz8Czq2RafCufG5vXtARvhVAQBZkCJk";

const BYPASS_ROUTES = ["/_next/static", "/_next/image", "/favicon.ico", "/robots.txt"];
const _edgeBlockCache = new Map();

// ─── TEHDİT ANALİZ MOTORU (WAF - Edge Level) ──────────────────────────────────
function classifyEdgeThreat(req) {
  const url = new URL(req.url);
  const path = url.pathname.toLowerCase();
  const query = url.search.toLowerCase();
  const ua = (req.headers.get("user-agent") || "").toLowerCase();

  if (/(%27)|(\')|(--)|(%23)|(#)|(\bselect\b|\bunion\b|\bdrop\b)/i.test(query)) return { type: "SQL Injection", conf: 0.96 };
  if (/(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)/i.test(query)) return { type: "XSS", conf: 0.94 };
  if (req.method === "POST" && /\/(login|auth|admin|signin)/.test(path)) return { type: "Brute Force", conf: 0.85 };
  if (/(nikto|sqlmap|nmap|burp|dirbuster|gobuster)/i.test(ua)) return { type: "Vulnerability Scanner", conf: 0.99 };

  return { type: "BENIGN", conf: 0.0 };
}

// ─── GELİŞMİŞ PARMAK İZİ (FINGERPRINTING) ─────────────────────────────────────
async function generateAdvancedFingerprint(req, ip) {
  const ua = req.headers.get("user-agent") || "";
  const lang = req.headers.get("accept-language") || "";
  // Edge Header'ları ile Cihazı Kesinleştirme (Vercel/Cloudflare özel başlıkları)
  const secChUa = req.headers.get("sec-ch-ua") || "";
  const secChPlatform = req.headers.get("sec-ch-ua-platform") || "";
  
  const rawFingerprint = `${ip}|${ua}|${lang}|${secChUa}|${secChPlatform}`;

  const encoded = new TextEncoder().encode(rawFingerprint);
  const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  const hex = hashArr.map((b) => b.toString(16).padStart(2, "0")).join("");
  
  return `FH-DEV-${hex.slice(0, 16).toUpperCase()}`;
}

// ─── ANA MIDDLEWARE ────────────────────────────────────────────────────────────
export async function middleware(req, event) {
  const url = new URL(req.url);

  if (BYPASS_ROUTES.some((p) => url.pathname.startsWith(p))) return NextResponse.next();

  // Gerçek IP'yi al (Proxy arkasındaysa X-Forwarded-For)
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0] || "127.0.0.1";
  const deviceId = await generateAdvancedFingerprint(req, ip);

  // 1. Önce RAM'deki Edge Cache'e bak (Ultra hızlı)
  if (_edgeBlockCache.has(ip) && _edgeBlockCache.get(ip) > Date.now()) {
    return blockedResponse(ip, deviceId);
  }

  // 2. Supabase'den Doğrudan Ban Kontrolü (Python API'sini beklemeden)
  try {
    const checkController = new AbortController();
    const timeoutId = setTimeout(() => checkController.abort(), 800); // Fail-Open: 800ms'de cevap gelmezse geçmesine izin ver
    
    // REST API kullanarak Supabase'i sorgula
    const supaRes = await fetch(`${SUPABASE_URL}/rest/v1/banned_ips?ip=eq.${ip}&select=ip`, {
      headers: {
        "apikey": SUPABASE_KEY,
        "Authorization": `Bearer ${SUPABASE_KEY}`
      },
      signal: checkController.signal
    });
    clearTimeout(timeoutId);
    
    const data = await supaRes.json();
    if (data && data.length > 0) {
      // Adam gerçekten banlıymış. RAM Cache'e 1 saatliğine ekle.
      _edgeBlockCache.set(ip, Date.now() + 3600000);
      return blockedResponse(ip, deviceId);
    }
  } catch (err) {
    // Supabase yanıt vermezse trafiği kesme (Kullanıcı deneyimini koru)
    console.warn("[FlowHive] Supabase Edge Check Timeout, bypassing...");
  }

  // 3. Edge WAF Tehdit Sınıflandırması
  const threat = classifyEdgeThreat(req);

  if (threat.type !== "BENIGN") {
    // Tehditi arka planda (kullanıcıyı bekletmeden) Python API'sine gönder
    event.waitUntil(
      fetch(`${SOC_API_BASE}/api/trigger-alert`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_ip: ip,
          destination_ip: req.headers.get("host") || "Vercel_Edge",
          threat_type: threat.type,
          confidence: threat.conf,
          device_id: deviceId
        })
      }).catch(() => {})
    );
  }

  const response = NextResponse.next();
  // Savunma Katmanı Başlıkları (Security Headers)
  response.headers.set("X-FlowHive-WAF", "Active");
  response.headers.set("X-Device-Trace", deviceId);
  response.headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  
  return response;
}

// ─── ENGELLEME EKRANI ─────────────────────────────────────────────────────────
function blockedResponse(ip, deviceId) {
  const html = `
    <div style="background:#030712; color:#ef4444; height:100vh; display:flex; flex-direction:column; justify-content:center; align-items:center; font-family:'Fira Code', monospace; text-align:center; padding:20px;">
        <svg style="width:100px; height:100px; margin-bottom:20px; opacity:0.8;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8V7a4 4 0 00-8 0v4h8z"></path></svg>
        <h1 style="font-size:64px; margin:0; text-shadow: 0 0 20px rgba(239,68,68,0.5);">403</h1>
        <h2 style="letter-spacing:8px; border:1px solid #ef4444; padding:15px 30px; margin:20px 0; background: rgba(239,68,68,0.1);">ACCESS DENIED</h2>
        <p style="color:#94a3b8; font-size:16px; max-width: 600px; line-height:1.6;">Connection isolated. The source IP address <b>${ip}</b> has triggered critical security protocols and is restricted by FlowHive Active Defense.</p>
        <div style="margin-top:40px; color:#475569; font-size:12px; border-top: 1px solid #1e293b; padding-top: 20px;">Trace ID: ${deviceId}</div>
    </div>`;

  return new NextResponse(html, {
    status: 403,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}

export const config = {
  matcher: "/((?!api|_next/static|_next/image|favicon.ico).*)",
};
