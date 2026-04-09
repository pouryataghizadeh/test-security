import { NextResponse } from 'next/server';

export default async function middleware(req, event) {
    const ip = req.headers.get('x-forwarded-for')?.split(',')[0] || '127.0.0.1';
    
    // NGROK VEYA SUNUCU IP'N
    const SOC_API_BASE = 'https://davida-unslain-allen.ngrok-free.dev';

    try {
        // 1. ULTRA HIZLI BAN KONTROLÜ (Sadece RAM'den sorgular, siteyi yavaşlatmaz)
        // İşlemin timeout süresini 500ms ile sınırlıyoruz ki SOC çökerse site açık kalsın.
        const checkController = new AbortController();
        const timeoutId = setTimeout(() => checkController.abort(), 500);
        
        const banCheck = await fetch(`${SOC_API_BASE}/api/check-ip/${ip}`, { signal: checkController.signal });
        clearTimeout(timeoutId);
        
        const banResult = await banCheck.json();

        // EĞER BANLIYSA İÇERİ ASLA ALMA
        if (banResult.status === 'banned') {
            return new Response(
                `<div style="background:#020617; color:#ef4444; height:100vh; display:flex; justify-content:center; align-items:center; text-align:center; font-family:monospace;">
                    <h1>🔴 ACCESS DENIED BY FLOWHIVE SOC</h1><p>IP: ${ip}</p>
                </div>`, 
                { status: 403, headers: { 'content-type': 'text/html' } }
            );
        }

        // 2. TEHDİT ANALİZİ İÇİN ARKA PLANDA BİLGİ GÖNDER (Kullanıcıyı bekletmez)
        const url = new URL(req.url);
        const path = url.pathname.toLowerCase();
        
        // Basit Regex Tabanlı WAF (False-Positive'i azaltılmış)
        let threatType = null;
        if (req.method === 'POST' && path.includes('/login')) threatType = "Possible Brute Force";
        if (/(%27)|(\')|(--)|(%23)|(#)/i.test(url.search)) threatType = "SQL Injection Attempt";
        if (/(%3C)|(<)|(%3E)|(>)|(script)/i.test(url.search)) threatType = "XSS Attempt";

        if (threatType) {
            // event.waitUntil: Bu fonksiyon arka planda çalışır, return komutunu durdurmaz!
            event.waitUntil(
                fetch(`${SOC_API_BASE}/api/trigger-alert`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        source_ip: ip, destination_ip: "Vercel Edge Node",
                        threat_type: threatType, confidence: 0.95
                    })
                }).catch(() => console.log("SOC Merkezine ulaşılamadı."))
            );
        }

    } catch (error) {
        // SOC API çökerse, güvenlik duvarı siteyi KİTLEMESİN (Fail-Open prensibi)
        console.log("Güvenlik duvarı atlandı, sunucu yanıt vermiyor.");
    }

    // 3. SİTEYİ NORMAL AÇ
    return NextResponse.next();
}

export const config = { matcher: '/:path*' };
