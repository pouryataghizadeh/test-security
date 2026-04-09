/**
 * FLOWHIVE NEXUS - ENTERPRISE EDGE WAF (Web Application Firewall)
 * Sürüm: 3.1.0 | Sıfır Bağımlılık (Pure Edge)
 */

// SHA-256 Kriptografik Parmak İzi Üretici
async function generateFingerprint(req, ip) {
    const userAgent = req.headers.get('user-agent') || 'unknown';
    const acceptLang = req.headers.get('accept-language') || 'unknown';
    const secChUa = req.headers.get('sec-ch-ua') || 'unknown';
    
    // Tarayıcı donanım ve ağ verilerini birleştir
    const rawData = `${ip}|${userAgent}|${acceptLang}|${secChUa}`;
    
    // Vercel Edge üzerinde donanımsal SHA-256 şifreleme
    const msgBuffer = new TextEncoder().encode(rawData);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return `FH-DEV-${hashHex.substring(0, 12).toUpperCase()}`;
}

export default async function middleware(req, event) {
    const forwarded = req.headers.get('x-forwarded-for');
    const ip = forwarded ? forwarded.split(',')[0] : '127.0.0.1';
    
    // NGROK LİNKİNİ BURAYA GİR
    const NGROK_LINK = 'https://davida-unslain-allen.ngrok-free.dev/api/trigger-alert';

    const url = new URL(req.url);
    const path = url.pathname.toLowerCase();
    const query = url.search.toLowerCase();
    const method = req.method;

    // 1. ENTERPRISE WAF KURALLARI (RegEx)
    const sqliRegex = /(union|select|insert|update|delete|drop|--|#|\/\*|' OR 1=1)/i;
    const xssRegex = /(<script>|%3cscript%3e|onload=|onerror=|javascript:)/i;
    const lfiRegex = /(\.\.\/|\.\.\\|\/etc\/passwd|\/windows\/win.ini)/i;

    let detected_threat = null;
    let confidence = 0.0;

    if (method === 'POST' && (path.includes('login') || path.includes('auth'))) {
        detected_threat = "Brute Force Authentication"; confidence = 0.92;
    } else if (sqliRegex.test(query) || sqliRegex.test(path)) {
        detected_threat = "SQL Injection (SQLi) Payload"; confidence = 0.99;
    } else if (xssRegex.test(query)) {
        detected_threat = "Cross-Site Scripting (XSS)"; confidence = 0.98;
    } else if (lfiRegex.test(query)) {
        detected_threat = "Local File Inclusion (LFI)"; confidence = 0.97;
    } else if (method === 'GET' && path === '/') {
        // Normal trafik için DDoS şüphesi (AI modeli desteklemeli)
        detected_threat = "Volumetric Traffic (Potential DDoS)"; confidence = 0.75;
    }

    // 2. Kriptografik Cihaz Parmak İzini Oluştur
    const device_id = await generateFingerprint(req, ip);

    // 3. SOC Merkezine Raporla ve Kararı Bekle
    try {
        const response = await fetch(NGROK_LINK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source_ip: ip,
                destination_ip: url.hostname,
                threat_type: detected_threat || "Unknown Anomaly",
                confidence: confidence,
                device_id: device_id,
                path_accessed: path
            }),
        });

        // 4. KESİN ENGELLEME (403 Forbidden)
        if (response.status === 403) {
            console.warn(`[SHIELD] Traffic blocked for FP: ${device_id}`);
            return new Response(
                `
                <!DOCTYPE html>
                <html><head><title>Access Denied | FlowHive</title>
                <style>body{background:#0a0a0a;color:#ef4444;font-family:monospace;padding:50px;text-align:center;} .box{border:1px solid #ef4444;padding:20px;display:inline-block;background:#170505;} h1{font-size:3rem;margin:0;}</style>
                </head><body>
                <div class="box">
                    <h1>ERROR 403: ACCESS DENIED</h1>
                    <p>Your request was blocked by FlowHive Web Application Firewall.</p>
                    <p>Reference ID: <b>${device_id}</b></p>
                    <p>IP Address: ${ip}</p>
                </div></body></html>
                `, 
                { status: 403, headers: { 'content-type': 'text/html; charset=UTF-8' } }
            );
        }
    } catch (err) {
        console.error("SOC İletişim Hatası:", err.message);
    }

    return new Response(null, { headers: { 'x-middleware-next': '1' } });
}

export const config = { matcher: '/:path*' };
