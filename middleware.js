/**
 * FLOWHIVE NEXUS - PURE EDGE SHIELD (NO IMPORTS)
 * Konum: /middleware.js (Vercel Root)
 */

export default function middleware(req, event) {
    // 1. Ziyaretçi Verilerini Yakala
    const forwarded = req.headers.get('x-forwarded-for');
    const ip = forwarded ? forwarded.split(',')[0] : 'Bilinmeyen IP';
    const userAgent = req.headers.get('user-agent') || 'Bilinmeyen Tarayici';
    
    // 🛡️ KRİTİK: Ngrok adresin değiştikçe burayı güncellemeyi unutma!
    const NGROK_LINK = 'https://davida-unslain-allen.ngrok-free.dev/api/trigger-alert';

    const url = new URL(req.url);
    const path = url.pathname.toLowerCase();
    const query = url.search.toLowerCase();

    // 2. Akıllı Saldırı Analizi (WAF Logic)
    let detected_threat = "DDoS Volumetric"; 

    // Giriş sayfasına yoğun POST isteği geliyorsa
    if (req.method === 'POST' && (path.includes('login') || path.includes('auth'))) {
        detected_threat = "Brute Force Password Attack";
    } 
    // URL içinde SQL komutları aranıyorsa
    else if (query.includes('select') || query.includes('union') || query.includes("'")) {
        detected_threat = "SQL Injection (SQLi)";
    }
    // URL içinde script kodu geçiyorsa
    else if (query.includes('<script>') || query.includes('%3cscript%3e')) {
        detected_threat = "Cross-Site Scripting (XSS)";
    }

    // Cihaz Parmak İzi (Fingerprint)
    const device_id = "DEV-VRC-" + (ip.length + userAgent.length + 99);

    /**
     * 3. AKTİF SAVUNMA VE RAPORLAMA
     * Bu işlem hem SOC paneline veri gönderir hem de Python'dan gelen engelleme emrine bakar.
     */
    return fetch(NGROK_LINK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            source_ip: ip,
            destination_ip: "Farmer Project (Vercel)",
            threat_type: detected_threat,
            confidence: 0.98,
            device_id: device_id
        }),
    })
    .then(res => {
        /**
         * EĞER SEN PANELDE 'BAN' TUŞUNA BASTIYSAN:
         * Python backend bu isteğe 403 (Forbidden) cevabı dönecek.
         */
        if (res.status === 403) {
            return new Response(
                `
                <div style="background:#030712; color:#ef4444; font-family:sans-serif; height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; padding:20px; border: 5px solid #ef4444;">
                    <h1 style="font-size:60px; margin-bottom:10px;">🔴 ACCESS DENIED</h1>
                    <p style="font-size:24px; color:#94a3b8; max-width:600px;">Your IP address (${ip}) has been blacklisted by <strong>FlowHive Nexus SOC</strong> for suspicious activity.</p>
                    <div style="margin-top:30px; padding:15px; border:1px solid #ef4444; color:#ef4444; font-family:monospace; background:rgba(239,68,68,0.1);">
                        THREAT_DETECTED: ${detected_threat}<br>
                        DEVICE_ID: ${device_id}
                    </div>
                </div>
                `, 
                { status: 403, headers: { 'content-type': 'text/html; charset=UTF-8' } }
            );
        }
        // Banlı değilse, normal site akışına devam et
        return new Response(null, { headers: { 'x-middleware-next': '1' } });
    })
    .catch(err => {
        // Ngrok kapalıysa siteyi aç (hata toleransı), sadece konsola yaz
        console.error("SOC Bağlantı Hatası:", err.message);
        return new Response(null, { headers: { 'x-middleware-next': '1' } });
    });
}

// Tüm alt dizinleri (api, login, admin vb.) koruma altına al
export const config = {
    matcher: '/:path*',
};
