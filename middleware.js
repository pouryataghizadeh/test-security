/**
 * FLOWHIVE NEXUS - EDGE SHIELD MIDDLEWARE
 * Bu dosya Vercel projesinin ana dizininde (/) bulunmalıdır.
 */

export default function middleware(req, event) {
    // 1. Ziyaretçinin IP ve Tarayıcı kimliğini yakala
    const forwarded = req.headers.get('x-forwarded-for');
    const ip = forwarded ? forwarded.split(',')[0] : 'Bilinmeyen IP';
    const userAgent = req.headers.get('user-agent') || 'Bilinmeyen Tarayici';
    
    // NGROK LİNKİN (SOC MERKEZİ) - Ngrok değiştikçe burayı güncellemeyi unutma!
    const NGROK_LINK = 'https://davida-unslain-allen.ngrok-free.dev/api/trigger-alert';

    const url = new URL(req.url);
    const path = url.pathname.toLowerCase();
    const query = url.search.toLowerCase();

    // 2. SALDIRI TİPİNİ ANALİZ ET (WAF MANTIĞI)
    let detected_threat = "DDoS Volumetric"; // Varsayılan şüpheli hareket

    // Brute Force tespiti (/login sayfasına POST isteği atılıyorsa)
    if (req.method === 'POST' && (path.includes('login') || path.includes('auth'))) {
        detected_threat = "Brute Force Password Attack";
    } 
    // SQL Injection tespiti (URL içinde SQL komutları geçiyorsa)
    else if (query.includes('select') || query.includes('union') || query.includes("'") || query.includes('insert')) {
        detected_threat = "SQL Injection (SQLi)";
    }
    // XSS tespiti (URL içinde script etiketleri geçiyorsa)
    else if (query.includes('<script>') || query.includes('%3cscript%3e')) {
        detected_threat = "Cross-Site Scripting (XSS)";
    }

    // Basit bir Cihaz ID (Fingerprint) oluştur
    const device_id = "DEV-VRC-" + (ip.length + userAgent.length + 99);

    /**
     * 3. EN KRİTİK KISIM: MERKEZE SOR VE GEREKİRSE ENGELLE!
     * Bu işlem Vercel Edge üzerinde saniyeler içinde gerçekleşir.
     */
    const response = fetch(NGROK_LINK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            source_ip: ip,
            destination_ip: "Farmer Project (Vercel)",
            threat_type: detected_threat,
            confidence: 0.98,
            device_id: device_id
        }),
    }).then(res => {
        /**
         * Eğer FlowHive Dashboard'dan 'BAN DEVICE' tuşuna bastıysan, 
         * Python backend 403 (Forbidden) cevabı dönecektir.
         */
        if (res.status === 403) {
            console.log(`[BLOCK] Saldırgan engellendi: ${ip}`);
            return new Response(
                `
                <div style="background:#020617; color:#ef4444; font-family:sans-serif; height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; padding:20px;">
                    <h1 style="font-size:50px; margin-bottom:10px;">🔴 ACCESS DENIED</h1>
                    <p style="font-size:20px; color:#94a3b8;">Your IP address (${ip}) or Device ID (${device_id}) has been blacklisted by <strong>FlowHive Defense System</strong>.</p>
                    <div style="margin-top:30px; padding:10px; border:1px solid #ef4444; color:#ef4444; font-family:monospace;">Threat Type: ${detected_threat}</div>
                </div>
                `, 
                { status: 403, headers: { 'content-type': 'text/html' } }
            );
        }
        return null;
    }).catch(err => {
        // Eğer Ngrok kapalıysa veya hata verirse siteyi çökertme, trafiğe izin ver
        console.error("SOC Bağlantı Hatası:", err.message);
        return null;
    });

    // Eğer bir engelleme (403) cevabı oluştuysa onu döndür, yoksa siteyi normal aç
    return response.then(res => res || new Response(null, { headers: { 'x-middleware-next': '1' } }));
}

// 🔥 TÜM SAYFALARI KORU: Sitenin içindeki her sayfayı dinlemeye alıyoruz.
export const config = {
    matcher: '/:path*',
};
