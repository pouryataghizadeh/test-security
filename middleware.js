// Dikkat: next/server importunu tamamen kaldırdık. 
// Bu sayede Vercel, projeni Next.js projesi sanıp hata vermeyecek.

export default function middleware(req, event) {
    // 1. Saldırganın IP adresini ve Tarayıcı bilgisini yakala
    const forwarded = req.headers.get('x-forwarded-for');
    const ip = forwarded ? forwarded.split(',')[0] : 'Bilinmeyen IP';
    const userAgent = req.headers.get('user-agent') || 'Bilinmeyen Tarayici';

    // DİKKAT: Ngrok linkin değiştiyse burayı güncellemeyi unutma!
    const NGROK_LINK = 'https://davida-unslain-allen.ngrok-free.dev/api/trigger-alert';

    // 3. İsteğin URL'ini parse et
    const url = new URL(req.url);
    const path = url.pathname.toLowerCase();
    const query = url.search.toLowerCase();

    // 🔥 ZEKİ SİBER AJAN (SMART WAF) DEVREDE: Saldırı Türünü Kendi Bulur! 🔥
    let detected_threat = "DDoS Volumetric"; // Varsayılan şüpheli hareket

    // Kural A: Eğer /login veya /api/login gibi bir sayfaya şifre denemesi yapılıyorsa
    if (req.method === 'POST' && (path.includes('login') || path.includes('auth'))) {
        detected_threat = "Brute Force Password Attack";
    }
    // Kural B: Eğer URL'nin sonuna zararlı veritabanı kodları yazılıyorsa
    else if (query.includes('select') || query.includes('union') || query.includes('%27') || query.includes("'")) {
        detected_threat = "SQL Injection (SQLi)";
    }
    // Kural C: Eğer zararlı javascript çalıştırılmaya çalışılıyorsa
    else if (query.includes('<script>') || query.includes('%3cscript%3e')) {
        detected_threat = "Cross-Site Scripting (XSS)";
    }

    // Basit ve Hızlı bir Cihaz ID (Fingerprint) oluştur
    const device_id = "DEV-VRC-" + (ip.length + userAgent.length + 99);

    // 5. Analiz edilen gerçek veriyi SOC merkezine gönder
    event.waitUntil(
        fetch(NGROK_LINK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source_ip: ip,
                destination_ip: "Farmer Project (Vercel)",
                threat_type: detected_threat,
                confidence: 0.98,
                device_id: device_id
            }),
        }).catch(err => {
            console.error("SOC Merkezine ulaşılamadı:", err.message);
        })
    );

    // 6. Saldırganı şüphelendirmemek için normal siteyi göstermeye devam et
    return new Response(null, {
        headers: { 'x-middleware-next': '1' }
    });
}

// 🔥 EN ÖNEMLİ DEĞİŞİKLİK: Sadece ana sayfayı (/) DEĞİL, 
// sitenin içindeki tüm alt sayfaları (login vb.) dinlemeye alıyoruz!
export const config = {
    matcher: '/:path*',
};
