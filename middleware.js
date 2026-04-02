import { NextResponse } from 'next/server';

export default async function middleware(req) {
    // 1. Kullanıcının IP adresini daha güvenli şekilde alıyoruz
    // x-forwarded-for bazen "ip1, ip2" şeklinde liste dönebilir, ilkini alıyoruz.
    const forwarded = req.headers.get('x-forwarded-for');
    const ip = forwarded ? forwarded.split(',')[0] : (req.ip || 'Bilinmeyen IP');

    // 2. Ngrok veya Webhook linkini buraya yazıyoruz
    // Öneri: Canlı projede bunu process.env.TRIGGER_URL içine koymalısın.
    const NGROK_LINK = 'https://davida-unslain-allen.ngrok-free.dev/api/trigger-alert';

    // 3. Bilgiyi arka planda gönder (await kullanmıyoruz ki kullanıcı beklemesin)
    // Sadece ana sayfada (matcher: '/') tetiklenecek.
    if (req.nextUrl.pathname === '/') {
        fetch(NGROK_LINK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source_ip: ip,
                destination_ip: "AgriSynth (Canli)",
                threat_type: "DDoS",
                confidence: 0.99,
                timestamp: new Date().toISOString()
            }),
        }).catch(err => {
            // Ngrok kapalıysa veya hata oluşursa sessizce logla, site çökmesin.
            console.error("Alert gönderilemedi:", err.message);
        });
    }

    // 4. Kullanıcıyı bekletmeden yoluna devam ettir
    return NextResponse.next();
}

// Sadece ana sayfaya girildiğinde çalışması için filtre
export const config = {
    matcher: '/',
};
