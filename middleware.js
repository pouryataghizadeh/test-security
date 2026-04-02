import { NextResponse } from 'next/server';

// 1. İkinci parametre olarak 'event'i ekliyoruz. 'async' kelimesine artık gerek yok.
export default function middleware(req, event) {
    const forwarded = req.headers.get('x-forwarded-for');
    const ip = forwarded ? forwarded.split(',')[0] : (req.ip || 'Bilinmeyen IP');

    const NGROK_LINK = 'https://davida-unslain-allen.ngrok-free.dev/api/trigger-alert';

    if (req.nextUrl.pathname === '/') {
        // 2. event.waitUntil kullanarak Vercel'e şunu diyoruz: 
        // "Kullanıcıyı bekletme ama bu arka plan işlemi bitmeden de sunucuyu (Edge) kapatma!"
        event.waitUntil(
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
                console.error("Alert gönderilemedi:", err.message);
            })
        );
    }

    // 3. Kullanıcı anında siteye girer.
    return NextResponse.next();
}

export const config = {
    matcher: '/',
};
