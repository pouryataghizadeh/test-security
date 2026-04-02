// Dikkat: next/server importunu tamamen kaldırdık. 
// Bu sayede Vercel, projeni Next.js projesi sanıp hata vermeyecek.

export default function middleware(req, event) {
    // 1. Giren kişinin IP adresini yakala
    const forwarded = req.headers.get('x-forwarded-for');
    const ip = forwarded ? forwarded.split(',')[0] : 'Bilinmeyen IP';

    // 2. İstihbaratın gideceği Ngrok adresi
    const NGROK_LINK = 'https://davida-unslain-allen.ngrok-free.dev/api/trigger-alert';

    // 3. İsteğin URL'ini parse et
    const url = new URL(req.url);

    // 4. Sadece ana sayfaya ( / ) girildiğinde tetiklenmesini sağla
    if (url.pathname === '/') {
        // 5. event.waitUntil ile kullanıcıyı bekletmeden arka planda veriyi gönder
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
                // Ngrok kapalıysa Vercel loglarına yaz, siteyi çökertme
                console.error("Alert gönderilemedi:", err.message);
            })
        );
    }

    // 6. En önemli kısım: Vercel'in akışı kesmeyip index.html'i göstermeye devam etmesi için
    // standart Edge Middleware cevabını döndürüyoruz.
    return new Response(null, {
        headers: {
            'x-middleware-next': '1'
        }
    });
}

// Vercel'e bu ajan kodun sadece ana dizin isteklerinde çalışacağını bildiriyoruz
export const config = {
    matcher: '/',
};
