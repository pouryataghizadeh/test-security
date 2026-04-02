export default async function middleware(req) {
  // 1. Giren kişinin gerçek IP adresini gizlice alıyoruz
  const ip = req.headers.get('x-forwarded-for') || 'Bilinmeyen IP';
  
  // 2. İŞTE ÇÖZÜM BURADA! Ngrok linkinin sonuna /api/trigger-alert ekledik.
  // Bu, ajanımızın "ana kapıya" değil, "istihbarat odasına" gitmesini sağlar.
  const NGROK_LINK = 'https://davida-unslain-allen.ngrok-free.dev/api/trigger-alert'; 

  try {
    // 3. Bilgiyi AgriSynth'ten senin odandaki bilgisayara fırlat!
    await fetch(NGROK_LINK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source_ip: ip,
        destination_ip: "AgriSynth (Canli)",
        threat_type: "DDoS", 
        confidence: 0.99
      })
    });
  } catch (err) {
    // Ngrok kapalıysa site çökmeyecek
  }

  // 4. Kullanıcının siteyi normal şekilde gezmesine izin ver
  return new Response(null, {
    headers: { 'x-middleware-next': '1' }
  });
}

// Bu ajan sadece ana sayfaya girildiğinde çalışsın
export const config = {
  matcher: '/',
};
