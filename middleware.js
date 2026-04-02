export default async function middleware(req) {
  // 1. Giren kişinin gerçek IP adresini gizlice alıyoruz
  const ip = req.headers.get('x-forwarded-for') || 'Bilinmeyen IP';
  
  // 2. Senin şu an açık olan gizli Ngrok İstihbarat Hattın
  const NGROK_LINK = 'https://davida-unslain-allen.ngrok-free.dev'; 

  try {
    // 3. Bilgiyi AgriSynth'ten senin odandaki bilgisayara fırlat!
    // Await ekliyoruz ki sinyal gitmeden Vercel işlemi kapatmasın
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
  // NextResponse yerine standart Vercel pas geçme komutunu (x-middleware-next) kullanıyoruz
  return new Response(null, {
    headers: { 'x-middleware-next': '1' }
  });
}

// Bu ajan sadece ana sayfaya girildiğinde çalışsın
export const config = {
  matcher: '/',
};
