import { NextResponse } from 'next/server';

export async function middleware(req) {
  // 1. Giren kişinin gerçek IP adresini Vercel üzerinden gizlice alıyoruz
  const ip = req.headers.get('x-forwarded-for') || req.ip || 'Bilinmeyen IP';
  
  // 2. Senin şu an açık olan gizli Ngrok İstihbarat Hattın
  const NGROK_LINK = 'https://davida-unslain-allen.ngrok-free.dev/api/trigger-alert'; 

  try {
    // 3. Bilgiyi AgriSynth'ten senin odandaki bilgisayara (FlowHive IDS'e) fırlat!
    fetch(NGROK_LINK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source_ip: ip,
        destination_ip: "AgriSynth (Canli)",
        threat_type: "DDoS", // Ekranda net görebilmen için DDoS alarmı verdiriyoruz
        confidence: 0.99
      })
    });
  } catch (err) {
    // Ngrok kapalıysa veya internet koparsa AgriSynth çökmeyecek, çalışmaya devam edecek
  }

  return NextResponse.next(); // Kullanıcı siteyi normal şekilde gezmeye devam etsin
}

// Bu ajan sadece ana sayfaya girildiğinde çalışsın
export const config = {
  matcher: '/',
};