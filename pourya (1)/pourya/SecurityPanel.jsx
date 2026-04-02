import React, { useState, useEffect } from 'react';

const SecurityPanel = () => {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    // Backend API'deki WebSocket'e bağlan
    const ws = new WebSocket('ws://localhost:8000/ws/alerts');

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      // Yeni alarmı listenin en üstüne ekle (En fazla 100 alarm tut)
      setAlerts((prev) => [data, ...prev].slice(0, 100));
    };

    return () => ws.close();
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-8 font-sans">
      <div className="flex justify-between items-center mb-8 border-b border-gray-700 pb-4">
        <h1 className="text-3xl font-bold tracking-wider text-blue-400">
          MERKEZİ AĞ GÜVENLİK İZLEME PANELİ
        </h1>
        <div className="flex items-center gap-3">
          <span className="relative flex h-4 w-4">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-4 w-4 bg-green-500"></span>
          </span>
          <span className="text-green-500 font-semibold">Sistem Aktif & Dinleniyor</span>
        </div>
      </div>

      <div className="bg-gray-800 rounded-xl shadow-2xl border border-gray-700 overflow-hidden">
        <div className="p-4 bg-gray-850 border-b border-gray-700">
          <h2 className="text-xl font-semibold text-red-400 flex items-center gap-2">
            ⚠️ Son Tespit Edilen Tehditler
          </h2>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-gray-750 text-gray-400 text-sm uppercase tracking-wide">
                <th className="p-4 border-b border-gray-700">Zaman</th>
                <th className="p-4 border-b border-gray-700">Kaynak IP</th>
                <th className="p-4 border-b border-gray-700">Hedef IP</th>
                <th className="p-4 border-b border-gray-700">Saldırı Türü</th>
                <th className="p-4 border-b border-gray-700">Eminlik Derecesi</th>
              </tr>
            </thead>
            <tbody className="text-sm">
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan="5" className="p-8 text-center text-gray-500 italic">
                    Ağ trafiği temiz. Tehdit bulunamadı.
                  </td>
                </tr>
              ) : (
                alerts.map((alert, index) => (
                  <tr key={index} className="hover:bg-gray-750 transition-colors">
                    <td className="p-4 border-b border-gray-700 text-gray-400">
                      {new Date().toLocaleTimeString()}
                    </td>
                    <td className="p-4 border-b border-gray-700 font-mono text-red-400">
                      {alert.source_ip}
                    </td>
                    <td className="p-4 border-b border-gray-700 font-mono text-blue-300">
                      {alert.destination_ip}
                    </td>
                    <td className="p-4 border-b border-gray-700">
                      <span className="bg-red-900/50 text-red-400 py-1 px-3 rounded-full font-semibold">
                        {alert.threat_type}
                      </span>
                    </td>
                    <td className="p-4 border-b border-gray-700 font-bold">
                      %{(alert.confidence * 100).toFixed(1)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default SecurityPanel;