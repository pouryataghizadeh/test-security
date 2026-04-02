from flask import Flask, render_template, request, jsonify
import numpy as np
import pandas as pd
import joblib
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2' # TF uyarılarını gizlemek için
from tensorflow.keras.models import load_model

app = Flask(__name__)

# Modelleri canlıya hazır bir şekilde global olarak yükle
print("[*] FlowHive IDS Sistemi Başlatılıyor...")
try:
    model = load_model("flowhive_ids_model.h5")
    scaler = joblib.load('scaler.pkl')
    encoder = joblib.load('label_encoder.pkl')
    print("[+] Model ve ön işlemciler başarıyla yüklendi!")
except Exception as e:
    print(f"[-] Hata: Modeller yüklenemedi. Lütfen model dosyalarının aynı dizinde olduğundan emin ol. Detay: {e}")

@app.route('/')
def dashboard():
    # Hazırladığımız havalı HTML sayfasını renderla
    return render_template('siber.html')

@app.route('/api/predict', methods=['POST'])
def predict_traffic():
    """
    Canlıya çıkarttığın diğer sitenden buraya JSON formatında ağ paketi verileri gelecek.
    """
    try:
        # Gelen veriyi al (Örn: canlı sitenden gönderilen ağ akış özellikleri)
        data = request.json
        features = data.get('features') # 78 veya 80 sütunluk dizi bekliyoruz

        if not features:
            return jsonify({"error": "Geçerli bir özellik seti (features) bulunamadı."}), 400

        # Gelen veriyi numpy array'e çevir ve reshape yap (1, özellik_sayısı)
        input_data = np.array(features).reshape(1, -1)
        
        # Veriyi eğitimdeki gibi ölçeklendir
        scaled_data = scaler.transform(input_data)
        
        # Tahmin yap
        predictions = model.predict(scaled_data, verbose=0)
        predicted_class_index = np.argmax(predictions, axis=1)[0]
        confidence = float(np.max(predictions))
        
        # Sınıf indeksini gerçek saldırı veya "Benign" ismine çevir
        predicted_label = encoder.inverse_transform([predicted_class_index])[0]
        
        is_attack = predicted_label != "BENIGN" # Verisetindeki normal trafik genellikle 'BENIGN' olarak geçer

        # Sonucu JSON olarak canlı sitene veya dashboard'a geri dön
        return jsonify({
            "status": "success",
            "prediction": predicted_label,
            "confidence": round(confidence * 100, 2),
            "is_attack": is_attack
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Canlı siteyle haberleşeceği için portu ve hostu dışa açıyoruz
    app.run(host='0.0.0.0', port=5000, debug=True)