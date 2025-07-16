# REDHACK Sentinel: Kablosuz Keşif ve Farkındalık Aracı


REDHACK Sentinel, çevredeki Wi-Fi ve Bluetooth cihazlarını tespit ederek kablosuz ağ farkındalığını artıran gelişmiş bir keşif aracıdır. Güvenlik uzmanları ve etik hacker'lar için tasarlanan bu araç, gerçek zamanlı cihaz izleme ve sinyal analizi sağlar.


🔍 Özellikler

    Çift Mod Tarama: Eşzamanlı Wi-Fi ve Bluetooth cihaz tespiti

    Sinyal İzleme: RSSI gücüne göre cihaz konum analizi

    Zaman Damgalı Kayıt: Cihazların ilk/son görülme zamanları

    Bluetooth Durum İzleme: Aktif/pasif durum geçmişi

    Entegre Web Paneli: Gerçek zamanlı veri görselleştirme

    Telegram Entegrasyonu: Anlık bildirimler (opsiyonel)

⚙️ Kurulum
Gereksinimler

    Python 3.8+

    Root yetkileri

    airmon-ng ve hcitool araçları

Adım Adım Kurulum
bash

# Gereken araçları kurun
sudo apt install aircrack-ng bluez

# Depedencies'leri yükleyin
pip install -r requirements.txt

# Veritabanını ve gerekli arayüzleri hazırlayın
sudo python sential.py --setup

🚀 Kullanım
bash

# Sistemi başlatma (root yetkisi gerektirir)
sudo python sential.py

# Web paneline erişim
http://localhost:5000

Yapılandırma

CONFIG bölümünden ayarları özelleştirin:
python

CONFIG = {
    "WIFI_INTERFACE": "wlan0",
    "BLUETOOTH_INTERFACE": "hci0",
    "TELEGRAM_TOKEN": "YOUR_BOT_TOKEN",  # Bildirimler için
    "TELEGRAM_CHAT_ID": "YOUR_CHAT_ID",
    "SCAN_INTERVAL": 5  # Tarama aralığı (saniye)
}



🛠️ Teknoloji Yığını

    Backend: Python 3, Flask, Bleak, Scapy

    Veritabanı: SQLite3

    Frontend: HTML5, Chart.js, CSS Grid

    Sistem Araçları: airmon-ng, hcitool



     Geliştirici Notları

    Bluetooth pasif tarama için Bleak kütüphanesi kullanılır

    Wi-Fi tespiti monitor modda çalışır

    Veriler SQLite veritabanında şifrelenmeden saklanır

    Üretim ortamında ek güvenlik önlemleri alınmalıdır

python

# Örnek veri yapısı
{
    "mac": "AA:BB:CC:DD:EE:FF",
    "name": "iPhone_Pro",
    "type": "bluetooth",
    "rssi": -67,
    "first_seen": "2023-11-05 14:30:22",
    "last_seen": "2023-11-05 15:45:18"
}

Proje Durumu: Aktif geliştirme aşamasında - PR'lar memnuniyetle karşılanır!
