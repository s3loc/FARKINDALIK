#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REDHACK Sentinel: Kablosuz Keşif ve Farkındalık Aracı
# Versiyon: 1.0 Elite
# Lisans: AGPL-3.0

import os
import sys
import csv
import sqlite3
import threading
import time
import subprocess
import re
import json
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from bleak import BleakScanner
from scapy.all import sniff, Dot11, RadioTap
import requests

# -------------------- KONFİGÜRASYON --------------------
CONFIG = {
    "WIFI_INTERFACE": "wlan0",
    "MONITOR_INTERFACE": "wlan0mon",
    "BLUETOOTH_INTERFACE": "hci0",
    "DATABASE": "sentinel.db",
    "AIRODUMP_LOG": "airodump.log",
    "SCAN_INTERVAL": 5,  # Saniye
    "TELEGRAM_TOKEN": None,
    "TELEGRAM_CHAT_ID": None,
    "PACKET_THRESHOLD": 100
}

# -------------------- ASCII ART --------------------
def show_banner():
    banner = r"""
⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⠟⠡⠶⣎⠤⠤⠤⡸⣫⡝⠛⠏⠹⠩⠍⠫⢝⡶⢄⡈⠙⣿⣿⣿
⣿⣿⣿⡏⠀⠀⠊⠀⠀⠀⠀⠀⠑⠂⠓⠁⠀⠀⠀⠀⠀⠈⠚⠄⡄⢸⣿⣿
⣿⡿⠋⡀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⢻⣿
⡿⠁⡜⠀⠉⠐⠀⠀⠀⠀⠀⢠⣤⣾⣿⣅⣤⠀⠀⠀⣀⠤⠒⠓⠲⡄⠊⢿
⡇⢰⠀⠀⠀⠀⠀⣀⡐⠒⠀⠒⠈⠻⠟⠃⠀⠂⠀⢀⡀⡄⠀⠀⠀⠘⡔⢸
⣿⡌⢆⠀⠀⠀⠀⠀⡙⠺⣶⣤⣾⣶⢠⣿⣦⣿⣏⠏⡁⠀⠀⠀⠀⢀⠇⣼
⣿⣿⣮⡑⠠⡀⠀⠀⠀⠁⠀⠀⠄⠰⠐⠄⠲⠈⠀⠀⠀⠀⠀⡀⠀⠬⣳⣿
⣿⣿⣿⣷⡄⠐⠑⢆⡄⠀⠁⠰⠤⣤⢠⢠⢀⡤⠊⠀⠀⣠⠄⠀⢠⣼⣿⣿
⣿⣿⣿⣿⣿⣆⠑⢄⢘⡆⢠⢠⢠⣤⣤⣤⣤⢠⠆⢢⡿⡇⠀⣰⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣇⠐⡷⡘⣄⠀⠘⠿⠘⠛⠙⠀⡰⢞⡤⢀⣼⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣷⡉⣷⢙⢦⣀⣀⣀⣀⣀⡔⢣⠏⢀⣾⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠿⣵⡿⠿⠛⠛⣓⣷⠎⠊⣾⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣙⣿⣷⣶⣿⣿⠋⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣯⣭⣿⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    """
    print(banner)
    print(f"[*] Sistem Başlatılıyor: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Wi-Fi Arayüzü: {CONFIG['WIFI_INTERFACE']}")
    print(f"[*] Bluetooth Arayüzü: {CONFIG['BLUETOOTH_INTERFACE']}")
    print("[*] 0 Hata Politikası Aktif")

# -------------------- VERİTABANI YÖNETİMİ --------------------
class DatabaseManager:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.initialize_db()
        
    def initialize_db(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY,
                mac TEXT UNIQUE,
                name TEXT,
                type TEXT,
                rssi INTEGER,
                first_seen DATETIME,
                last_seen DATETIME,
                packet_count INTEGER DEFAULT 0
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS rssi_history (
                id INTEGER PRIMARY KEY,
                device_id INTEGER,
                rssi INTEGER,
                timestamp DATETIME,
                FOREIGN KEY(device_id) REFERENCES devices(id)
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS bluetooth_status (
                id INTEGER PRIMARY KEY,
                status TEXT,
                timestamp DATETIME
            )
        ''')
        self.conn.commit()
    
    def device_exists(self, mac):
        self.cursor.execute("SELECT id FROM devices WHERE mac=?", (mac,))
        return self.cursor.fetchone()
    
    def update_device(self, device_id, rssi, packet_count):
        self.cursor.execute('''
            UPDATE devices 
            SET rssi=?, last_seen=?, packet_count=packet_count+?
            WHERE id=?
        ''', (rssi, datetime.now(), packet_count, device_id))
        self.conn.commit()
    
    def insert_device(self, mac, name, dev_type, rssi):
        now = datetime.now()
        self.cursor.execute('''
            INSERT INTO devices (mac, name, type, rssi, first_seen, last_seen, packet_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
        ''', (mac, name, dev_type, rssi, now, now))
        self.conn.commit()
        return self.cursor.lastrowid
    
    def record_rssi(self, device_id, rssi):
        self.cursor.execute('''
            INSERT INTO rssi_history (device_id, rssi, timestamp)
            VALUES (?, ?, ?)
        ''', (device_id, rssi, datetime.now()))
        self.conn.commit()
    
    def log_bluetooth_status(self, status):
        self.cursor.execute('''
            INSERT INTO bluetooth_status (status, timestamp)
            VALUES (?, ?)
        ''', (status, datetime.now()))
        self.conn.commit()
    
    def get_all_devices(self):
        self.cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        return self.cursor.fetchall()
    
    def get_rssi_history(self, device_id, limit=50):
        self.cursor.execute('''
            SELECT rssi, timestamp 
            FROM rssi_history 
            WHERE device_id=? 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (device_id, limit))
        return self.cursor.fetchall()
    
    def get_bluetooth_status_history(self, limit=20):
        self.cursor.execute('''
            SELECT status, timestamp 
            FROM bluetooth_status 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        return self.cursor.fetchall()

# -------------------- Wİ-Fİ TARAMA MODÜLÜ --------------------
class WiFiScanner(threading.Thread):
    def __init__(self, db_manager):
        threading.Thread.__init__(self)
        self.db = db_manager
        self.stop_event = threading.Event()
        self.monitor_mode_set = False
        self.setup_monitor_mode()
        
    def setup_monitor_mode(self):
        try:
            # Monitor modu kontrolü
            subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
            result = subprocess.run(["airmon-ng", "start", CONFIG["WIFI_INTERFACE"]], 
                                  capture_output=True, text=True)
            
            if "monitor mode enabled" in result.stdout:
                self.monitor_mode_set = True
                print(f"[+] {CONFIG['WIFI_INTERFACE']} monitor modunda başlatıldı")
            else:
                print("[-] Monitor mod etkinleştirme hatası!")
                sys.exit(1)
                
        except Exception as e:
            logging.error(f"WiFi başlatma hatası: {str(e)}")
            sys.exit(1)
    
    def packet_handler(self, packet):
        if packet.haslayer(Dot11):
            mac = packet.addr2
            if not mac or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                return
                
            rssi = packet.dBm_AntSignal if hasattr(packet, "dBm_AntSignal") else -100
            ssid = packet.info.decode('utf-8', 'ignore') if packet.info else "Bilinmeyen"
            
            # Veritabanı işlemleri
            device = self.db.device_exists(mac)
            if device:
                self.db.update_device(device[0], rssi, 1)
            else:
                device_id = self.db.insert_device(mac, ssid, "wifi", rssi)
            
            self.db.record_rssi(device_id if device else self.db.cursor.lastrowid, rssi)
    
    def run(self):
        print("[*] Wi-Fi pasif tarama başlatıldı")
        sniff(iface=CONFIG["MONITOR_INTERFACE"], 
              prn=self.packet_handler,
              store=False,
              stop_filter=lambda x: self.stop_event.is_set())

    def stop(self):
        self.stop_event.set()
        subprocess.run(["airmon-ng", "stop", CONFIG["MONITOR_INTERFACE"]])
        print("[*] Wi-Fi tarayıcı durduruldu")

# -------------------- BLUETOOTH TARAMA MODÜLÜ --------------------
class BluetoothScanner(threading.Thread):
    def __init__(self, db_manager):
        threading.Thread.__init__(self)
        self.db = db_manager
        self.stop_event = threading.Event()
        self.current_status = "active"
        self.status_history = []
        
    def detection_callback(self, device, advertisement_data):
        mac = device.address
        name = device.name or "Bilinmeyen"
        rssi = advertisement_data.rssi if advertisement_data.rssi else -100
        
        # Veritabanı işlemleri
        device_entry = self.db.device_exists(mac)
        if device_entry:
            self.db.update_device(device_entry[0], rssi, 1)
            device_id = device_entry[0]
        else:
            device_id = self.db.insert_device(mac, name, "bluetooth", rssi)
            
        self.db.record_rssi(device_id, rssi)
        
        # Bluetooth durum değişikliklerini logla
        if self.current_status != "active":
            self.current_status = "active"
            self.db.log_bluetooth_status("active")
            if CONFIG["TELEGRAM_TOKEN"]:
                self.send_notification("📶 Bluetooth tarayıcı AKTİF")

    async def run_scan(self):
        scanner = BleakScanner(detection_callback=self.detection_callback)
        while not self.stop_event.is_set():
            await scanner.start()
            await asyncio.sleep(CONFIG["SCAN_INTERVAL"])
            await scanner.stop()
            
            # Bluetooth durum kontrolü
            if self.current_status == "active":
                self.current_status = "inactive"
                self.db.log_bluetooth_status("inactive")
                if CONFIG["TELEGRAM_TOKEN"]:
                    self.send_notification("🚫 Bluetooth tarayıcı PASİF")

    def run(self):
        print("[*] Bluetooth pasif tarama başlatıldı")
        asyncio.run(self.run_scan())

    def stop(self):
        self.stop_event.set()
        print("[*] Bluetooth tarayıcı durduruldu")
        
    def send_notification(self, message):
        if not CONFIG["TELEGRAM_TOKEN"] or not CONFIG["TELEGRAM_CHAT_ID"]:
            return
            
        url = f"https://api.telegram.org/bot{CONFIG['TELEGRAM_TOKEN']}/sendMessage"
        payload = {
            "chat_id": CONFIG["TELEGRAM_CHAT_ID"],
            "text": message
        }
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            logging.error(f"Telegram bildirim hatası: {str(e)}")

# -------------------- WEB ARAYÜZÜ --------------------
app = Flask(__name__)
db_manager = DatabaseManager(CONFIG["DATABASE"])

@app.route('/')
def dashboard():
    devices = db_manager.get_all_devices()
    bt_history = db_manager.get_bluetooth_status_history()
    return render_template('dashboard.html', devices=devices, bt_history=bt_history)

@app.route('/api/devices')
def api_devices():
    devices = db_manager.get_all_devices()
    return jsonify([dict(zip(('id', 'mac', 'name', 'type', 'rssi', 'first_seen', 'last_seen', 'packet_count'), d)) for d in devices])

@app.route('/api/rssi_history/<int:device_id>')
def api_rssi_history(device_id):
    history = db_manager.get_rssi_history(device_id)
    return jsonify([{'rssi': h[0], 'timestamp': h[1]} for h in history])

@app.route('/api/bluetooth_history')
def api_bluetooth_history():
    history = db_manager.get_bluetooth_status_history()
    return jsonify([{'status': h[0], 'timestamp': h[1]} for h in history])

@app.route('/toggle_bluetooth', methods=['POST'])
def toggle_bluetooth():
    # Bluetooth durumunu değiştirme (simülasyon)
    current_status = "active" if request.json.get('status') else "inactive"
    db_manager.log_bluetooth_status(current_status)
    return jsonify(success=True)

# -------------------- ANA YÖNETİM --------------------
def main():
    show_banner()
    
    # Kök kullanıcı kontrolü
    if os.geteuid() != 0:
        print("[-] Bu araç root yetkileri gerektirir!")
        sys.exit(1)
    
    # Bağımlılık kontrolü
    try:
        subprocess.run(["airmon-ng", "--version"], stdout=subprocess.DEVNULL)
        subprocess.run(["hcitool", "--version"], stdout=subprocess.DEVNULL)
    except FileNotFoundError:
        print("[-] Gerekli araçlar kurulu değil: airmon-ng, hcitool")
        sys.exit(1)
    
    # Veritabanı ve tarayıcıları başlat
    wifi_scanner = WiFiScanner(db_manager)
    bt_scanner = BluetoothScanner(db_manager)
    
    try:
        wifi_scanner.start()
        bt_scanner.start()
        
        # Flask'ı ayrı thread'de başlat
        flask_thread = threading.Thread(target=lambda: app.run(
            host='0.0.0.0', port=5000, debug=False, use_reloader=False))
        flask_thread.daemon = True
        flask_thread.start()
        
        print("[+] Sistem başarıyla başlatılddı")
        print("[*] Web arayüzü: http://localhost:5000")
        
        # Ana thread'i beklet
        while True:
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\n[*] Sistem durduruluyor...")
        wifi_scanner.stop()
        bt_scanner.stop()
        sys.exit(0)
    except Exception as e:
        logging.critical(f"Kritik hata: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    import asyncio
    main() 