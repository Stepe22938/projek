import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from scapy.all import sniff, IP, TCP, UDP
import threading
import time
from datetime import datetime
import subprocess
import logging
import socket
import requests
import json
import re

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ddos_defense.log"),
        logging.StreamHandler()
    ]
)

class DDoSDefenseAI:
    def __init__(self):
        self.normal_traffic_profile = {}
        self.current_traffic = {}
        self.suspicious_ips = set()
        self.attack_detected = False
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        self.target_ip = None
        self.interface = None
        self.pterodactyl_api_url = None
        self.pterodactyl_api_key = None
        
    def get_user_input(self):
        """Mendapatkan informasi dari pengguna"""
        print("=" * 50)
        print("SISTEM PERTAHANAN DDoS BERBASIS AI")
        print("=" * 50)
        
        # Meminta target IP
        while True:
            target = input("Masukkan alamat IP server yang ingin dilindungi: ").strip()
            if self.validate_ip(target):
                self.target_ip = target
                break
            else:
                print("Alamat IP tidak valid. Silakan coba lagi.")
        
        # Meminta interface jaringan
        self.interface = input("Masukkan interface jaringan (tekan Enter untuk default): ").strip()
        if not self.interface:
            self.interface = None
        
        # Meminta konfigurasi Pterodactyl (opsional)
        pterodactyl = input("Apakah menggunakan Pterodactyl? (y/n): ").strip().lower()
        if pterodactyl == 'y':
            self.pterodactyl_api_url = input("Masukkan URL API Pterodactyl: ").strip()
            self.pterodactyl_api_key = input("Masukkan API Key Pterodactyl: ").strip()
            
        print("\nSistem sedang disiapkan...")
        logging.info(f"Target IP: {self.target_ip}")
        if self.pterodactyl_api_url:
            logging.info(f"Pterodactyl terintegrasi: {self.pterodactyl_api_url}")
    
    def validate_ip(self, ip):
        """Validasi alamat IP"""
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not pattern.match(ip):
            return False
        
        parts = ip.split('.')
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    
    def integrate_with_pterodactyl(self, action, ip_address=None):
        """Berintegrasi dengan panel Pterodactyl"""
        if not self.pterodactyl_api_url or not self.pterodactyl_api_key:
            return False
        
        headers = {
            'Authorization': f'Bearer {self.pterodactyl_api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        try:
            if action == "get_servers":
                # Mendapatkan daftar server dari Pterodactyl
                response = requests.get(f"{self.pterodactyl_api_url}/api/application/servers", headers=headers)
                if response.status_code == 200:
                    return response.json()
                else:
                    logging.error(f"Gagal mendapatkan server dari Pterodactyl: {response.status_code}")
                    return None
            
            elif action == "block_ip" and ip_address:
                # Membuat firewall rule untuk memblokir IP
                data = {
                    "type": "block",
                    "protocol": "all",
                    "interface": "any",
                    "source": ip_address,
                    "destination": "any",
                    "action": "drop"
                }
                response = requests.post(f"{self.pterodactyl_api_url}/api/application/firewall/rules", 
                                        headers=headers, data=json.dumps(data))
                if response.status_code in [200, 201]:
                    logging.info(f"IP {ip_address} berhasil diblokir di Pterodactyl firewall")
                    return True
                else:
                    logging.error(f"Gagal memblokir IP di Pterodactyl: {response.status_code}")
                    return False
                    
        except Exception as e:
            logging.error(f"Error integrasi Pterodactyl: {str(e)}")
            return False
    
    def extract_features(self, packet):
        """Ekstrak fitur dari paket jaringan untuk analisis"""
        if IP in packet and (packet[IP].dst == self.target_ip or packet[IP].src == self.target_ip):
            ip_src = packet[IP].src
            
            # Inisialisasi entri untuk IP sumber jika belum ada
            if ip_src not in self.current_traffic:
                self.current_traffic[ip_src] = {
                    'packet_count': 0,
                    'bytes': 0,
                    'ports': set(),
                    'protocols': set(),
                    'start_time': time.time(),
                    'last_seen': time.time()
                }
            
            # Update statistik
            self.current_traffic[ip_src]['packet_count'] += 1
            self.current_traffic[ip_src]['bytes'] += len(packet)
            self.current_traffic[ip_src]['last_seen'] = time.time()
            
            if TCP in packet:
                self.current_traffic[ip_src]['ports'].add(packet[TCP].dport)
                self.current_traffic[ip_src]['protocols'].add('TCP')
            elif UDP in packet:
                self.current_traffic[ip_src]['ports'].add(packet[UDP].dport)
                self.current_traffic[ip_src]['protocols'].add('UDP')
            else:
                self.current_traffic[ip_src]['protocols'].add(f'OTHER_{packet[IP].proto}')
    
    def train_normal_profile(self, duration=300):
        """Melatih model dengan profil traffic normal"""
        logging.info(f"Melatih model dengan traffic normal selama {duration} detik")
        print("Sedang mempelajari pola traffic normal...")
        time.sleep(duration)
        
        # Siapkan data untuk training
        features = []
        for ip, stats in self.current_traffic.items():
            features.append([
                stats['packet_count'],
                stats['bytes'],
                len(stats['ports']),
                len(stats['protocols']),
                stats['last_seen'] - stats['start_time']
            ])
        
        if features:
            X = np.array(features)
            self.model.fit(X)
            self.normal_traffic_profile = self.current_traffic.copy()
            self.is_trained = True
            logging.info("Model AI telah dilatih dengan profil traffic normal")
            print("Model AI telah siap dan mulai memantau traffic")
        else:
            logging.warning("Tidak cukup data untuk training model")
            print("Peringatan: Traffic jaringan sangat rendah, model mungkin kurang akurat")
        
        # Reset traffic data setelah training
        self.current_traffic = {}
    
    def detect_anomalies(self):
        """Mendeteksi anomaly dalam traffic jaringan"""
        if not self.is_trained:
            logging.warning("Model belum dilatih, tidak dapat mendeteksi anomaly")
            return
        
        features = []
        ip_list = []
        
        for ip, stats in self.current_traffic.items():
            features.append([
                stats['packet_count'],
                stats['bytes'],
                len(stats['ports']),
                len(stats['protocols']),
                stats['last_seen'] - stats['start_time']
            ])
            ip_list.append(ip)
        
        if features:
            X = np.array(features)
            predictions = self.model.predict(X)
            
            for i, pred in enumerate(predictions):
                if pred == -1:  # Anomali terdeteksi
                    suspicious_ip = ip_list[i]
                    self.suspicious_ips.add(suspicious_ip)
                    logging.warning(f"Anomali terdeteksi dari IP: {suspicious_ip}")
                    
                    # Jika banyak anomali, mungkin serangan DDoS
                    if len(self.suspicious_ips) > 10:
                        self.attack_detected = True
                        logging.critical("Serangan DDoS terdeteksi!")
                        print("PERINGATAN: Serangan DDoS terdeteksi!")
                        self.mitigate_attack()
    
    def mitigate_attack(self):
        """Melakukan mitigasi serangan DDoS"""
        if self.attack_detected:
            logging.info("Memulai mitigasi serangan DDoS")
            print("Melakukan mitigasi serangan...")
            
            # Blokir IP yang mencurigakan menggunakan iptables (Linux)
            for ip in self.suspicious_ips:
                try:
                    # Blokir IP yang mencurigakan
                    subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                    logging.info(f"IP {ip} telah diblokir")
                    
                    # Jika terintegrasi dengan Pterodactyl, blokir di sana juga
                    if self.pterodactyl_api_url:
                        self.integrate_with_pterodactyl("block_ip", ip)
                        
                except subprocess.CalledProcessError as e:
                    logging.error(f"Gagal memblokir IP {ip}: {e}")
            
            # Redirect traffic mencurigakan ke blackhole (0.0.0.0)
            try:
                subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', 
                               '-s', ','.join(self.suspicious_ips), 
                               '-j', 'DNAT', '--to-destination', '0.0.0.0'], check=True)
                logging.info("Traffic mencurigakan dialihkan ke 0.0.0.0")
            except subprocess.CalledProcessError as e:
                logging.error(f"Gagal mengalihkan traffic: {e}")
            
            # Catat serangan untuk analisis lebih lanjut
            self.log_attack()
            
            # Reset status setelah mitigasi
            self.attack_detected = False
            self.suspicious_ips = set()
            
            print("Mitigasi serangan selesai. Traffic mencurigakan telah diblokir dan dialihkan.")
    
    def log_attack(self):
        """Mencatat detail serangan untuk analisis"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ddos_attack_{timestamp}.log"
        
        with open(filename, 'w') as f:
            f.write(f"DDoS Attack Detected at {datetime.now()}\n")
            f.write(f"Target IP: {self.target_ip}\n")
            f.write(f"Number of suspicious IPs: {len(self.suspicious_ips)}\n")
            f.write("Suspicious IPs:\n")
            for ip in self.suspicious_ips:
                f.write(f"- {ip}\n")
                if ip in self.current_traffic:
                    stats = self.current_traffic[ip]
                    f.write(f"  Packets: {stats['packet_count']}, Bytes: {stats['bytes']}\n")
        
        logging.info(f"Detail serangan telah dicatat dalam {filename}")
    
    def start_monitoring(self):
        """Memulai monitoring traffic jaringan"""
        logging.info("Memulai monitoring traffic jaringan")
        print("Sistem monitoring telah aktif...")
        
        # Thread untuk training awal
        training_thread = threading.Thread(target=self.train_normal_profile)
        training_thread.daemon = True
        training_thread.start()
        
        # Thread untuk periodic anomaly detection
        def periodic_detection():
            while True:
                time.sleep(30)  # Cek setiap 30 detik
                self.detect_anomalies()
                # Reset traffic data setelah deteksi
                self.current_traffic = {}
        
        detection_thread = threading.Thread(target=periodic_detection)
        detection_thread.daemon = True
        detection_thread.start()
        
        # Mulai sniffing paket
        try:
            if self.interface:
                sniff(iface=self.interface, prn=self.extract_features, store=0)
            else:
                sniff(prn=self.extract_features, store=0)
        except Exception as e:
            logging.error(f"Error dalam monitoring: {str(e)}")
            print(f"Error: {str(e)}")
            print("Pastikan Anda menjalankan script dengan hak akses administrator")

# Jalankan sistem pertahanan DDoS
if __name__ == "__main__":
    ai_defense = DDoSDefenseAI()
    ai_defense.get_user_input()
    
    try:
        ai_defense.start_monitoring()
    except KeyboardInterrupt:
        logging.info("Sistem pertahanan DDoS dihentikan")
        print("\nSistem dihentikan oleh pengguna")
