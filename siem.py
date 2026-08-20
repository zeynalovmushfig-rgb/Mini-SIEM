import os
import re
import json
import time
from datetime import datetime

# --- AYARLAR ---
ALERT_JSON_FILE = "alerts.json"
RULES_JSON_FILE = "rules.json"
BAN_THRESHOLD = 3
ip_track = {}
banned_ips = set()
alert_counter = 1

# --- KURALLARI OKUMA ---
try:
    with open(RULES_JSON_FILE, "r") as f:
        rules = json.load(f)
except Exception as e:
    print(f"[-] HATA: {RULES_JSON_FILE} okunamadi! {e}")
    exit()

# --- IPS (OTOMATIK BAN) FONKSIYONU ---
def block_ip(ip):
    if ip == "127.0.0.1" or ip == "0.0.0.0": 
        return
        
    if ip not in banned_ips:
        print(f"\n[!!!] IPS DEVREDE: {ip} adresi {BAN_THRESHOLD} kez saldirdi!")
        print(f"[!!!] UFW GUVENLIK DUVARI BLOKLUYOR...")
        
        os.system(f"ufw deny from {ip} > /dev/null 2>&1")
        banned_ips.add(ip)
        
        print(f" BASARILI: {ip} tamamen engellendi!\n")

# --- ALARM FONKSIYONU ---
def generate_alert(rule_name, severity, source_ip, mitre_id):
    global alert_counter
    alert_id = f"ALERT-{alert_counter:04d}"
    alert_counter += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    alert_data = {
        "id": alert_id, "time": timestamp, "severity": severity,
        "rule": rule_name, "mitre": mitre_id, "ip": source_ip
    }
    
    print(f" [{severity}] {alert_id} | MITRE: {mitre_id} | IP: {source_ip} | Kural: {rule_name}")
    
    with open(ALERT_JSON_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert_data) + "\n")

    # Ban Sayaci Tetikleyicisi
    if source_ip != "127.0.0.1":
        ip_track[source_ip] = ip_track.get(source_ip, 0) + 1
        if ip_track[source_ip] >= BAN_THRESHOLD:
            block_ip(source_ip)

# --- ANALIZ MOTORU ---
def analyze_log_line(line):
    # SSH Brute Force Kontrolu (IP'yi cimbizla ceker)
    ssh_match = re.search(rules["SSH_BRUTE_PATTERN"], line)
    if ssh_match:
        ip = ssh_match.group(1) 
        generate_alert("SSH Brute Force", "CRITICAL", ip, "T1110")
        return
        
    if re.search(rules["SQLI_PATTERN"], line, re.IGNORECASE):
        generate_alert("SQL Injection", "HIGH", "127.0.0.1", "T1190")
        return
        
    if re.search(rules["XSS_PATTERN"], line, re.IGNORECASE):
        generate_alert("XSS Attack", "HIGH", "127.0.0.1", "T1189")
        return
        
    if re.search(rules["PORT_SCAN_PATTERN"], line, re.IGNORECASE):
        generate_alert("Port Scan", "MEDIUM", "127.0.0.1", "T1046")
        return
        
    if re.search(rules["SUDO_FAIL_PATTERN"], line, re.IGNORECASE):
        generate_alert("Sudo Auth Fail", "MEDIUM", "127.0.0.1", "T1548")
        return

# --- CANLI AV (LIVE TAIL) ---
def live_tail(log_file):
    print("\n=== MINI-SIEM v2.0 (KUSURSUZ SURUM) DEVREDE ===")
    print("[+] Firewall (UFW) silahlaniyor...")
    os.system("ufw --force enable > /dev/null 2>&1")
    print(f"[+] {log_file} izleniyor... Cikmak icin CTRL+C\n")

    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                
                # SIFIR HATA RADARI: Dosyaya yazi girerse once bunu basacak!
                if "Failed password" in line:
                    print(f"\n[RADAR] Dosyaya metin dustu: {line.strip()}")
                    
                analyze_log_line(line)
                
    except Exception as e:
        print(f"\nHATA OLUSTU: {e}")

if __name__ == "__main__":
    live_tail("/var/log/auth.log")