import re 
import time 

LOG_FILE = "/var/log/auth.log"

BRUTE_FORCE_LIMIT = 3
failed_attempts = {}

def analyze_line(line):
    if "Failed password" in line or "authentication failure" in line:
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if ip_match:
            ip = ip_match.group(1)

            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            print(f"[UYARI] BASARISIZ Giris! IP: {ip} | Toplam Hata :{failed_attempts[ip]}")

            if failed_attempts[ip] >= BRUTE_FORCE_LIMIT:
                print(f"[ALARM -CRITICAL] Brrute-Force saldirisi tespiti!Saldirgan IP:{ip}")

    sql_patterns = ["UNION SELECT", "OR 1=1", "' OR '1' = '1'", "DROP TABLE"]
    for pattern in sql_patterns:
        if pattern.lower() in line.lower():
            print(f"[ALARM - HIGH] SQL Injection Denemesi Tespiti YAkalanan Kalip: '{pattern}'")

    if "nmap" in line.lower() or "portscan" in line.lower():
        print(f"[ALARM - MEDIUM] SUPHELI port taramasi / nmap Tespiti")

def start_monitoring():
    print("Mini-SIEM muhafizi calisiyor... Loglar canli izleniyor...\n" + "="*60)
    try:
        with open(LOG_FILE, "r") as file:
            file.seek(0, 2)
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                analyze_line(line)
    except FileNotFoundError:
        print(f"HATA: {LOG_FILE} dosyasi bulunamadi")
    except KeyboardInterrupt:
        print("\n Mini-SIE durduruldu.")

if __name__ == "__main__":
    start_monitoring()
