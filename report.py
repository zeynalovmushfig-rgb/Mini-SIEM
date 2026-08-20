import json
from collections import Counter

ALERT_FILE = "alerts.json"

print("\n" + "="*55)
print("  MINI-SIEM V2.0 - VARDİYA SONU RAPORU ")
print("="*55 + "\n")

try:
    with open(ALERT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        print("[+] Bugün hiç alarm veya siber saldırı kaydedilmedi.")
    else:
        total_alerts = len(lines)
        print(f"[!] Toplam Tespit Edilen Tehdit Sayısı: {total_alerts}\n")

        rule_counts = Counter()
        severity_counts = Counter()
        ip_counts = Counter()

        for line in lines:
            data = json.loads(line)
            rule_counts[data.get("rule", "Bilinmeyen")] += 1
            severity_counts[data.get("severity", "Bilinmeyen")] += 1
            ip_counts[data.get("ip", "Bilinmeyen")] += 1

        print(" TEHDİT TÜRLERİ (KURAL BAZLI):")
        for rule, count in rule_counts.items():
            print(f"  - {rule}: {count} kez")

        print("\n RİSK SEVİYELERİ:")
        for severity, count in severity_counts.items():
            print(f"  - {severity}: {count} alarm")

        print("\n EN SALDIRGAN IP ADRESLERİ (İLK 3):")
        for ip, count in ip_counts.most_common(3):
            print(f"  - {ip}: {count} saldırı")

except FileNotFoundError:
    print(f"[-] HATA: {ALERT_FILE} dosyası bulunamadı. Sistem henüz bir log yakalamamış.")
except Exception as e:
    print(f"[-] Rapor oluşturulurken bir hata oluştu: {e}")

print("\n" + "="*55)
print("VArdiya Bitti")
print("="*55 + "\n")
