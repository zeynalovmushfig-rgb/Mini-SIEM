import json
import os

def show_dashboard():
    print("\n" + "="*85)
    print("MINI-SIEM Dashboard v0.4".center(85))
    print("="*85 + "\n")

    if not os.path.exists("alerts.json"):
        print("[-] Henuz hicbir alarm kaydedilmemis! (alerts.json bulunamadi)")
        return

# Loglari dosyadan okuma

    with open("alerts.json", "r", encoding="utf-8") as f:
        lines = f.readlines()

    print(f"Toplam Tespit Edilen Tehdit Sayisi:{len(lines)}\n")

#Tablo Basliklari
    print(f"{'ZAMAN':<22} | {'SEVIYE':<10} | {'MITRE':<7} | {'KURAL':<25} | {'KAYNAK IP'}")
    print("-" * 85)

#Her bir JSON satirini tabloya terlestirme
    for line in lines:
        try:
            alert = json.loads(line.strip())
        # RENklendirme mantigi
            severity = alert['severity']
            if severity == "CRITICAL":
                sev_text = f"\033[91m{severity}\033[0m" # Kirmizi
            elif severity == "HIGH":
                sev_text = f"\033[93m{severity}\033[0m" #SAri
            else :
                sev_text = f"\033[96m{severity}\033[0m" # MAVI

            print (f"{alert['timestamp']:<22} | {sev_text:<19} | {alert['mitre_tactic']:<7} | {alert['rule']:<25} | {alert['source_ip']}")
        except Exception as e:
            print("HATA:",e)
            

    print("\n" + "="*85)

if __name__ == "__main__":
    show_dashboard()


