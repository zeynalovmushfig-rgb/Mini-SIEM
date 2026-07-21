import time
import os 

log_yolu = "/var/log/auth.log"
hatali_giris_sayaci = 0

print("[*] MINI-SIEM STARTED... Canli Tehdit Avciligi Aktif.\n")

with open(log_yolu, "r") as dosya:
   dosya.seek(0,os.SEEK_END)
   while True:
      satir= dosya.readline()
      if satir:
         print(f"[LOG] {satir.strip()}")

         if "authentication failure" in satir or "FAILED SU" in satir:
            hatali_giris_sayaci +=1
            print (f"\n [UYARI] Hatali giris tespit edildi sayac: {hatali_giris_sayaci}\n")

            if hatali_giris_sayaci >=3:
               print("\n [Alarm] - Brute force attack detected! \n")
               hatali_giris_sayaci = 0

         time.sleep(0.1)
      