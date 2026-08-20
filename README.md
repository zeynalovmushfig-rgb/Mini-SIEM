# Mini-SIEM: Canli log analizi ve Tehdit Avciligi
Bu proje,Linux sistemlerindeki kimlik dogrulama loglarini ('/var/log/auth.log') canli olarak izeyen,Regex ile IP tespiti yapan ve supheli guvenlik olaylarini kategorize ederek alarm ureten Python tabanli bir **SOC Tehdit Tespit Mekanizmasidir**

##Ozellikler

1.SSH Brute-Force Tespiti (Critical):Belirli bir IP adresinden gelen basarisiz giris denemelerini IP bazli olarak takip eder.Esik deger(3) asildiginda kritik alarm uretir.

2.SQL Injection Tespiti (High):Log akisinda gecen 'UnionSelect','OR 1=1' gibi veri tabani sizma kaliplarini anlik olarak yakalar.

3.Port Tarama / Nmap TEspiti(Medium):Ag taramasi ve kesif aktivitelerine ait izleri tespit eder.


##Kurulum ve Calistirma

Projeyi klonlayip calistirmak icin:

'''bash
git clone [https://github.com/zeynalovmushfig-rgb/Mini-SIEM.git](https://github.com/zeynalovmushfig-rgb/Mini-SIEM.git)
cd Mini-SIEM
sudo python3 siem.py

