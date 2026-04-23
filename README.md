# 🛡️ OssiqnScan Framework
**Gelismis, Multi-Threaded ve Kapsamli Web Zafiyet Tarama Motoru**

[![Developer](https://img.shields.io/badge/Developer-Ossiqn-0e75b6?style=for-the-badge)](https://github.com/ossiqn)
[![Python](https://img.shields.io/badge/Python-3.x-yellow?style=for-the-badge&logo=python)](https://python.org)
[![Website](https://img.shields.io/badge/Website-Live-green?style=for-the-badge)](https://ossiqn.com.tr)

---

## 📖 Proje Hakkinda

OssiqnScan, harici bir aractan bagimsiz olarak tamamen kendi motoruyla calisan, yuksek performansli bir guvenlik tarama framework'udur. WAF tespiti, bypass teknikleri ve otomatik cozum onerileri (Fix) ile sistemlerinizi derinlemesine analiz eder. Tamamen Python ile, gereksiz kodlardan arindirilmis tertemiz bir mimariyle gelistirilmistir.

## ✨ Temel Ozellikler

* **Kapsamli Tarama:** XSS, SQLi, LFI, RFI, SSRF, IDOR, XXE, Command Injection, CSRF, Open Redirect ve Dosya Yukleme zafiyetleri.
* **WAF Bypass:** Cloudflare, ModSecurity gibi guvenlik duvarlarini tespit eder ve otomatik bypass teknikleri (Header manipulasyonu, payload obfuscation) uygular.
* **Akilli Cozum Onerileri (Fix Modulu):** Tespit edilen zafiyetlerin altyapisini inceleyip nasil kapatilacagina dair nokta atisi guvenlik tavsiyeleri sunar.
* **Ozel Turkce CMS Destegi:** Yerel CMS sistemlerinde (WordPress, Joomla vb.) bilinen kronik aciklari ve dizinleri otomatik tarar.
* **Multi-Threading:** Yuzlerce is parcacigi (thread) ile inanilmaz hizli port, servis ve subdomain taramasi gerceklestirir.
* **Raporlama & Loglama:** Sonuclari anlik olarak terminale yansitir, ayni zamanda detayli log ve JSON formatiyla cihazina kaydeder.

## 🚀 Kurulum

Gereksinimleri yuklemek ve projeyi calistirmak sadece birkac saniye surer:

```bash
git clone [https://github.com/ossiqn/Ossiqn-Vuln-Framework.git](https://github.com/ossiqn/Ossiqn-Vuln-Framework.git)
cd Ossiqn-Vuln-Framework
pip install requests colorama dnspython
python ossiqn.py
💻 Kullanim Ornegi
Araci baslattiktan sonra konsol uzerinden komutlarla taramanizi yapilandirabilirsiniz:

Bash
ossiqn > set URL [https://hedefsite.com](https://hedefsite.com)
ossiqn > set PORT_RANGE 1-1000
ossiqn > scan
ossiqn > vulns
ossiqn > use 1
ossiqn > show options
ossiqn > fix 1
⚠️ Yasal Uyari
Bu arac yalnizca egitim, guvenlik arastirmalari ve yetkili guvenlik testleri (pentest) amaciyla gelistirilmistir. Izin almadan herhangi bir sisteme karsi kullanilmasi yasa disidir. Olusabilecek tum yasal sorumluluk kodu kullanan kisiye aittir.

Coded with ⚡ by Ossiqn
