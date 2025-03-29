import ssl
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import hashlib
from core import detect_software
from playwright.sync_api import sync_playwright
import json

network_requests = []
cookie_banner_detected = False
cookie_tool_name = None
pre_consent_requests = []

def fetch_html_and_requests(url):
    global cookie_banner_detected, cookie_tool_name, network_requests, pre_consent_requests
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Phase A: vor Consent-Klick
        temp_requests = []
        page.on("request", lambda request: temp_requests.append(request.url))

        page.goto(url, wait_until="load", timeout=20000)
        page.wait_for_timeout(3000)

        html = page.content()

        cookie_keywords = [
            "akzeptieren", "alle cookies", "nur essenzielle", "cookie einstellungen",
            "datenschutz", "zustimmen", "cookie-richtlinie", "tracking erlauben"
        ]
        cookie_banner_detected = any(word in html.lower() for word in cookie_keywords)

        # Erkenne Cookie-Tool
        known_tools = {
            "Borlabs Cookie": ["borlabs-cookie", "borlabs-cookie-blocker"],
            "Real Cookie Banner": ["real-cookie-banner"],
            "Cookiebot": ["consent.cookiebot.com", "cookiebot"],
            "Complianz": ["cmplz", "complianz.io"],
            "CookieYes": ["cookieyes", "cookie-law-info"],
            "OneTrust": ["onetrust", "optanon"],
            "Usercentrics": ["usercentrics"],
            "Didomi": ["didomi"]
        }
        for name, patterns in known_tools.items():
            for pattern in patterns:
                if pattern.lower() in html.lower():
                    cookie_tool_name = name
                    break
            if cookie_tool_name:
                break

        # Speichere Requests vor Consent
        pre_consent_requests = temp_requests.copy()

        # Phase B: versuche Consent zu geben
        try:
            selectors = [
                "text=Alle akzeptieren",
                "text=Zustimmen",
                "text=Einverstanden",
                "button:has-text('Akzeptieren')",
                "button:has-text('OK')",
                "text=Ich stimme zu"
            ]
            for selector in selectors:
                try:
                    page.click(selector, timeout=2000)
                    break
                except:
                    continue
        except:
            pass

        # Phase B: neue Requests nach Klick sammeln
        network_requests = []
        page.on("request", lambda request: network_requests.append(request.url))
        page.wait_for_timeout(5000)
        html = page.content()

        browser.close()
        return html

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                binary_cert = ssock.getpeercert(binary_form=True)
                valid_from = cert['notBefore']
                valid_to = cert['notAfter']
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                sha1 = hashlib.sha1(binary_cert).hexdigest()
                sha256 = hashlib.sha256(binary_cert).hexdigest()
                return {
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "issuer": issuer.get("O", "Unbekannt"),
                    "common_name": subject.get("commonName", domain),
                    "serial_number": cert.get("serialNumber", "N/A"),
                    "sha1": sha1,
                    "sha256": sha256
                }
    except Exception as e:
        return {"error": str(e)}

def fetch_html(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response.text
    except Exception as e:
        print(f"Fehler beim Abrufen von {url}: {e}")
        return None

def extract_meta(html):
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.string if soup.title else "Kein Titel gefunden"
    desc = ""
    desc_tag = soup.find("meta", attrs={"name": "description"})
    if desc_tag and desc_tag.get("content"):
        desc = desc_tag["content"]
    return title.strip(), desc.strip()

def detect_wordpress_theme(html):
    if "/wp-content/themes/" in html:
        start = html.find("/wp-content/themes/") + len("/wp-content/themes/")
        end = html.find("/", start)
        theme = html[start:end]
        return theme
    return None

def detect_cms(html):
    cms_patterns = {
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Wix": ["wix.com", "wixsite", "Wix.ads", "viewerWix"],
        "Webflow": ["webflow.js", "webflow.css", "data-wf-page"],
        "Joomla": ["joomla"],
        "Drupal": ["drupal", "sites/all", "misc/drupal.js"],
        "Typo3": ["typo3"],
        "Squarespace": ["static.squarespace.com"],
        "Shopify": ["cdn.shopify.com", "shopify"]
    }

    builder_patterns = {
        "Elementor": ["elementor"],
        "Divi": ["et_pb_section", "et_pb_module", "et_pb_row", "et_pb_column"]
    }

    cms_found = []
    builders_found = []

    for name, patterns in cms_patterns.items():
        for pattern in patterns:
            if pattern.lower() in html.lower():
                cms_found.append(name)
                break

    for name, patterns in builder_patterns.items():
        for pattern in patterns:
            if pattern.lower() in html.lower():
                builders_found.append(name)
                break

    return sorted(set(cms_found)), sorted(set(builders_found))

def main():
    console = Console()
    url = input("Gib eine URL ein (mit https://): ").strip()
    domain = urlparse(url).hostname
    risks = []

    print("\n🔍 Lade Seite...")
    html = fetch_html_and_requests(url)
    software = detect_software(html)
    title, desc = extract_meta(html)
    ssl_info = get_ssl_info(domain)

    # Abschnitt: GENERAL INFORMATION
    table = Table(show_header=False, title="1. GENERAL INFORMATION", title_style="bold green")
    table.add_row("URL:", url)
    table.add_row("Title:", title)
    table.add_row("Description:", desc if desc else "Keine Beschreibung gefunden")
    console.print(table)

    # Erweiterte Risikoauswertung über riskmap.json
    try:
        with open("scripts/riskmap.json", "r", encoding="utf-8") as f:
            riskmap = json.load(f)
    except Exception as e:
        print(f"Fehler beim Laden von riskmap.json: {e}")
        riskmap = []

    # Phase-A-Verstöße prüfen: Was wurde vor dem Consent geladen?
    pre_consent_violations = []

    for entry in riskmap:
        for pattern in entry["match"]:
            if any(pattern.lower() in url.lower() for url in pre_consent_requests):
                pre_consent_violations.append({
                    "name": entry["name"],
                    "category": entry["category"],
                    "risk": entry["risk"],
                    "note": entry.get("note", "")
                })
                break

    matched_risks = []

    for entry in riskmap:
        for pattern in entry["match"]:
            if any(pattern.lower() in url.lower() for url in network_requests):
                matched_risks.append({
                    "name": entry["name"],
                    "category": entry["category"],
                    "risk": entry["risk"],
                    "note": entry.get("note", "")
                })
                break

    # Abschnitt: SOFTWARE / CMS
    cms_list, builder_list = detect_cms(html)
    theme = detect_wordpress_theme(html)
    console.print("\n[bold]2. Software – CMS[/bold]")
    if cms_list:
        print(f"  CMS: {', '.join(cms_list)}")
    if builder_list:
        print(f"  Page-Builder: {', '.join(builder_list)}")
    if theme:
        print(f"  Theme: {theme}")

    # Plugins (nur WordPress)
    wordpress_plugins = []
    if "WordPress" in cms_list:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("link", href=True):
            if "/wp-content/plugins/" in tag["href"]:
                plugin = tag["href"].split("/wp-content/plugins/")[1].split("/")[0]
                if plugin not in wordpress_plugins:
                    wordpress_plugins.append(plugin)
        for tag in soup.find_all("script", src=True):
            if "/wp-content/plugins/" in tag["src"]:
                plugin = tag["src"].split("/wp-content/plugins/")[1].split("/")[0]
                if plugin not in wordpress_plugins:
                    wordpress_plugins.append(plugin)

    if wordpress_plugins:
        print(f"  Plugins:")
        for p in sorted(set(wordpress_plugins)):
            print(f"    - {p}")
    else:
        print("  Plugins: Keine erkannt")

    # Abschnitt: Tracker
    console.print("\n[bold]3. Tracker[/bold]")
    if software:
        for s in software:
            print(f"  - {s}")
    else:
        print("  Keine Tracker erkannt")

    # Abschnitt: DSGVO-CHECK
    console.print("\n[bold red]4. DSGVO-Check[/bold red]")

    if matched_risks:
        console.print("\n[bold yellow]⚠️ Risiken laut RiskMap:[/bold yellow]")
        for r in matched_risks:
            console.print(f"  ⚠️ [bold]{r['name']}[/bold]  →  {r['category']} (Risiko: {r['risk']})")
            if r["note"]:
                console.print(f"     [dim]Grund:[/dim] {r['note']}")

    if pre_consent_violations:
        console.print("\n[bold red]❗️ Verstöße: Tracker vor Einwilligung geladen[/bold red]")
        for r in pre_consent_violations:
            console.print(f"  ❗️ [bold]{r['name']}[/bold]  →  {r['category']} (Risiko: {r['risk']})")
            if r["note"]:
                console.print(f"     [dim]Grund:[/dim] {r['note']}")

    if risks:
        console.print("\n[bold red]❌ Weitere DSGVO-Indikatoren:[/bold red]")
        for r in sorted(set(risks)):
            console.print(f"  ❌ {r}")

    # Ampel direkt darunter anzeigen
    total_risks = len(risks) + len(matched_risks) + len(pre_consent_violations)
    if total_risks == 0:
        console.print("\n🟢 [bold green]DSGVO-Ampel: Keine erkannten Risiken[/bold green]")
    elif total_risks <= 2:
        console.print(f"\n🟡 [bold yellow]DSGVO-Ampel: {total_risks} mögliche Probleme erkannt[/bold yellow]")
    else:
        console.print(f"\n🔴 [bold red]DSGVO-Ampel: {total_risks} Risiken erkannt – genau prüfen![/bold red]")

    # Abschnitt: 6. Cookies
    console.print("\n[bold magenta]6. Cookies gesetzt[/bold magenta]")

    cookies = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(url, timeout=20000)
            page.wait_for_timeout(3000)
            cookies = context.cookies()
            browser.close()
    except Exception as e:
        cookies = []

    if cookies:
        cookie_table = Table(title="Gesetzte Cookies", show_lines=True)
        cookie_table.add_column("Name", style="bold")
        cookie_table.add_column("Domain")
        cookie_table.add_column("Path")
        cookie_table.add_column("Expires")
        cookie_table.add_column("Secure")
        cookie_table.add_column("HttpOnly")

        for c in cookies:
            name = c.get("name", "")
            domain = c.get("domain", "")
            path = c.get("path", "")
            expires = str(c.get("expires", ""))
            secure = str(c.get("secure", ""))
            http_only = str(c.get("httpOnly", ""))
            cookie_table.add_row(name, domain, path, expires, secure, http_only)

        console.print(cookie_table)
        
        # Verdächtige Cookies markieren
        suspicious_keywords = ["_ga", "_gid", "_gat", "_fbp", "matomo", "piwik", "ajs_", "amplitude", "hubspot", "ac_", "tracking", "sessionid", "cookie_consent", "cluid"]
        suspicious_cookies = [c["name"] for c in cookies if any(keyword in c["name"].lower() for keyword in suspicious_keywords)]
        
        if suspicious_cookies:
            console.print("\n[bold red]⚠️ Verdächtige Cookies erkannt:[/bold red]")
            for sc in suspicious_cookies:
                console.print(f"  ⚠️ {sc}")
            # DSGVO-Ampel mitverdacht erhöhen
            risks.append("Verdächtige Cookies gesetzt (z. B. Tracking ohne Einwilligung möglich)")
    else:
        console.print("Keine Cookies erkannt.")

    # Abschnitt: 5. E-Mail-Sicherheitsprüfung
    console.print("\n[bold blue]5. E-Mail-Sicherheit[/bold blue]")

    def check_dns_record(name):
        try:
            import dns.resolver
            answers = dns.resolver.resolve(name, 'TXT')
            return [r.to_text() for r in answers]
        except:
            return []

    def check_email_security(domain):
        result = {}
        result["SPF"] = check_dns_record(domain)
        result["DMARC"] = check_dns_record(f"_dmarc.{domain}")
        result["DKIM"] = check_dns_record(f"default._domainkey.{domain}")
        return result

    email_security = check_email_security(domain)

    score = 0
    total = 3
    for key in ["SPF", "DKIM", "DMARC"]:
        records = email_security.get(key, [])
        if any("v=" in r for r in records):
            console.print(f"✅ {key} vorhanden")
            score += 1
        else:
            console.print(f"❌ {key} fehlt oder falsch konfiguriert")

    rating_text = {
        3: "Sehr gut geschützt",
        2: "Gut, aber Verbesserung möglich",
        1: "Schwach abgesichert",
        0: "Keine Schutzmaßnahmen erkannt"
    }

    console.print(f"\n🔐 Gesamtbewertung: {score}/3 – {rating_text[score]}")
    console.print("Diese Sicherheitsmechanismen schützen deine Domain vor Spoofing, Phishing und unautorisiertem E-Mail-Versand.")

    # SSL-Zertifikat anzeigen
    console.print("\n[bold]SSL-Zertifikat:[/bold]")
    if ssl_info and "error" not in ssl_info:
        cert_table = Table(show_header=False)
        cert_table.add_row("Issuer:", ssl_info["issuer"])
        cert_table.add_row("Valid from:", ssl_info["valid_from"])
        cert_table.add_row("Valid to:", ssl_info["valid_to"])
        cert_table.add_row("Common Name:", ssl_info["common_name"])
        cert_table.add_row("Serial Number:", ssl_info["serial_number"])
        cert_table.add_row("FP SHA-1:", ssl_info["sha1"])
        cert_table.add_row("FP SHA-256:", ssl_info["sha256"])
        console.print(cert_table)
    else:
        print("Konnte SSL-Zertifikat nicht abrufen.")

if __name__ == "__main__":
    main()
