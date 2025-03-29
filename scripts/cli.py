import ssl
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from playwright.sync_api import sync_playwright

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                valid_from = cert['notBefore']
                valid_to = cert['notAfter']
                issuer = dict(x[0] for x in cert['issuer'])
                return {
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "issuer": issuer.get("O", "Unbekannt"),
                    "org_cn": issuer.get("CN", "Unbekannt"),
                    "common_name": cert.get("subject", [["commonName", "Unbekannt"]])[0][1],
                    "serial": cert.get("serialNumber", "N/A"),
                    "sha1": ssock.getpeercert(True).hex(),
                    "sha256": "Not available via socket"  # Optional: mit OpenSSL ersetzen
                }
    except Exception as e:
        return {"error": str(e)}

def fetch_html(url):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="load", timeout=20000)
            page.wait_for_timeout(2000)  # Kurze Wartezeit, damit JS laden kann
            content = page.content()
            browser.close()
            return content
    except Exception as e:
        print(f"Fehler beim Laden mit Playwright: {e}")
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

def detect_software(html):
    soup = BeautifulSoup(html, 'html.parser')
    scripts = soup.find_all("script", src=True)
    found = []
    for script in scripts:
        src = script["src"]
        if "gtag/js" in src or "analytics.js" in src:
            found.append("Google Analytics")
        elif "facebook.net" in src:
            found.append("Facebook Pixel")
        elif "hotjar.com" in src:
            found.append("Hotjar")
    return list(set(found))

def main():
    console = Console()
    url = input("Gib eine URL ein (mit https://): ").strip()
    domain = urlparse(url).hostname

    print("\n🔍 Lade Seite...")
    html = fetch_html(url)
    if not html:
        return

    title, desc = extract_meta(html)
    table = Table(show_header=False, title="GENERAL INFORMATION", title_style="bold green")
    table.add_row("Title:", title)
    table.add_row("Description:", desc if desc else "Keine Beschreibung gefunden")
    table.add_row("URL:", url)
    table.add_row("Software:", "Unbekannt")  # Placeholder
    console.print(table)

    print("\n🛠️  Erkannte Software/Tracker:")
    software = detect_software(html)
    if software:
        for s in software:
            print(f"  - {s}")
    else:
        print("  Keine Tracker erkannt")

    print("\n🎨 WordPress Theme:")
    theme = detect_wordpress_theme(html)
    print(f"  Theme: {theme}" if theme else "  Kein WordPress-Theme gefunden")

    print("\n🔐 SSL-Zertifikat:")
    ssl_info = get_ssl_info(domain)
    if "error" in ssl_info:
        console.print(f"[red]SSL-Fehler:[/red] {ssl_info['error']}")
    else:
        ssl_table = Table(show_header=False, title="SSL CERTIFICATE", title_style="bold green")
        ssl_table.add_row("Common Name:", ssl_info.get("common_name", ""))
        ssl_table.add_row("Organization:", ssl_info.get("issuer", ""))
        ssl_table.add_row("Organization CN:", ssl_info.get("org_cn", ""))
        ssl_table.add_row("Valid from:", ssl_info['valid_from'])
        ssl_table.add_row("Valid to:", ssl_info['valid_to'])
        ssl_table.add_row("Serial Number:", ssl_info.get("serial", ""))
        ssl_table.add_row("FP SHA-1:", ssl_info.get("sha1", ""))
        ssl_table.add_row("FP SHA-256:", ssl_info.get("sha256", ""))
        console.print(ssl_table)

if __name__ == "__main__":
    main()
