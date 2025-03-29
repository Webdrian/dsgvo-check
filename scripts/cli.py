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
        ssl_table.add_row("Issuer:", ssl_info['issuer'])
        ssl_table.add_row("Valid from:", ssl_info['valid_from'])
        ssl_table.add_row("Valid to:", ssl_info['valid_to'])
        ssl_table.add_row("Common Name:", ssl_info['common_name'])
        ssl_table.add_row("Serial Number:", ssl_info['serial_number'])
        ssl_table.add_row("FP SHA-1:", ssl_info['sha1'])
        ssl_table.add_row("FP SHA-256:", ssl_info['sha256'])
        console.print(ssl_table)

if __name__ == "__main__":
    main()
