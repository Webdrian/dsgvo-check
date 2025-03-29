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

def fetch_html_and_requests(url):
    global cookie_banner_detected
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.on("request", lambda request: network_requests.append(request.url))

        page.goto(url, wait_until="load", timeout=20000)

        try:
            # Cookie-Consent aktiv akzeptieren, wenn möglich
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

        page.wait_for_timeout(7000)  # längere Wartezeit für dynamisch geladene Tracker

        html = page.content()

        cookie_keywords = [
            "akzeptieren", "alle cookies", "nur essenzielle", "cookie einstellungen",
            "datenschutz", "zustimmen", "cookie-richtlinie", "tracking erlauben"
        ]
        cookie_banner_detected = any(
            word in html.lower() for word in cookie_keywords
        )

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

def main():
    console = Console()
    url = input("Gib eine URL ein (mit https://): ").strip()
    domain = urlparse(url).hostname

    print("\n🔍 Lade Seite...")
    html = fetch_html_and_requests(url)
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

    # Erweiterung: Prüfe auf Tracker in Netzwerk-Requests
    external_trackers = []
    with open("scripts/trackers.json", "r", encoding="utf-8") as f:
        tracker_list = json.load(f)
        for url in network_requests:
            for tracker in tracker_list:
                for pattern in tracker["match"]:
                    if pattern.lower() in url.lower():
                        external_trackers.append(tracker["name"])
    external_trackers = sorted(set(external_trackers))
    software = sorted(set(software + external_trackers))

    if software:
        for s in software:
            print(f"  - {s}")
    else:
        print("  Keine Tracker erkannt")

    if cookie_banner_detected:
        console.print("\n🍪 [bold yellow]Cookie-Banner erkannt[/bold yellow]")
    else:
        console.print("\n✅ [green]Kein Cookie-Banner erkannt[/green]")

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
