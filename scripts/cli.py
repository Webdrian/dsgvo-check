import ssl
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime

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
                    "issuer": issuer.get("O", "Unbekannt")
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
    url = input("Gib eine URL ein (mit https://): ").strip()
    domain = urlparse(url).hostname

    print("\n🔍 Lade Seite...")
    html = fetch_html(url)
    if not html:
        return

    print("\n📄 Meta-Daten:")
    title, desc = extract_meta(html)
    print(f"  Titel: {title}")
    print(f"  Beschreibung: {desc if desc else 'Keine Beschreibung gefunden'}")

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
        print(f"  Fehler: {ssl_info['error']}")
    else:
        print(f"  Ausgestellt von: {ssl_info['issuer']}")
        print(f"  Gültig von: {ssl_info['valid_from']}")
        print(f"  Gültig bis: {ssl_info['valid_to']}")

if __name__ == "__main__":
    main()
