from playwright.sync_api import sync_playwright
import requests
from bs4 import BeautifulSoup

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
        return html, network_requests, pre_consent_requests, cookie_tool_name, cookie_banner_detected

def fetch_html(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"
    }
    response = requests.get(url, headers=headers, timeout=10)
    return response.text

def extract_meta(html):
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.string if soup.title else "Kein Titel gefunden"
    desc_tag = soup.find("meta", attrs={"name": "description"})
    return title.strip(), desc_tag["content"].strip() if desc_tag else ""