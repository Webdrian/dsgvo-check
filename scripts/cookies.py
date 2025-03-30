from playwright.sync_api import sync_playwright
import json

def analyze_cookies(url):
    from rich.console import Console
    from rich.table import Table

    console = Console()
    cookies_before = []
    cookies_after = []
    suspicious = []
    cookie_db = {}

    try:
        with open("scripts/json/cookies.json", "r", encoding="utf-8") as f:
            cookie_db = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Fehler beim Laden von cookies.json:[/bold red] {e}")
        return [], [], []

    def find_cookie_info(name):
        for entry in cookie_db:
            if name.lower().startswith(entry["name"].lower()):
                return entry
        return None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            page.goto(url, timeout=20000)
            page.wait_for_timeout(3000)
            cookies_before = context.cookies()

            # Consent klicken
            selectors = [
                "text=Alle akzeptieren", "text=Zustimmen", "text=Einverstanden",
                "button:has-text('Akzeptieren')", "button:has-text('OK')",
                "text=Ich stimme zu"
            ]
            for selector in selectors:
                try:
                    page.click(selector, timeout=2000)
                    break
                except:
                    continue

            page.wait_for_timeout(3000)
            cookies_after = context.cookies()
            browser.close()
    except Exception as e:
        console.print(f"Fehler beim Cookie-Check: {e}")
        return [], [], []

    # Verdächtige Cookies analysieren
    for c in cookies_before:
        info = find_cookie_info(c.get("name", ""))
        if info and info["category"] in ["Analyse", "Marketing"]:
            suspicious.append(c.get("name", ""))

    return cookies_before, cookies_after, suspicious