from fetching import fetch_html_and_requests, extract_meta
from cms import detect_cms, detect_wordpress_theme, detect_plugins
from ssl_info import get_ssl_info
from cookies import analyze_cookies, load_cookie_db
from email_sicherheit import check_email_security
from dsgvo import evaluate_risks
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
import json

# Definieren der Console Instanz
console = Console()

def main():
    url = input("Gib eine URL ein (mit https://): ").strip()
    domain = urlparse(url).hostname

    # Abruf der HTML-Daten, Cookies, etc.
    html, network_requests, pre_consent_requests, cookie_tool, cookie_banner = fetch_html_and_requests(url)
    title, desc = extract_meta(html)
    cms_list, builder_list = detect_cms(html)
    theme = detect_wordpress_theme(html)
    plugins = detect_plugins(html)
    ssl_info = get_ssl_info(domain)
    cookies_before, cookies_after, suspicious, tools_detected = analyze_cookies(url)
    cookie_db = load_cookie_db()
    raw_email_security = check_email_security(domain)
    if isinstance(raw_email_security, list):
        raw_email_security = raw_email_security[0] if raw_email_security else {}
    risks, violations, indicators = evaluate_risks(url, network_requests, pre_consent_requests, "scripts/json/riskmap.json")

    # Abschnitt: Allgemeine Informationen
    console.rule("[bold green]1. Allgemeine Informationen[/bold green]")
    console.print(f"[bold]URL:[/bold] {url}")
    console.print(f"[bold]Titel:[/bold] {title}")
    console.print(f"[bold]Beschreibung:[/bold] {desc or 'Keine Beschreibung gefunden'}")
    console.print()

    # Abschnitt: Software
    console.rule("[bold cyan]2. Software[/bold cyan]")
    console.print(f"[bold]CMS:[/bold] {', '.join(cms_list) if cms_list else 'Nicht erkannt'}")
    console.print(f"[bold]Page-Builder:[/bold] {', '.join(builder_list) if builder_list else 'Nicht erkannt'}")
    console.print(f"[bold]Theme:[/bold] {theme or 'Nicht erkannt'}")
    console.print()
    if plugins:
        console.print("[bold]Plugins:[/bold]")
        for plugin in plugins:
            console.print(f"  • {plugin}")
    else:
        console.print("[bold]Plugins:[/bold] Keine erkannt")
    console.print()

    # Abschnitt: Tracker
    console.rule("[bold magenta]3. Tracker[/bold magenta]")
    with open('scripts/json/trackers.json', 'r', encoding='utf-8') as f:
        trackers = json.load(f)

    detected_trackers = set()

    for tracker in trackers:
        for match in tracker["match"]:
            if any(match.lower() in request.lower() for request in network_requests):
                detected_trackers.add(tracker['name'])

    if detected_trackers:
        console.print("[yellow]⚠️ Tracker erkannt:[/yellow]")
        for tracker in sorted(detected_trackers):
            console.print(f"  • {tracker}")
        console.print()
    else:
        console.print("✅ Keine Tracker erkannt")
        console.print()

    # Abschnitt: DSGVO-Check
    console.rule("[bold red]4. DSGVO-Check[/bold red]")
    total_issues = len(risks) + len(violations) + len(indicators)

    if risks:
        console.print("[yellow]⚠️ Risiken laut RiskMap:[/yellow]")
        for r in risks:
            console.print(f"  ⚠️ {r['name']} → {r['category']} (Risiko: {r['risk']})")

    console.print()
    if violations:
        console.print("[red]🚨 Vor Einwilligung geladen:[/red]")
        for v in violations:
            console.print(f"  🚨 {v['name']} → {v['category']} (Risiko: {v['risk']})")

    if total_issues == 0:
        console.print()
        console.print("🟢 [bold green]DSGVO-Ampel: Keine Probleme erkannt[/bold green]")
    elif total_issues <= 2:
        console.print()
        console.print(f"🟡 [bold yellow]DSGVO-Ampel: {total_issues} kleinere Probleme erkannt[/bold yellow]")
    else:
        console.print()
        console.print(f"🔴 [bold red]DSGVO-Ampel: {total_issues} Risiken erkannt – bitte prüfen[/bold red]")
    console.print()

    if indicators:
        console.print("[red]❌ Weitere Auffälligkeiten:[/red]")
        for i in indicators:
            console.print(f"  ❌ {i}")
    if not any([risks, violations, indicators]):
        console.print("[green]Keine DSGVO-Probleme erkannt.[/green]")

    # Abschnitt: Cookies
    console.rule("[bold yellow]5. Cookies[/bold yellow]")
    if cookie_tool:
        console.print(f"[bold]Erkanntes Cookie-Tool:[/bold] {cookie_tool}")
    if cookie_banner:
        console.print("[green]✅ Cookie-Banner erkannt[/green]")
    else:
        console.print("[red]❌ Kein Cookie-Banner erkannt[/red]")

    console.print(f"[bold]🍪 Cookies vor Zustimmung:[/bold] {len(cookies_before)}")
    console.print(f"[bold]🍪 Cookies nach Zustimmung:[/bold] {len(cookies_after)}")

    if not cookies_before and not cookies_after:
        console.print("Keine Cookies erkannt.")
    console.print()

    # Abschnitt: E-Mail-Sicherheit
    console.rule("[bold blue]6. E-Mail-Sicherheit[/bold blue]")

    email_security = {
        "spf": raw_email_security.get("spf", {"status": False, "score": 0}),
        "dkim": raw_email_security.get("dkim", {"status": False, "score": 0}),
        "dmarc": raw_email_security.get("dmarc", {"status": False, "score": 0, "policy": "Keine Policy gefunden"}),
        "score": raw_email_security.get("score", 0),
        "rating": raw_email_security.get("rating", "Keine Bewertung verfügbar"),
    }

    spf_status = email_security["spf"]["status"]
    dkim_status = email_security["dkim"]["status"]
    dmarc_status = email_security["dmarc"]["status"]
    dmarc_policy = email_security["dmarc"].get("policy", "Keine Policy gefunden")

    console.print("✅ SPF vorhanden" if spf_status else "❌ SPF fehlt")
    console.print("✅ DKIM vorhanden" if dkim_status else "❌ DKIM fehlt oder falsch konfiguriert")
    console.print(f"✅ DMARC vorhanden (Policy: {dmarc_policy})" if dmarc_status else "❌ DMARC fehlt oder falsch konfiguriert")
    console.print()

    score = email_security.get("score", 0)
    rating = email_security.get("rating", "Keine Bewertung verfügbar")
    console.print(f"🔐 Gesamtbewertung: [bold blue]{score}/10[/bold blue] – [bold]{rating}[/bold]")
    console.print("[green]Diese Sicherheitsmechanismen schützen deine Domain vor Spoofing, Phishing und unautorisiertem E-Mail-Versand.[/green]")
    console.print()

    # Abschnitt: SSL-Zertifikat
    console.rule("[bold white]7. SSL-Zertifikat[/bold white]")
    if ssl_info and "error" not in ssl_info:
        console.print(f"Issuer: {ssl_info['issuer']}")
        console.print(f"Common Name: {ssl_info['common_name']}")
        console.print(f"Gültig von: {ssl_info['valid_from']} bis {ssl_info['valid_to']}")
        console.print(f"SHA-1: {ssl_info['sha1']}")
        console.print(f"SHA-256: {ssl_info['sha256']}")
    else:
        console.print(f"[red]SSL-Zertifikat konnte nicht abgerufen werden.[/red]")

if __name__ == "__main__":
    main()