from fetching import fetch_html_and_requests, extract_meta
from cms import detect_cms, detect_wordpress_theme, detect_plugins
from ssl_info import get_ssl_info
from cookies import analyze_cookies, load_cookie_db
from email_sicherheit import check_email_security
from dsgvo import evaluate_risks

from urllib.parse import urlparse
from rich.console import Console
import json

def main():
    console = Console()
    url = input("Gib eine URL ein (mit https://): ").strip()
    domain = urlparse(url).hostname

    html, network_requests, pre_consent_requests, cookie_tool, cookie_banner = fetch_html_and_requests(url)
    title, desc = extract_meta(html)
    cms_list, builder_list = detect_cms(html)
    theme = detect_wordpress_theme(html)
    plugins = detect_plugins(html)
    ssl_info = get_ssl_info(domain)
    cookies_before, cookies_after, suspicious = analyze_cookies(url)
    cookie_db = load_cookie_db()
    email_security = check_email_security(domain)
    risks, violations, indicators = evaluate_risks(url, network_requests, pre_consent_requests, "scripts/json/riskmap.json")

    # Abschnitt: Allgemeine Informationen
    console.rule("[bold green]1. Allgemeine Informationen[/bold green]")
    console.print(f"[bold]URL:[/bold] {url}")
    console.print(f"[bold]Titel:[/bold] {title}")
    console.print(f"[bold]Beschreibung:[/bold] {desc or 'Keine Beschreibung gefunden'}\n")
    console.print("\n")  # Füge eine Leerzeile nach diesem Abschnitt ein

    # Abschnitt: Software
    console.rule("[bold cyan]2. Software[/bold cyan]")
    console.print(f"[bold]CMS:[/bold] {', '.join(cms_list) if cms_list else 'Nicht erkannt'}")
    console.print(f"[bold]Page-Builder:[/bold] {', '.join(builder_list) if builder_list else 'Nicht erkannt'}")
    console.print(f"[bold]Theme:[/bold] {theme or 'Nicht erkannt'}\n")

    if plugins:
        console.print("[bold]Plugins:[/bold]")
        for plugin in plugins:
            console.print(f"  • {plugin}")
    else:
        console.print("[bold]Plugins:[/bold] Keine erkannt\n")
    console.print("\n")  # Füge eine Leerzeile nach diesem Abschnitt ein

    # Abschnitt: Tracker
    console.print("\n")  # Fügt oben einen Abstand hinzu
    console.rule("[bold magenta]3. Tracker[/bold magenta]")
    with open('scripts/json/trackers.json', 'r', encoding='utf-8') as f:
        trackers = json.load(f)

    detected_trackers = set()  # Verwende ein Set, um Duplikate zu vermeiden

    if network_requests:
        console.print("\n[yellow]⚠️ Tracker erkannt:[/yellow]")
        for tracker in trackers:
            for match in tracker["match"]:
                if any(match.lower() in request.lower() for request in network_requests):
                    detected_trackers.add(tracker['name'])

        # Ausgabe der Tracker ohne Duplikate
        for tracker in detected_trackers:
            console.print(f"  • {tracker}")

    console.print("\n")  # Fügt unten einen Abstand hinzu
    console.print("\n")  # Füge eine Leerzeile nach diesem Abschnitt ein

    # Abschnitt: DSGVO-Check
    console.rule("[bold red]4. DSGVO-Check[/bold red]")
    total_issues = len(risks) + len(violations) + len(indicators)

    # Mehr Abstand und korrekte Reihenfolge
    if risks:
        console.print("\n[yellow]⚠️ Risiken laut RiskMap:[/yellow]")
        for r in risks:
            console.print(f"  ⚠️ {r['name']} → {r['category']} (Risiko: {r['risk']})")

    if violations:
        console.print("\n[red]🚨 Vor Einwilligung geladen:[/red]")
        for v in violations:
            console.print(f"  🚨 {v['name']} → {v['category']} (Risiko: {v['risk']})")

    if total_issues == 0:
        console.print("\n🟢 [bold green]DSGVO-Ampel: Keine Probleme erkannt[/bold green]")
    elif total_issues <= 2:
        console.print(f"\n🟡 [bold yellow]DSGVO-Ampel: {total_issues} kleinere Probleme erkannt[/bold yellow]")
    else:
        console.print(f"\n🔴 [bold red]DSGVO-Ampel: {total_issues} Risiken erkannt – bitte prüfen[/bold red]")

    # Füge eine einzige Leerzeile nach der DSGVO-Ampel ein
    console.print("\n")

    if indicators:
        console.print("[red]❌ Weitere Auffälligkeiten:[/red]")
        for i in indicators:
            console.print(f"  ❌ {i}")
    if not any([risks, violations, indicators]):
        console.print("[green]Keine DSGVO-Probleme erkannt.[/green]\n")

    console.print("\n")  # Füge eine Leerzeile nach diesem Abschnitt ein

    # Abschnitt: Cookies
    console.rule("[bold yellow]5. Cookies[/bold yellow]")
    if cookie_tool:
        console.print(f"[bold]Erkanntes Cookie-Tool:[/bold] {cookie_tool}")
    if cookie_banner:
        console.print("[green]✅ Cookie-Banner erkannt[/green]")
    else:
        console.print("[red]❌ Kein Cookie-Banner erkannt[/red]")
    if cookies_before:
        console.print(f"[bold]Cookies vor Zustimmung:[/bold] {len(cookies_before)}")
    if suspicious:
        console.print("[red]🚨 Verdächtige Cookies vor Zustimmung:[/red]")
        for s in suspicious:
            console.print(f"  🚨 {s}")
    if cookies_after:
        console.print(f"[bold]Cookies nach Zustimmung:[/bold] {len(cookies_after)}")
    if not cookies_before and not cookies_after:
        console.print("Keine Cookies erkannt.\n")
    console.print("\n")  # Füge eine Leerzeile nach diesem Abschnitt ein

    # Abschnitt: E-Mail-Sicherheit
    console.rule("[bold blue]6. E-Mail-Sicherheit[/bold blue]")
    score = sum(1 for prot, records in email_security.items() if any("v=" in r for r in records))
    if score == 3:
        console.print("🟢 [bold green]E-Mail-Ampel: Sehr gut geschützt[/bold green]")
    elif score == 2:
        console.print("🟡 [bold yellow]E-Mail-Ampel: Teilweise geschützt[/bold yellow]")
    else:
        console.print("🔴 [bold red]E-Mail-Ampel: Schwach oder ohne Schutz[/bold red]")
    
    console.print("\n")  # Füge eine Leerzeile nach diesem Abschnitt ein

    # Abschnitt: SSL-Zertifikat
    console.rule("[bold white]7. SSL-Zertifikat[/bold white]")
    if ssl_info and "error" not in ssl_info:
        console.print(f"Issuer: {ssl_info['issuer']}")
        console.print(f"Common Name: {ssl_info['common_name']}")
        console.print(f"Gültig von: {ssl_info['valid_from']} bis {ssl_info['valid_to']}")
        console.print(f"SHA-1: {ssl_info['sha1']}")
        console.print(f"SHA-256: {ssl_info['sha256']}")
    else:
        console.print(f"[red]SSL-Zertifikat konnte nicht abgerufen werden.[/red]\n")
    console.print("\n")  # Füge eine Leerzeile nach diesem Abschnitt ein

if __name__ == "__main__":
    main()