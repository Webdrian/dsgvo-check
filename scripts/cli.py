from fetching import fetch_html_and_requests, extract_meta
from cms import detect_cms, detect_wordpress_theme, detect_plugins, detect_technologies
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
    technologies = detect_technologies(html)
    ssl_info = get_ssl_info(domain)
    cookie_analysis = analyze_cookies(url)
    cookie_db = load_cookie_db()
    raw_email_security = check_email_security(domain)
    if isinstance(raw_email_security, list):
        raw_email_security = raw_email_security[0] if raw_email_security else {}

    def extract_record(data, default):
        if isinstance(data, list) and data:
            if isinstance(data[0], dict):
                return data[0]
            return default
        elif isinstance(data, dict):
            return data
        else:
            return default

    spf = extract_record(raw_email_security.get("spf"), {"status": False, "score": 0})
    dkim = extract_record(raw_email_security.get("dkim"), {"status": False, "score": 0})
    dmarc = extract_record(raw_email_security.get("dmarc"), {"status": False, "score": 0, "policy": "Keine Policy gefunden"})

    email_security = {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "score": raw_email_security.get("score", 0),
        "rating": raw_email_security.get("rating", "Keine Bewertung verfügbar"),
    }

    risk_result = evaluate_risks(url, network_requests, pre_consent_requests, "scripts/json/riskmap.json")
    critical = risk_result["critical_violations"]
    general = risk_result["general_risks"]
    indicators = risk_result["other_notes"]

    # Abschnitt: Allgemeine Informationen
    console.rule("[bold green]1. Allgemeine Informationen[/bold green]")
    console.print(f"[bold]URL:[/bold] {url}")
    console.print(f"[bold]Titel:[/bold] {title}")
    console.print(f"[bold]Beschreibung:[/bold] {desc or 'Keine Beschreibung gefunden'}")
    console.print()

    # Abschnitt: Software
    console.rule("[bold cyan]2. Software[/bold cyan]")
    # CMS + Hosting
    cms_display = ", ".join(cms_list) if cms_list else "Nicht erkannt"
    hosting_display = ", ".join(technologies["hosting"]) if technologies["hosting"] else "Nicht erkannt"
    console.print(f"[bold]CMS:[/bold] {cms_display} ({hosting_display})")

    # Shopsystem
    if technologies["shop"]:
        console.print(f"[bold]Shopsystem:[/bold] {', '.join(technologies['shop'])}")
    else:
        console.print("[bold]Shopsystem:[/bold] Nicht erkannt")

    # Page-Builder & Theme
    console.print(f"[bold]Page-Builder:[/bold] {', '.join(builder_list) if builder_list else 'Nicht erkannt'}")
    console.print(f"[bold]Theme:[/bold] {theme or 'Nicht erkannt'}")

    # Frameworks
    if technologies["frameworks"]:
        console.print(f"[bold]Frameworks:[/bold] {', '.join(technologies['frameworks'])}")
    else:
        console.print("[bold]Frameworks:[/bold] Nicht erkannt")

    # HTTP-Header Hinweis (Platzhalter)
    console.print("[bold]HTTP-Header:[/bold] (noch nicht implementiert)")

    # Plugins
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
    console.print("[italic]Hinweis: Externe Dienste und Tracker sollten erst nach Zustimmung geladen werden, um DSGVO-konform zu sein.[/italic]")
    console.print()

    # Kritische Verstöße (z.B. externe Dienste ohne Consent)
    if critical:
        console.print("[red]🚨 Kritische DSGVO-Verstöße:[/red]")
        for v in critical:
            console.print(f"  🚨 {v['name']} → {v['category']} (Risiko: {v['risk']})")
        console.print()

    # Optimierungspotenzial (Tools, die datenschutzfreundlicher konfiguriert werden können)
    if general:
        console.print("[yellow]⚠️ Optimierungspotenzial:[/yellow]")
        for r in general:
            console.print(f"  ⚠️ {r['name']} → {r['category']} (Risiko: {r['risk']})")
        console.print()

    # Externe Dienste ohne Zustimmung (z.B. Vimeo, YouTube, Google Maps)
    external_services = risk_result.get("external_services", [])
    if external_services:
        console.print("[red]🎥 Externe Dienste ohne Zustimmung geladen:[/red]")
        for service in external_services:
            console.print(f"  🎥 {service['name']} → {service['category']} (Risiko: {service['risk']})")
        console.print()

    # Weitere Hinweise (falls vorhanden)
    if indicators:
        console.print("[blue]ℹ️ Hinweise:[/blue]")
        for i in indicators:
            console.print(f"  ℹ️ {i}")
        console.print()

    # Keine Probleme erkannt
    if not any([critical, general, indicators, external_services]):
        console.print("[green]🟢 DSGVO-Ampel: Keine Probleme erkannt[/green]")

    # Abschnitt: Cookies
    console.rule("[bold yellow]5. Cookies[/bold yellow]")
    if cookie_analysis["detected_consent_tool"]:
        console.print(f"[bold]Erkanntes Consent-Tool:[/bold] {cookie_analysis['detected_consent_tool']}")

    if cookie_analysis["consent_found"]:
        console.print("[green]✅ Consent-Banner erkannt[/green]")
    else:
        console.print("[red]❌ Kein Consent-Banner erkannt[/red]")

    console.print(f"[bold]🍪 Cookies vor Zustimmung:[/bold] {len(cookie_analysis['cookies_before'])}")
    console.print(f"[bold]🍪 Cookies nach Zustimmung:[/bold] {len(cookie_analysis['cookies_after'])}")
    if not cookie_analysis['cookies_before'] and not cookie_analysis['cookies_after']:
        console.print("Keine Cookies erkannt.")

    if cookie_analysis.get('violations'):
        console.print(f"[red]🚨 Kritische Cookies vor Einwilligung geladen:[/red] {', '.join(cookie_analysis['violations'])}")
    else:
        console.print("[green]✅ Keine kritischen Cookies vor Zustimmung geladen[/green]")

    if not cookie_analysis.get('consent_mechanism_ok', False):
        console.print("[red]⚠️ Hinweis: Einige Cookies oder Dienste wurden vor der Zustimmung geladen.[/red]")
    console.print()

    # Abschnitt: E-Mail-Sicherheit innerhalb der main()-Funktion
    console.rule("[bold blue]6. E-Mail-Sicherheit[/bold blue]")

    # SPF Status
    spf_status = str(email_security["spf"].get("status", "")).lower() in ["valid", "pass", "true"]
    if spf_status:
        console.print("[green]✓[/green] SPF vorhanden")
    else:
        console.print("[red]✗[/red] [red]SPF fehlt oder falsch konfiguriert[/red]")

    # DKIM Status
    dkim_status = str(email_security["dkim"].get("status", "")).lower() in ["valid", "pass", "true"]
    dkim_selector = email_security["dkim"].get("selector", "nicht gefunden")
    if dkim_status:
        console.print(f"[green]✓[/green] DKIM vorhanden (Selector: {dkim_selector})")
    else:
        console.print(f"[red]✗[/red] [red]DKIM fehlt oder falsch konfiguriert[/red]")

    # DMARC Status
    dmarc_status = str(email_security["dmarc"].get("status", "")).lower() in ["valid", "pass", "true"]
    dmarc_policy = email_security["dmarc"].get("policy", "none")
    if dmarc_status:
        policy_text = f"(Policy: {dmarc_policy})"
        console.print(f"[green]✓[/green] DMARC vorhanden {policy_text}")
    else:
        console.print("[red]✗[/red] [red]DMARC fehlt oder falsch konfiguriert[/red]")

    console.print()

    # Gesamtbewertung
    score = int(email_security.get("score") or 0)
    rating = email_security.get("rating", "Keine Bewertung verfügbar")

    console.print(f"[yellow]🔐 Gesamtbewertung: {score}/10[/yellow] - {rating}")
    # scoring_reason anzeigen (wenn vorhanden)
    reasons = raw_email_security.get("scoring_reason", [])
    if reasons:
        console.print()
        console.print("[bold]Begründung der Bewertung:[/bold]")
        for r in reasons:
            console.print(f"- {r}")
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
    console.rule("[bold green]✅ Analyse abgeschlossen[/bold green]")

if __name__ == "__main__":
    main()