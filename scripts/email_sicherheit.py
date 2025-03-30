import dns.resolver
from rich.console import Console

console = Console()

def check_dns_record(name):
    try:
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

def evaluate_email_security(email_security):
    spf_records = email_security.get("SPF", [])
    dmarc_records = email_security.get("DMARC", [])
    dkim_records = email_security.get("DKIM", [])

    console.print()
    console.rule("[bold blue]5. E-Mail-Sicherheit[/bold blue]")

    if any("v=" in r for r in spf_records):
        console.print("✅ [green]SPF vorhanden[/green]")
    else:
        console.print("❌ [red]SPF fehlt oder falsch konfiguriert[/red]")

    if any("v=" in r for r in dkim_records):
        console.print("✅ [green]DKIM vorhanden[/green]")
    else:
        console.print("❌ [red]DKIM fehlt oder falsch konfiguriert[/red]")

    if any("v=" in r for r in dmarc_records):
        console.print("✅ [green]DMARC vorhanden[/green]")
    else:
        console.print("❌ [red]DMARC fehlt oder falsch konfiguriert[/red]")

    score = sum(1 for key in ["SPF", "DKIM", "DMARC"] if any("v=" in r for r in email_security.get(key, [])))

    rating_text = {
        3: "Sehr gut geschützt",
        2: "Gut, aber Verbesserung möglich",
        1: "Schwach abgesichert",
        0: "Keine Schutzmaßnahmen erkannt"
    }

    console.print()
    console.print(f"🛡️ [yellow]Gesamtbewertung: {score}/3 – {rating_text[score]}[/yellow]")
    console.print("Diese Sicherheitsmechanismen schützen deine Domain vor Spoofing, Phishing und unautorisiertem E-Mail-Versand.")
    return score, rating_text[score]