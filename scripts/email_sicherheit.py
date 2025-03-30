import dns.resolver

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

def render_email_security(email_security):
    lines = []
    lines.append("[bold blue]5. E-Mail-Sicherheit[/bold blue]")

    if any("v=" in r for r in email_security.get("SPF", [])):
        lines.append("✅ [green]SPF vorhanden[/green]")
    else:
        lines.append("❌ [red]SPF fehlt oder falsch konfiguriert[/red]")

    if any("v=" in r for r in email_security.get("DKIM", [])):
        lines.append("✅ [green]DKIM vorhanden[/green]")
    else:
        lines.append("❌ [red]DKIM fehlt oder falsch konfiguriert[/red]")

    if any("v=" in r for r in email_security.get("DMARC", [])):
        lines.append("✅ [green]DMARC vorhanden[/green]")
    else:
        lines.append("❌ [red]DMARC fehlt oder falsch konfiguriert[/red]")

    score = sum(1 for key in ["SPF", "DKIM", "DMARC"] if any("v=" in r for r in email_security.get(key, [])))

    rating_text = {
        3: "Sehr gut geschützt",
        2: "Gut, aber Verbesserung möglich",
        1: "Schwach abgesichert",
        0: "Keine Schutzmaßnahmen erkannt"
    }

    lines.append(f"🛡️ [yellow]Gesamtbewertung: {score}/3 – {rating_text[score]}[/yellow]")
    lines.append("Diese Sicherheitsmechanismen schützen deine Domain vor Spoofing, Phishing und unautorisiertem E-Mail-Versand.")
    return lines