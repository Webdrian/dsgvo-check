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

    # Erweiterter Score: 0–10
    score = 0

    # SPF Check
    spf_records = email_security.get("SPF", [])
    if any("v=spf1" in r for r in spf_records):
        score += 3
        if any("+all" not in r and "~all" in r for r in spf_records):
            score += 1
    else:
        lines.append("❌ [red]SPF fehlt oder falsch konfiguriert[/red]")

    # DKIM Check
    dkim_records = email_security.get("DKIM", [])
    if any("v=DKIM1" in r and "p=" in r for r in dkim_records):
        score += 3
    else:
        lines.append("❌ [red]DKIM fehlt oder falsch konfiguriert[/red]")

    # DMARC Check
    dmarc_records = email_security.get("DMARC", [])
    if any("v=DMARC1" in r for r in dmarc_records):
        score += 3
        if any("p=reject" in r or "p=quarantine" in r for r in dmarc_records):
            score += 1
    else:
        lines.append("❌ [red]DMARC fehlt oder falsch konfiguriert[/red]")

    if score >= 9:
        level = "Sehr gut"
        icon = "🟢"
    elif score >= 6:
        level = "Gut"
        icon = "🟡"
    elif score >= 3:
        level = "Schwach"
        icon = "🟠"
    else:
        level = "Kritisch"
        icon = "🔴"

    lines.append(f"{icon} [bold]Gesamtbewertung: {score}/10 – {level}[/bold]")
    lines.append("Diese Sicherheitsmechanismen schützen deine Domain vor Spoofing, Phishing und unautorisiertem E-Mail-Versand.")
    return lines