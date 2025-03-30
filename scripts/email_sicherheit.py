import dns.resolver

def check_dns_record(name):
    try:
        answers = dns.resolver.resolve(name, 'TXT')
        return [r.to_text() for r in answers]
    except:
        return []

def check_email_security(domain):
    result = {
        "score": 0,
        "spf": {"status": False, "raw": []},
        "dkim": {"status": False, "raw": []},
        "dmarc": {"status": False, "policy": "none", "raw": []},
    }

    # SPF prüfen
    spf_records = check_dns_record(domain)
    result["spf"]["raw"] = spf_records
    if any("v=spf1" in r for r in spf_records):
        result["spf"]["status"] = True
        result["score"] += 3
        if any("-all" in r for r in spf_records):
            result["score"] += 1
        elif any("~all" in r for r in spf_records):
            result["score"] += 0.5

    # DKIM prüfen (Selector "default")
    dkim_records = check_dns_record(f"default._domainkey.{domain}")
    result["dkim"]["raw"] = dkim_records
    if any("v=DKIM1" in r for r in dkim_records):
        if any("p=" in r for r in dkim_records):
            result["dkim"]["status"] = True
            result["score"] += 3

    # DMARC prüfen
    dmarc_records = check_dns_record(f"_dmarc.{domain}")
    result["dmarc"]["raw"] = dmarc_records
    if any("v=DMARC1" in r for r in dmarc_records):
        result["dmarc"]["status"] = True
        result["score"] += 3
        if any("p=reject" in r for r in dmarc_records):
            result["score"] += 1
            result["dmarc"]["policy"] = "reject"
        elif any("p=quarantine" in r for r in dmarc_records):
            result["score"] += 0.5
            result["dmarc"]["policy"] = "quarantine"
        elif any("p=none" in r for r in dmarc_records):
            result["dmarc"]["policy"] = "none"

    return result

def render_email_security(email_security):
    lines = []
    lines.append("[bold blue]6. E-Mail-Sicherheit[/bold blue]")
    lines.append("")

    score = int(email_security.get("score", 0))

    # SPF
    spf_records = email_security.get("spf", {}).get("raw", [])
    if any("v=spf1" in r for r in spf_records):
        spf_line = "✅ SPF vorhanden"
        if any("-all" in r for r in spf_records):
            pass
        elif any("~all" in r for r in spf_records):
            spf_line += " (nur ~all)"
        else:
            spf_line = "⚠️ [orange3]SPF vorhanden, aber keine gültige Policy (~all oder -all)[/orange3]"
    else:
        spf_line = "❌ [red]SPF fehlt oder falsch konfiguriert[/red]"
    lines.append(spf_line)

    # DKIM
    dkim_records = email_security.get("dkim", {}).get("raw", [])
    if any("v=DKIM1" in r for r in dkim_records):
        dkim_line = "✅ DKIM vorhanden"
        if any("p=" in r for r in dkim_records):
            pass
        else:
            dkim_line = "⚠️ [orange3]DKIM vorhanden, aber kein 'p=' Schlüssel gefunden[/orange3]"
    else:
        dkim_line = "❌ [red]DKIM fehlt oder falsch konfiguriert[/red]"
    lines.append(dkim_line)

    # DMARC
    dmarc_records = email_security.get("dmarc", {}).get("raw", [])
    if any("v=DMARC1" in r for r in dmarc_records):
        dmarc_line = "✅ DMARC vorhanden"
        if any("p=reject" in r for r in dmarc_records):
            pass
        elif any("p=quarantine" in r for r in dmarc_records):
            pass
        else:
            dmarc_line = "⚠️ [orange3]DMARC vorhanden, aber keine starke Policy (reject/quarantine)[/orange3]"
    else:
        dmarc_line = "❌ [red]DMARC fehlt oder falsch konfiguriert[/red]"
    lines.append(dmarc_line)

    lines.append("")

    # Bewertung
    if score >= 9:
        level = "[green]Sehr gut geschützt[/green]"
    elif score >= 6:
        level = "[yellow]Gut, aber Verbesserung möglich[/yellow]"
    elif score >= 3:
        level = "[orange3]Verbesserung dringend nötig[/orange3]"
    else:
        level = "[red]Kritisch – Sofort handeln[/red]"

    lines.append(f"🔐 [yellow]Gesamtbewertung: {score}/10 – {level}[/yellow]")
    lines.append("Diese Sicherheitsmechanismen schützen deine Domain vor Spoofing, Phishing und unautorisiertem E-Mail-Versand.")
    return lines