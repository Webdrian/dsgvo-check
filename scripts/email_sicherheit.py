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
        "spf": {"status": False, "raw": [], "policy": "none"},
        "dkim": {"status": False, "raw": [], "selector": None, "key_size": 0},
        "dmarc": {"status": False, "policy": "none", "raw": [], "pct": 0},
    }

    # SPF prüfen
    spf_records = check_dns_record(domain)
    result["spf"]["raw"] = spf_records
    if any("v=spf1" in r for r in spf_records):
        result["spf"]["status"] = True
        result["score"] += 1  # Reduzierte Basispunkte für SPF
        
        if any("-all" in r for r in spf_records):
            result["score"] += 2  # Höhere Punkte für strikte Policy
            result["spf"]["policy"] = "strict"
        elif any("~all" in r for r in spf_records):
            result["score"] += 0.5  # Geringe Punkte für softfail
            result["spf"]["policy"] = "softfail"
        else:
            result["spf"]["policy"] = "weak"
    else:
        result["score"] -= 2  # Höherer Abzug für fehlendes SPF

    # DKIM prüfen (erweiterte Selector-Liste)
    dkim_selectors = ["default", "mail", "selector1", "email", "google", "dkim", "k1", "key1", 
                      "2023", "2024", "s1", "s2", "selector2", "mta", "domainkey", 
                      "key", "mx", "mailchimp", "mandrill", "smtp", "dk"]
    dkim_records = []
    found_selector = None
    
    for selector in dkim_selectors:
        records = check_dns_record(f"{selector}._domainkey.{domain}")
        if any("v=DKIM1" in r for r in records):
            dkim_records = records
            found_selector = selector
            break
            
    if dkim_records:
        result["dkim"]["raw"] = dkim_records
        result["dkim"]["selector"] = found_selector
        
        # DKIM-Schlüsselgröße überprüfen (falls vorhanden)
        key_size = 0
        for record in dkim_records:
            if "v=DKIM1" in record and "p=" in record:
                # Vereinfachte Schätzung der Schlüsselgröße basierend auf Länge
                p_value = record.split('p=')[1].split(';')[0].strip('"\'')
                key_size = len(p_value) * 6 / 8  # Grobe Umrechnung von Base64 zu Bits
                result["dkim"]["key_size"] = key_size
                
                if key_size >= 2048:
                    result["score"] += 3  # Volle Punktzahl für starken Schlüssel
                    result["dkim"]["status"] = True
                elif key_size >= 1024:
                    result["score"] += 2  # Reduzierte Punktzahl für mittleren Schlüssel
                    result["dkim"]["status"] = True
                else:
                    result["score"] += 0.5  # Sehr geringe Punktzahl für schwachen Schlüssel
                    result["dkim"]["status"] = True
    else:
        result["dkim"]["raw"] = ["DKIM selectors not found"]
        result["score"] -= 2  # Höherer Abzug für fehlendes DKIM

    # DMARC prüfen - Strenger bewerten
    dmarc_records = check_dns_record(f"_dmarc.{domain}")
    result["dmarc"]["raw"] = dmarc_records
    if any("v=DMARC1" in r for r in dmarc_records):
        result["dmarc"]["status"] = True
        result["score"] += 1  # Basis-Punkte für DMARC-Vorhandensein
        
        # DMARC pct Wert extrahieren
        for r in dmarc_records:
            if "pct=" in r:
                try:
                    pct = int(r.split("pct=")[1].split(";")[0].strip('"\''))
                    result["dmarc"]["pct"] = pct
                except:
                    result["dmarc"]["pct"] = 100  # Standard, wenn nicht angegeben
        
        if any("p=reject" in r for r in dmarc_records):
            if result["dmarc"]["pct"] == 100:
                result["score"] += 3  # Volle Punktzahl für reject bei 100%
            else:
                result["score"] += 2  # Reduzierte Punktzahl für teilweises reject
            result["dmarc"]["policy"] = "reject"
        elif any("p=quarantine" in r for r in dmarc_records):
            if result["dmarc"]["pct"] == 100:
                result["score"] += 1.5  # Mittlere Punktzahl für quarantine bei 100%
            else:
                result["score"] += 1  # Reduzierte Punktzahl für teilweises quarantine
            result["dmarc"]["policy"] = "quarantine"
        elif any("p=none" in r for r in dmarc_records):
            result["score"] -= 1  # Abzug für "none" Policy - nur Monitoring ohne Schutz
            result["dmarc"]["policy"] = "none"
    else:
        result["score"] -= 3  # Stärkerer Abzug für fehlendes DMARC
    
    # Maximale Punktzahl begrenzen
    result["score"] = max(0, min(10, result["score"]))
    
    return result

def render_email_security(email_security):
    lines = []
    lines.append("[bold blue]6. E-Mail-Sicherheit[/bold blue]")
    lines.append("")

    score = int(email_security.get("score", 0))

    # SPF
    spf_records = email_security.get("spf", {}).get("raw", [])
    spf_policy = email_security.get("spf", {}).get("policy", "none")
    
    if any("v=spf1" in r for r in spf_records):
        if spf_policy == "strict":
            spf_line = "✅ SPF vorhanden (Policy: -all)"
        elif spf_policy == "softfail":
            spf_line = "⚠️ [orange3]SPF vorhanden (nur ~all – Softfail)[/orange3]"
        else:
            spf_line = "⚠️ [orange3]SPF vorhanden, aber keine gültige Policy (~all oder -all)[/orange3]"
    else:
        spf_line = "❌ [red]SPF fehlt oder falsch konfiguriert[/red]"
    lines.append(spf_line)

    # DKIM
    dkim_status = email_security.get("dkim", {}).get("status", False)
    dkim_selector = email_security.get("dkim", {}).get("selector", "nicht gefunden")
    dkim_key_size = email_security.get("dkim", {}).get("key_size", 0)
    
    if dkim_status:
        if dkim_key_size >= 2048:
            dkim_line = f"✅ DKIM vorhanden (Selector: {dkim_selector}, Schlüsselstärke: stark)"
        elif dkim_key_size >= 1024:
            dkim_line = f"⚠️ [yellow]DKIM vorhanden (Selector: {dkim_selector}, Schlüsselstärke: mittel)[/yellow]"
        else:
            dkim_line = f"⚠️ [orange3]DKIM vorhanden (Selector: {dkim_selector}, Schlüsselstärke: schwach)[/orange3]"
    else:
        dkim_line = "❌ [red]DKIM fehlt oder falsch konfiguriert[/red]"
    lines.append(dkim_line)

    # DMARC
    dmarc_status = email_security.get("dmarc", {}).get("status", False)
    dmarc_policy = email_security.get("dmarc", {}).get("policy", "none")
    dmarc_pct = email_security.get("dmarc", {}).get("pct", 0)
    
    if dmarc_status:
        pct_info = f", {dmarc_pct}%" if dmarc_pct < 100 else ""
        
        if dmarc_policy == "reject":
            dmarc_line = f"✅ DMARC vorhanden (Policy: reject{pct_info})"
        elif dmarc_policy == "quarantine":
            dmarc_line = f"⚠️ [yellow]DMARC vorhanden (Policy: quarantine{pct_info} – Teilschutz)[/yellow]"
        elif dmarc_policy == "none":
            dmarc_line = f"⚠️ [orange3]DMARC vorhanden (Policy: none{pct_info} – Keine Schutzwirkung)[/orange3]"
        else:
            dmarc_line = "⚠️ [orange3]DMARC vorhanden, aber keine erkannte Policy[/orange3]"
    else:
        dmarc_line = "❌ [red]DMARC fehlt oder falsch konfiguriert[/red]"
    lines.append(dmarc_line)

    lines.append("")

    # Risikobewertung hinzufügen
    risk_level = ""
    risk_description = ""
    
    if score >= 8:
        risk_level = "Low"
        level = "[green]Sehr gut geschützt[/green]"
        risk_description = "Domains with a low security risk level have minimal or no significant authentication issues, ensuring robust protection against email-based threats."
    elif score >= 5:
        risk_level = "Medium"
        level = "[yellow]Gut, aber Verbesserung möglich[/yellow]"
        risk_description = "This domain has some email security measures in place but may still be vulnerable to certain types of spoofing attacks."
    else:
        risk_level = "High"
        level = "[red]Kritisch – Sofort handeln[/red]"
        risk_description = "A domain with a high security risk level indicates critical vulnerabilities in SPF, DKIM, and DMARC, posing a severe threat of email impersonation."

    lines.append(f"Risk Assessment Level: [bold]{risk_level}[/bold]")
    lines.append(risk_description)
    lines.append("")
    lines.append(f"🔐 [yellow]Gesamtbewertung: {score}/10 – {level}[/yellow]")
    lines.append("Diese Sicherheitsmechanismen schützen deine Domain vor Spoofing, Phishing und unautorisiertem E-Mail-Versand.")
    return lines