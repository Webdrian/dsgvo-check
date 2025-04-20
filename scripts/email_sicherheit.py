import dns.resolver
import time

def check_dns_record(name, record_type='TXT'):
    results = []
    resolvers = [
        dns.resolver.Resolver(),  # Standard-Resolver
        dns.resolver.Resolver(configure=False)  # Alternativ-Resolver mit Google & Cloudflare
    ]
    resolvers[0].lifetime = 2.0
    resolvers[1].nameservers = ['8.8.8.8', '1.1.1.1']
    resolvers[1].lifetime = 2.0

    for idx, resolver in enumerate(resolvers):
        try:
            answers = resolver.resolve(name, record_type)
            for rdata in answers:
                txt = rdata.to_text() if record_type == 'TXT' else str(rdata)
                if txt not in results:
                    results.append(txt)
            if results:
                break  # Wenn Ergebnisse gefunden, nicht weitermachen
        except Exception as e:
            # Debug-Ausgabe entfernt: print(f"[Resolver {idx}] Fehler bei DNS-Check ({name}, {record_type}): {e}")
            continue
    return results

def check_email_security(domain):
    result = {
        "score": 0,
        "scoring_reason": [],
        "spf": {"status": False, "raw": [], "policy": "none"},
        "dkim": {"status": False, "raw": [], "selector": None, "key_size": 0},
        "dmarc": {"status": False, "policy": "none", "raw": [], "pct": 0},
    }

    # SPF mit erweiterter Prüfung
    try:
        # Standard TXT-Records
        spf_records = check_dns_record(domain)
        
        # Alternativer SPF-Record-Pfad prüfen
        spf_alt_records = check_dns_record(f"_spf.{domain}")
        if spf_alt_records:
            spf_records.extend(spf_alt_records)
        
        # Type SPF prüfen (veraltet, aber manche nutzen es noch)
        try:
            spf_type_records = check_dns_record(domain, 'SPF')
            if spf_type_records:
                spf_records.extend(spf_type_records)
        except:
            pass
            
        result["spf"]["raw"] = spf_records
        
        # Erweiterte SPF-Erkennung mit mehr Flexibilität bei der Erkennung
        spf_found = False
        for record in spf_records:
            record_lower = record.lower()
            
            # Sehr flexible SPF-Erkennung
            if "v=spf1" in record_lower:
                result["spf"]["status"] = True
                result["score"] += 2  # SPF vorhanden
                result["scoring_reason"].append("SPF vorhanden (+2)")
                if "-all" in record_lower:
                    result["score"] += 2
                    result["spf"]["policy"] = "strict"
                    result["scoring_reason"].append("SPF-Policy ist -all (strict) (+2)")
                elif "~all" in record_lower:
                    result["score"] += 0.5
                    result["spf"]["policy"] = "softfail"
                    result["scoring_reason"].append("SPF-Policy ist ~all (softfail) (+0.5)")
                elif "+all" in record_lower:
                    result["score"] -= 1
                    result["spf"]["policy"] = "dangerous"
                    result["scoring_reason"].append("SPF-Policy ist +all (unsicher) (-1)")
                spf_found = True
                break
        
        if not spf_found:
            result["score"] -= 1
            result["scoring_reason"].append("Kein gültiger SPF-Record gefunden (-1)")
    except Exception as e:
        print(f"SPF check error: {str(e)}")
        result["spf"]["raw"].append(f"Error: {str(e)}")

    # DKIM prüfen (stark erweiterte Selector-Liste)
    dkim_selectors = [
        "default", "mail", "selector1", "email", "google", "dkim", "k1", "key1", "k", 
        "2023", "2024", "s1", "s2", "selector2", "mta", "domainkey", "20240101", "20230101",
        "key", "mx", "mailchimp", "mandrill", "smtp", "dk", "dkim1", "dkim2", "current",
        "mail1", "mail2", "mail3", "mailjet", "20", "19", "18", "global", "z", "x", 
        "ses", "sendinblue", "outlook", "m1", "m2", "c1", "c2", "pm", "sendgrid",
        "prod", "test", "demo", "primary", "secondary", "main", "alt", "new", "old"
    ]
    
    dkim_records = []
    found_selector = None
    
    # Versuche erweiterte DKIM-Prüfung
    for selector in dkim_selectors:
        try:
            records = check_dns_record(f"{selector}._domainkey.{domain}")
            if records:
                # Zusätzliche Validierung, dass es ein echter DKIM-Eintrag ist
                valid_dkim = False
                for record in records:
                    if "v=dkim1" in record.lower() or "k=rsa" in record.lower() or "p=" in record.lower():
                        valid_dkim = True
                        break
                
                if valid_dkim:
                    dkim_records = records
                    found_selector = selector
                    # Debug-Ausgabe entfernt: print(f"✅ DKIM selector found: {found_selector}")
                    break
        except Exception:
            continue
            
    if dkim_records:
        result["dkim"]["raw"] = dkim_records
        result["dkim"]["selector"] = found_selector
        
        # DKIM-Status auch ohne genaue Schlüsselgrößenprüfung akzeptieren
        has_valid_dkim = False
        
        for record in dkim_records:
            record_lower = record.lower()
            if "v=dkim1" in record_lower or "k=rsa" in record_lower:
                has_valid_dkim = True
                result["dkim"]["status"] = True
                result["score"] += 3  # Grundpunkte für DKIM
                result["scoring_reason"].append("DKIM vorhanden (+3)")
                
                # DKIM-Schlüsselgröße überprüfen (falls vorhanden)
                if "p=" in record:
                    try:
                        p_value = ""
                        if ";" in record.split("p=")[1]:
                            p_value = record.split("p=")[1].split(";")[0].strip('"\'')
                        else:
                            p_value = record.split("p=")[1].strip('"\'')
                            
                        # Behandle mehrere Teile (manchmal werden lange Keys in Teilen gespeichert)
                        p_value = p_value.replace(" ", "")
                        key_size = len(p_value) * 6 / 8  # Grobe Umrechnung von Base64 zu Bits
                        result["dkim"]["key_size"] = key_size
                        
                        if key_size >= 1024:  # Bonus für großen Schlüssel
                            result["score"] += 1
                            result["scoring_reason"].append("DKIM-Schlüsselstärke ≥ 1024 Bit (+1)")
                    except Exception as e:
                        print(f"DKIM key size error: {str(e)}")
                break
        
        # Wenn kein gültiger DKIM-Eintrag, aber Records gefunden wurden
        if not has_valid_dkim:
            result["dkim"]["status"] = False  # Als nicht vorhanden markieren
            result["score"] -= 1  # Abzug für ungültigen DKIM
            result["scoring_reason"].append("DKIM fehlt oder ungültig (-1)")
    else:
        result["dkim"]["raw"] = ["DKIM selectors not found"]
        result["score"] -= 1  # Abzug für fehlendes DKIM
        result["scoring_reason"].append("DKIM fehlt oder ungültig (-1)")
        # Debug-Ausgabe entfernt: print(f"❌ No DKIM selector found after testing {len(dkim_selectors)} selectors.")

    # DMARC prüfen - Deutlich höhere Bewertung für reject
    try:
        dmarc_records = check_dns_record(f"_dmarc.{domain}")
        result["dmarc"]["raw"] = dmarc_records
        
        if any("v=DMARC1" in r for r in dmarc_records):
            result["dmarc"]["status"] = True
            result["score"] += 1  # DMARC vorhanden
            result["scoring_reason"].append("DMARC vorhanden (+1)")

            # DMARC pct Wert extrahieren
            for r in dmarc_records:
                if "pct=" in r:
                    try:
                        pct = int(r.split("pct=")[1].split(";")[0].strip('"\''))
                        result["dmarc"]["pct"] = pct
                    except:
                        result["dmarc"]["pct"] = 100  # Default

            if any("p=reject" in r.lower() for r in dmarc_records):
                result["dmarc"]["policy"] = "reject"
                result["score"] += 5 if result["dmarc"]["pct"] == 100 else 4
                result["scoring_reason"].append("DMARC-Policy ist reject (+5)")
            elif any("p=quarantine" in r.lower() for r in dmarc_records):
                result["dmarc"]["policy"] = "quarantine"
                result["score"] += 2 if result["dmarc"]["pct"] == 100 else 1
                result["scoring_reason"].append("DMARC-Policy ist quarantine (+2)")
            elif any("p=none" in r.lower() for r in dmarc_records):
                result["dmarc"]["policy"] = "none"
                result["score"] -= 1
                result["scoring_reason"].append("DMARC-Policy ist none (-1)")
        else:
            result["score"] -= 1  # Kein DMARC
            result["scoring_reason"].append("DMARC fehlt oder ungültig (-1)")
    except Exception as e:
        print(f"DMARC check error: {str(e)}")
        result["dmarc"]["raw"].append(f"Error: {str(e)}")
        
    # Allgemeine Regelanpassungen
    
    # Bewertung bei SPF=ok, DMARC=reject/quarantine und fehlendem DKIM
    if (
        result["spf"]["status"]
        and result["spf"]["policy"] == "strict"
        and result["dmarc"]["status"]
        and result["dmarc"]["policy"] == "reject"
        and not result["dkim"]["status"]
    ):
        result["score"] = 7
        result["scoring_reason"].append("SPF + DMARC reject vorhanden, aber DKIM fehlt → Score auf 7 gesetzt")
    elif (
        result["spf"]["status"]
        and result["spf"]["policy"] == "strict"
        and result["dmarc"]["status"]
        and result["dmarc"]["policy"] == "quarantine"
        and not result["dkim"]["status"]
    ):
        result["score"] = 6
        result["scoring_reason"].append("SPF + DMARC quarantine vorhanden, aber DKIM fehlt → Score auf 6 gesetzt")
    
    # 3. Wenn SPF mit -all und DMARC=reject, mindestens 8 Punkte
    elif (result["spf"]["status"] and result["spf"]["policy"] == "strict" and 
          result["dmarc"]["status"] and result["dmarc"]["policy"] == "reject"):
        result["score"] = max(8, result["score"])
    
    # 4. Wenn kein SPF oder kein DMARC, max 2 Punkte
    elif not result["spf"]["status"] or not result["dmarc"]["status"]:
        result["score"] = min(2, result["score"])
    
    # Maximale Punktzahl begrenzen und runden
    result["score"] = max(0, min(10, round(result["score"])))
    
    # Bewertung bei SPF=ok, DMARC=none und fehlendem DKIM
    if (
        result["spf"]["status"]
        and result["spf"]["policy"] == "strict"
        and result["dmarc"]["status"]
        and result["dmarc"]["policy"] == "none"
        and not result["dkim"]["status"]
    ):
        result["score"] = 4
        result["scoring_reason"].append("SPF + DMARC none vorhanden, aber DKIM fehlt → Score auf 4 gesetzt")

    # Fallback-Regel wie bei EasyDMARC: SPF + DMARC (p=none) + kein DKIM → min 4 Punkte
    if (
        result["spf"]["status"]
        and result["dmarc"]["status"]
        and result["dmarc"]["policy"] == "none"
        and not result["dkim"]["status"]
        and result["score"] < 4
    ):
        result["score"] = 4
        result["scoring_reason"].append("Fallback: min. 4 Punkte bei SPF + DMARC(p=none) ohne DKIM")

    # Mindestscore wenn nur SPF vorhanden, kein DKIM/DMARC – analog EasyDMARC
    if (
        result["spf"]["status"]
        and not result["dkim"]["status"]
        and not result["dmarc"]["status"]
        and result["score"] < 3
    ):
        result["score"] = 3
        result["scoring_reason"].append("Fallback: min. 3 Punkte bei SPF-only ohne DKIM/DMARC")

    return result

def render_email_security(email_security):
    lines = []
    lines.append("[bold blue]6. E-Mail-Sicherheit[/bold blue]")
    lines.append("")

    score = int(email_security.get("score", 0))

    # SPF
    spf_status = email_security.get("spf", {}).get("status", False)
    spf_policy = email_security.get("spf", {}).get("policy", "none")
    
    if spf_status:
        if spf_policy == "strict":
            spf_line = "✅ SPF vorhanden (Policy: -all)"
        elif spf_policy == "softfail":
            spf_line = "⚠️ [orange3]SPF vorhanden (nur ~all – Softfail)[/orange3]"
        elif spf_policy == "dangerous":
            spf_line = "❌ [red]SPF vorhanden (Policy: +all – Unsicher!)[/red]"
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
            dkim_line = f"✅ DKIM vorhanden (Selector: {dkim_selector})"
        else:
            dkim_line = f"✅ DKIM vorhanden (Selector: {dkim_selector})"
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
    # scoring_reason anzeigen (wenn vorhanden)
    reasons = email_security.get("scoring_reason", [])
    if reasons:
        lines.append("")
        lines.append("[bold]Begründung der Bewertung:[/bold]")
        for r in reasons:
            lines.append(f"- {r}")
    lines.append("Diese Sicherheitsmechanismen schützen deine Domain vor Spoofing, Phishing und unautorisiertem E-Mail-Versand.")
    return lines