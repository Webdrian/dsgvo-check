import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.align import Align
from rich import box

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
    dkim_selectors = ["default", "mail", "selector1", "email", "google"]
    dkim_records = []
    for selector in dkim_selectors:
        records = check_dns_record(f"{selector}._domainkey.{domain}")
        if any("v=DKIM1" in r for r in records):
            dkim_records = records
            break
    if dkim_records:
        result["dkim"]["raw"] = dkim_records
        if any("v=DKIM1" in r and "p=" in r for r in dkim_records):
            result["dkim"]["status"] = True
            result["score"] += 3
    else:
        result["dkim"]["raw"] = ["DKIM selectors not found"]

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
    else:
        result["score"] -= 1  # slight penalty for missing strong policy

    return result

def visualize_email_security(email_security):
    """
    Erstellt eine visuelle Darstellung der E-Mail-Sicherheitsbewertung.
    
    Args:
        email_security: Ergebnis der check_email_security Funktion
    """
    console = Console()
    
    # Extrahiere Werte
    score = int(email_security.get("score", 0))
    spf_status = email_security.get("spf", {}).get("status", False)
    dkim_status = email_security.get("dkim", {}).get("status", False)
    dmarc_status = email_security.get("dmarc", {}).get("status", False)
    dmarc_policy = email_security.get("dmarc", {}).get("policy", "none")
    
    # Bestimme Risiko-Level
    if score >= 8:
        risk_level = "Low"
        risk_color = "green"
    elif score >= 5:
        risk_level = "Medium"
        risk_color = "yellow"
    else:
        risk_level = "High"
        risk_color = "red"
    
    # Header mit Risikobewertung
    console.print()
    console.print(Text("Scan another domain", style="blue"), "←")
    console.print()
    
    risk_title = f"Risk Assessment Level: {risk_level}"
    if risk_level == "High":
        risk_title = f"Risk Assessment Level: [bold red]{risk_level}[/bold red]"
        risk_description = "A domain with a high security risk level indicates critical vulnerabilities in SPF, DKIM, and DMARC, posing a severe threat of email impersonation and phishing attacks, necessitating urgent protocol enhancements."
    elif risk_level == "Medium":
        risk_title = f"Risk Assessment Level: [bold yellow]{risk_level}[/bold yellow]"
        risk_description = "This domain has some email security measures in place but may still be vulnerable to certain types of spoofing attacks. Consider strengthening the configuration."
    else:
        risk_title = f"Risk Assessment Level: [bold green]{risk_level}[/bold green]"
        risk_description = "This domain has strong email security measures in place, providing good protection against email spoofing and phishing attacks."
    
    console.print(Panel(
        f"{risk_title}\n\n{risk_description}",
        border_style=risk_color,
        box=box.ROUNDED
    ))
    
    # Overall result line
    console.print("Overall result", end="")
    console.print("   [?]", style="dim")
    console.print("                                                  DMARC Policy:", end="")
    policy_style = "white on gray" if dmarc_policy == "none" or not dmarc_status else "white"
    console.print(f"  [{policy_style}] {dmarc_policy.title() if dmarc_status else 'Missing'} [/{policy_style}]")
    console.print()
    
    # Layout für Score und Protokolle
    layout = Layout()
    layout.split_row(
        Layout(name="score", size=20),
        Layout(name="protocols")
    )
    
    # Score section
    score_circle = f"""
          Score
          
          [bold]{score}[/bold]
         of 10
    """
    layout["score"].update(Align.center(Text(score_circle, justify="center"), vertical="middle"))
    
    # Protokolle section
    layout["protocols"].split_row(
        Layout(name="dmarc"),
        Layout(name="spf"),
        Layout(name="dkim")
    )
    
    # Icons for status
    dmarc_icon = "🔴" if not dmarc_status else "🟢"
    spf_icon = "🔴" if not spf_status else "🟢"
    dkim_icon = "🔴" if not dkim_status else "🟢"
    
    dmarc_text = f"""
    {dmarc_icon} [bold]DMARC[/bold]
    Domain-based Message
    Authentication,
    Reporting and
    Conformance
    """
    
    spf_text = f"""
    {spf_icon} [bold]SPF[/bold]
    Sender Policy
    Framework
    """
    
    dkim_text = f"""
    {dkim_icon} [bold]DKIM[/bold]
    DomainKeys
    Identified Mail
    """
    
    layout["dmarc"].update(Align.center(Text(dmarc_text)))
    layout["spf"].update(Align.center(Text(spf_text)))
    layout["dkim"].update(Align.center(Text(dkim_text)))
    
    console.print(layout)
    console.print()
    
    # Buttons
    console.print(Align.center(
        Panel(" See Details ", width=20, border_style="blue", box=box.ROUNDED) + 
        "   " + 
        Panel(" Start DMARC Journey ", width=30, border_style="blue", box=box.ROUNDED, style="bold white on blue")
    ))
    console.print()

def render_email_security(email_security):
    lines = []
    lines.append("[bold blue]6. E-Mail-Sicherheit[/bold blue]")
    lines.append("")

    score = int(email_security.get("score", 0))

    # SPF
    spf_records = email_security.get("spf", {}).get("raw", [])
    if any("v=spf1" in r for r in spf_records):
        if any("-all" in r for r in spf_records):
            spf_line = "✅ SPF vorhanden (Policy: -all)"
        elif any("~all" in r for r in spf_records):
            spf_line = "⚠️ [orange3]SPF vorhanden (nur ~all – Softfail)[/orange3]"
        else:
            spf_line = "⚠️ [orange3]SPF vorhanden, aber keine gültige Policy (~all oder -all)[/orange3]"
    else:
        spf_line = "❌ [red]SPF fehlt oder falsch konfiguriert[/red]"
    lines.append(spf_line)

    # DKIM
    dkim_records = email_security.get("dkim", {}).get("raw", [])
    if "DKIM selectors not found" in dkim_records:
        dkim_line = "❌ [red]DKIM fehlt – keine Selector gefunden[/red]"
    elif any("v=DKIM1" in r and "p=" in r for r in dkim_records):
        dkim_line = "✅ DKIM vorhanden"
    else:
        dkim_line = "❌ [red]DKIM fehlt oder falsch konfiguriert[/red]"
    lines.append(dkim_line)

    # DMARC
    dmarc_records = email_security.get("dmarc", {}).get("raw", [])
    if any("v=DMARC1" in r for r in dmarc_records):
        if any("p=reject" in r for r in dmarc_records):
            dmarc_line = "✅ DMARC vorhanden (Policy: reject)"
        elif any("p=quarantine" in r for r in dmarc_records):
            dmarc_line = "⚠️ [orange3]DMARC vorhanden (Policy: quarantine – Softfail)[/orange3]"
        elif any("p=none" in r for r in dmarc_records):
            dmarc_line = "⚠️ [orange3]DMARC vorhanden (Policy: none – Keine Schutzwirkung)[/orange3]"
        else:
            dmarc_line = "⚠️ [orange3]DMARC vorhanden, aber keine erkannte Policy[/orange3]"
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