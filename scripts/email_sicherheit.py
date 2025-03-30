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
    
    console.print("\n[bold]E-Mail-Sicherheitsstatus[/bold]")
    console.print(f"SPF: {', '.join(spf_records) if spf_records else 'Kein SPF-Datensatz gefunden'}")
    console.print(f"DMARC: {', '.join(dmarc_records) if dmarc_records else 'Kein DMARC-Datensatz gefunden'}")
    console.print(f"DKIM: {', '.join(dkim_records) if dkim_records else 'Kein DKIM-Datensatz gefunden'}")
    
    score = sum(1 for key in ["SPF", "DKIM", "DMARC"] if any("v=" in r for r in email_security.get(key, [])))
    
    if score == 3:
        status = "Sehr gut geschützt"
    elif score == 2:
        status = "Gut, aber Verbesserung möglich"
    else:
        status = "Schwach abgesichert"

    console.print(f"\n🔐 Gesamtbewertung: {score}/3 – {status}")
    return score, status