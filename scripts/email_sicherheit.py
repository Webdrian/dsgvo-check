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
    score = 0
    for key in ["SPF", "DKIM", "DMARC"]:
        records = email_security.get(key, [])
        if any("v=" in r for r in records):
            score += 1

    if score == 3:
        status = "🟢 Sehr gut geschützt"
    elif score == 2:
        status = "🟡 Teilweise geschützt"
    else:
        status = "🔴 Schwach oder ohne Schutz"

    console.print(f"\n🔐 Gesamtbewertung: {score}/3 – {status}")
    return score, status