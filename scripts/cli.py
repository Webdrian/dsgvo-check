from fetching import fetch_html_and_requests
from core import extract_meta
from cms import detect_cms, detect_wordpress_theme, detect_plugins
from ssl_info import get_ssl_info
from cookies import analyze_cookies
from email_check import check_email_security
from dsgvo import evaluate_risks

from urllib.parse import urlparse
from rich.console import Console

def main():
    console = Console()
    url = input("Gib eine URL ein (mit https://): ").strip()
    domain = urlparse(url).hostname

    html, network_requests, pre_consent_requests = fetch_html_and_requests(url)
    title, desc = extract_meta(html)
    cms_list, builder_list = detect_cms(html)
    theme = detect_wordpress_theme(html)
    plugins = detect_plugins(html)
    ssl_info = get_ssl_info(domain)
    cookies_before, cookies_after, suspicious = analyze_cookies(url)
    email_security = check_email_security(domain)
    risks, violations, indicators = evaluate_risks(url, network_requests, pre_consent_requests)

    # Optional: console.print(...) für die Ausgabe (noch nicht eingebaut)

if __name__ == "__main__":
    main()