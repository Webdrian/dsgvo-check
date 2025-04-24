from bs4 import BeautifulSoup

IMPRESSUM_KEYWORDS = ["impressum", "legal", "contact", "kontakt"]
DATENSCHUTZ_KEYWORDS = ["datenschutz", "privacy", "data-protection"]

def check_legal_pages(html):
    """
    Prüft, ob im HTML ein Link zu Impressum und Datenschutzerklärung vorhanden ist.
    Gibt ein Dictionary mit Status und gefundenen Links zurück.
    """
    soup = BeautifulSoup(html, "html.parser")
    links = soup.find_all("a", href=True)

    impressum_found = False
    datenschutz_found = False
    impressum_link = ""
    datenschutz_link = ""

    for link in links:
        href = link["href"].lower()
        text = link.get_text(strip=True).lower()

        if not impressum_found and any(term in href or term in text for term in IMPRESSUM_KEYWORDS):
            impressum_found = True
            impressum_link = href
        if not datenschutz_found and any(term in href or term in text for term in DATENSCHUTZ_KEYWORDS):
            datenschutz_found = True
            datenschutz_link = href

        if impressum_found and datenschutz_found:
            break

    return {
        "impressum": impressum_found,
        "datenschutz": datenschutz_found,
        "impressum_link": impressum_link,
        "datenschutz_link": datenschutz_link
    }
