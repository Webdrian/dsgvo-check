from bs4 import BeautifulSoup

def check_legal_pages(html):
    soup = BeautifulSoup(html, "html.parser")
    links = soup.find_all("a", href=True)

    impressum_found = False
    datenschutz_found = False
    impressum_link = ""
    datenschutz_link = ""

    for link in links:
        href = link["href"].lower()
        text = link.get_text(strip=True).lower()

        if not impressum_found and any(term in href or term in text for term in ["impressum", "legal", "contact", "kontakt"]):
            impressum_found = True
            impressum_link = href
        if not datenschutz_found and any(term in href or term in text for term in ["datenschutz", "privacy", "data-protection"]):
            datenschutz_found = True
            datenschutz_link = href

    return {
        "impressum": impressum_found,
        "datenschutz": datenschutz_found,
        "impressum_link": impressum_link,
        "datenschutz_link": datenschutz_link
    }
