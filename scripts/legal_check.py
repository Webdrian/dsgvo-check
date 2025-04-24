from bs4 import BeautifulSoup

def check_legal_pages(html):
    soup = BeautifulSoup(html, "html.parser")
    links = soup.find_all("a", href=True)

    impressum_found = False
    datenschutz_found = False

    for link in links:
        href = link["href"].lower()
        text = link.get_text(strip=True).lower()

        if any(term in href or term in text for term in ["impressum", "legal", "contact", "kontakt"]):
            impressum_found = True
        if any(term in href or term in text for term in ["datenschutz", "privacy", "data-protection"]):
            datenschutz_found = True

    return {
        "impressum": impressum_found,
        "datenschutz": datenschutz_found
    }
