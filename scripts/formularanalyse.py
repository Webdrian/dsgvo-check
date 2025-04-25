from bs4 import BeautifulSoup
from urllib.parse import urlparse

def analyze_forms(html, url):
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')

    results = []
    for form in forms:
        form_info = {}
        action = form.get('action')
        form_info['action'] = action if action else '⚠️ Action-URL fehlt – mögliche Versandprobleme'

        # Prüfen, ob Action-URL SSL verwendet
        if action and action.startswith('http://'):
            form_info['ssl'] = '❌ Keine SSL-Verschlüsselung'
        else:
            form_info['ssl'] = '✅ SSL vorhanden oder relative URL'

        # Prüfen auf personenbezogene Felder
        sensitive_fields = []
        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type', 'text').lower()
            name_attr = input_tag.get('name', '').lower()
            if any(keyword in name_attr for keyword in ['name', 'email', 'phone', 'tel']):
                sensitive_fields.append(name_attr or input_type)

        form_info['personenbezogene_felder'] = sensitive_fields if sensitive_fields else '✅ Keine kritischen Felder erkannt'

        # Prüfen auf Checkbox (z.B. für Datenschutz-Zustimmung)
        checkbox = form.find('input', {'type': 'checkbox'})
        form_info['checkbox_vorhanden'] = '✅ Checkbox vorhanden' if checkbox else '⚠️ Keine Checkbox für Zustimmung gefunden'

        results.append(form_info)

    print(f"{len(forms)} Formulare geprüft – Analyse abgeschlossen ✅")
    return results