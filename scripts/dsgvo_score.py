def calculate_dsgvo_score(results):
    score = 10
    details = []

    # 1. SSL-Check
    if not results.get('ssl_valid', True):
        score -= 3
        details.append("❌ Kein gültiges SSL-Zertifikat (-3)")

    # 2. Cookie-Consent
    if not results.get('cookie_consent', False):
        score -= 3
        details.append("❌ Kein Cookie-Consent-Banner (-3)")

    # 3. Tracker vor Zustimmung
    if results.get('tracker_pre_consent', False):
        score -= 2
        details.append("❌ Tracker laden vor Zustimmung (-2)")

    # 4. Google Fonts extern
    if results.get('google_fonts_external', False):
        score -= 1
        details.append("❌ Google Fonts extern eingebunden (-1)")

    # 5. Externe Dienste ohne Zustimmung
    if results.get('external_services_without_consent', False):
        score -= 3
        details.append("❌ Externe Dienste ohne Zustimmung geladen (-3)")

    # 6. Impressum & Datenschutz
    if not results.get('legal_pages', True):
        score -= 2
        details.append("❌ Fehlendes Impressum oder Datenschutzerklärung (-2)")

    # Score nicht negativ werden lassen
    score = max(score, 0)

    # Bewertung
    if score >= 8:
        summary = "✅ DSGVO-konform"
    elif score >= 5:
        summary = "⚠️ Verbesserungsbedarf"
    else:
        summary = "❌ Kritisch – akuter Handlungsbedarf"

    return score, details, summary