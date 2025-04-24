import json

def evaluate_risks(url, network_requests, pre_consent_requests, riskmap_path="scripts/json/riskmap.json"):
    external_services = []
    matched_risks = []
    pre_consent_violations = []
    other_risks = []

    try:
        with open(riskmap_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            riskmap = data["tools"]
    except Exception as e:
        print(f"Fehler beim Laden von riskmap.json: {e}")
        return [], [], []

    for entry in riskmap:
        matched = any(pattern.lower() in r.lower() for pattern in entry["match"] for r in network_requests)
        pre_consent = any(pattern.lower() in r.lower() for pattern in entry["match"] for r in pre_consent_requests)

        if matched and not (pre_consent and entry.get("consent_required", False)):
            matched_risks.append({
                "name": entry["name"],
                "category": entry["category"],
                "risk": entry["risk"],
                "note": entry.get("note", "Keine besonderen Hinweise."),
                "emoji": "⚠️"
            })

        if pre_consent and entry.get("consent_required", False):
            if entry["category"] == "Externe Medien":
                external_services.append({
                    "name": entry["name"],
                    "category": entry["category"],
                    "risk": entry["risk"],
                    "note": entry.get("note", "Keine besonderen Hinweise."),
                    "emoji": "🎥"
                })
            else:
                pre_consent_violations.append({
                    "name": entry["name"],
                    "category": entry["category"],
                    "risk": entry["risk"],
                    "note": entry.get("note", "Keine besonderen Hinweise."),
                    "emoji": "🚨"
                })

    # Beispiel für weiteren allgemeinen Risikoeintrag
    if "google-analytics.com" in url.lower():
        other_risks.append("Google Analytics URL direkt aufgerufen")

    # Google Fonts Prüfung
    google_fonts_detected = any("fonts.googleapis.com" in r or "fonts.gstatic.com" in r for r in network_requests)

    if google_fonts_detected:
        matched_risks.append({
            "name": "Google Fonts",
            "category": "Externe Schriften",
            "risk": "hoch",
            "note": "Google Fonts extern eingebunden – Empfehlung: Lokal hosten.",
            "emoji": "⚠️"
        })
    else:
        pass  # Keine Aktion notwendig, da DSGVO-konform

    return {
        "critical_violations": pre_consent_violations,
        "external_services": external_services,
        "general_risks": matched_risks,
        "other_notes": other_risks
    }