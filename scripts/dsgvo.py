import json

def evaluate_risks(url, network_requests, pre_consent_requests, riskmap_path="scripts/json/riskmap.json"):
    matched_risks = []
    pre_consent_violations = []
    other_risks = []

    try:
        with open(riskmap_path, "r", encoding="utf-8") as f:
            riskmap = json.load(f)
    except Exception as e:
        print(f"Fehler beim Laden von riskmap.json: {e}")
        return [], [], []

    for entry in riskmap:
        for pattern in entry["match"]:
            if any(pattern.lower() in r.lower() for r in network_requests):
                matched_risks.append({
                    "name": entry["name"],
                    "category": entry["category"],
                    "risk": entry["risk"],
                    "note": entry.get("note", "")
                })
                break

    for entry in riskmap:
        for pattern in entry["match"]:
            if any(pattern.lower() in r.lower() for r in pre_consent_requests):
                pre_consent_violations.append({
                    "name": entry["name"],
                    "category": entry["category"],
                    "risk": entry["risk"],
                    "note": entry.get("note", "")
                })
                break

    # Beispiel für weiteren allgemeinen Risikoeintrag
    if "google-analytics.com" in url.lower():
        other_risks.append("Google Analytics URL direkt aufgerufen")

    return matched_risks, pre_consent_violations, other_risks