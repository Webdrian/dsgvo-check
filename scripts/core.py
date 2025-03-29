import json
import os
from bs4 import BeautifulSoup

def detect_software(html):
    soup = BeautifulSoup(html, 'html.parser')
    scripts = soup.find_all("script", src=True)
    found = set()

    # Lade Tracker-Liste
    tracker_file = os.path.join(os.path.dirname(__file__), "trackers.json")
    try:
        with open(tracker_file, "r", encoding="utf-8") as f:
            tracker_list = json.load(f)
    except Exception as e:
        print(f"Fehler beim Laden von trackers.json: {e}")
        return []

    for script in scripts:
        src = script["src"]
        for tracker in tracker_list:
            for pattern in tracker["match"]:
                if pattern.lower() in src.lower():
                    found.add(tracker["name"])

    return sorted(found)
