def export_to_markdown(data, filename):
    with open(filename, 'w') as file:
        file.write(f"# DSGVO-Check Bericht\n\n")
        file.write(f"## 1. Allgemeine Informationen\n")
        file.write(f"- **URL:** {data.get('url', 'N/A')}\n")
        file.write(f"- **Titel:** {data.get('title', 'N/A')}\n")
        file.write(f"- **Beschreibung:** {data.get('description', 'N/A')}\n\n")

        file.write(f"## 2. Software\n")
        file.write(f"- **CMS:** {data.get('cms', 'N/A')}\n")
        file.write(f"- **Pagebuilder:** {data.get('pagebuilder', 'N/A')}\n")
        file.write(f"- **Plugins:** {', '.join(data.get('plugins', []))}\n\n")

        file.write(f"## 3. Tracker\n")
        trackers = data.get('trackers', [])
        if trackers:
            for tracker in trackers:
                file.write(f"- ⚠️ {tracker}\n")
        else:
            file.write("- ✅ Keine Tracker erkannt\n")
        file.write("\n")

        file.write(f"## 4. DSGVO-Check\n")
        for check in data.get('dsgvo_check', []):
            file.write(f"- {check}\n")
        file.write("\n")

        file.write(f"## 5. Cookies\n")
        file.write(f"- Consent-Tool: {data.get('consent_tool', 'N/A')}\n")
        file.write(f"- Cookies vor Zustimmung: {data.get('cookies_before', 0)}\n")
        file.write(f"- Cookies nach Zustimmung: {data.get('cookies_after', 0)}\n\n")

        file.write(f"## 6. E-Mail-Sicherheit\n")
        for item in data.get('email_security', []):
            file.write(f"- {item}\n")
        file.write("\n")

        file.write(f"## 7. SSL-Zertifikat\n")
        for item in data.get('ssl_info', []):
            file.write(f"- {item}\n")
        file.write("\n")

        file.write(f"## 8. Rechtliche Seiten\n")
        for item in data.get('legal_pages', []):
            file.write(f"- {item}\n")
        file.write("\n")

        file.write(f"## 9. Formularanalyse\n")
        for item in data.get('forms', []):
            file.write(f"- {item}\n")
        file.write("\n")

        file.write(f"## 10. DSGVO-Score\n")
        file.write(f"- **Gesamt:** {data.get('score', 'N/A')} ✅\n\n")

        file.write(f"---\n*Analyse abgeschlossen am: {data.get('date', 'N/A')}*\n")
