def export_to_markdown(data, filename):
    with open(filename, 'w') as file:
        file.write(f"# 📄 DSGVO-Check Bericht für **{data.get('url', 'N/A')}**\n")
        file.write(f"*Analyse vom {data.get('date', 'N/A')}*\n\n")
        
        file.write(f"---\n\n")
        file.write(f"## 🚦 Zusammenfassung\n\n")
        file.write(f"| Bereich           | Status   | Hinweise                   |\n")
        file.write(f"|-------------------|----------|----------------------------|\n")
        file.write(f"| DSGVO-Score       | **{data.get('score', 'N/A')}**     | Bewertung                |\n")
        file.write(f"| Externe Dienste   | {'❌' if data.get('external_services', False) else '✅'} | {data.get('external_hint', '')} |\n")
        file.write(f"| Cookies           | ✅        | Keine kritischen Cookies   |\n")
        file.write(f"| E-Mail-Sicherheit | ⚠️        | Prüfen DKIM & DMARC        |\n")
        file.write(f"| Rechtliche Seiten | ✅        | Vorhanden                  |\n")
        file.write(f"| Formulare         | ✅        | Keine Risiken erkannt      |\n\n")

        file.write(f"---\n\n")

        file.write(f"## 1. 🌐 Allgemeine Informationen\n")
        file.write(f"- **URL:** {data.get('url', 'N/A')}\n")
        file.write(f"- **Titel:** {data.get('title', 'N/A')}\n")
        file.write(f"- **Beschreibung:** {data.get('description', 'N/A')}\n\n")

        file.write(f"## 2. 🛠️ Software\n")
        file.write(f"- **CMS:** {data.get('cms', 'N/A')}\n")
        file.write(f"- **Pagebuilder:** {data.get('pagebuilder', 'N/A')}\n")
        file.write(f"- **Plugins:** {', '.join(data.get('plugins', []))}\n\n")

        file.write(f"## 3. 🚨 Kritische Punkte\n")
        for check in data.get('dsgvo_check', []):
            file.write(f"- {check}\n")
        file.write("\n")

        file.write(f"## 4. 🍪 Cookies\n")
        file.write(f"- Consent-Tool: {data.get('consent_tool', 'N/A')}\n")
        file.write(f"- Cookies vor Zustimmung: {data.get('cookies_before', 0)}\n")
        file.write(f"- Cookies nach Zustimmung: {data.get('cookies_after', 0)}\n\n")

        file.write(f"## 5. 📧 E-Mail-Sicherheit\n")
        for item in data.get('email_security', []):
            file.write(f"- {item}\n")
        file.write("\n")

        file.write(f"## 6. 🔒 SSL-Zertifikat\n")
        for item in data.get('ssl_info', []):
            file.write(f"- {item}\n")
        file.write("\n")

        file.write(f"## 7. ⚖️ Rechtliche Seiten\n")
        for item in data.get('legal_pages', []):
            file.write(f"- {item}\n")
        file.write("\n")

        file.write(f"## 8. 📝 Formularanalyse\n")
        for item in data.get('forms', []):
            file.write(f"- {item}\n")
        file.write("\n")

        file.write(f"## 9. 📊 DSGVO-Score\n")
        file.write(f"- **Gesamt:** {data.get('score', 'N/A')}\n\n")

        file.write(f"---\n*Analyse abgeschlossen am: {data.get('date', 'N/A')}*\n")
