def export_to_markdown(data, filename):
    with open(filename, 'w') as file:
        file.write(f"# 📄 DSGVO-Check Bericht für **{data.get('url', 'N/A')}**\n")
        file.write(f"*Analyse vom {data.get('date', 'N/A')}*\n\n")
        
        file.write(f"---\n\n")
        file.write(f"## 🚦 Zusammenfassung\n\n")
        score = int(data.get('score_value', 0))
        external_services = data.get('external_services', False)
        external_hint = data.get('external_hint', '')
        cookies_critical = data.get('cookies_critical', False)
        dkim_status = data.get('dkim', 'Unbekannt')
        legal_pages_ok = data.get('legal_pages_ok', True)
        forms_ok = data.get('forms_ok', True)

        file.write(f"| Bereich             | Status   | Hinweise                             |\n")
        file.write(f"|---------------------|----------|--------------------------------------|\n")
        file.write(f"| **DSGVO-Score**     | {'⚠️' if score < 10 else '✅'}  {score}/10 | {data.get('score_text', '')} |\n")
        file.write(f"| **Externe Dienste** | {'❌' if external_services else '✅'}        | {external_hint or 'Keine Probleme'} |\n")
        file.write(f"| **Cookies**         | {'⚠️' if cookies_critical else '✅'}        | {'Kritische Cookies vor Zustimmung' if cookies_critical else 'Keine kritischen Cookies'} |\n")
        file.write(f"| **E-Mail-Sicherheit** | {'⚠️' if dkim_status != 'OK' else '✅'}   | DKIM: {dkim_status} |\n")
        file.write(f"| **Rechtliche Seiten** | {'✅' if legal_pages_ok else '❌'}        | {'Alles vorhanden' if legal_pages_ok else 'Fehlende Angaben'} |\n")
        file.write(f"| **Formulare**       | {'✅' if forms_ok else '⚠️'}              | {'Keine Risiken' if forms_ok else 'Prüfen erforderlich'} |\n\n")

        file.write(f"> **Fazit:** {'Bitte dringend handeln!' if score < 7 else 'Optimierung empfohlen.' if score < 10 else 'Alles in Ordnung.'}\n\n")

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
        file.write(f"- **Gesamt:** {score}/10 – {data.get('score_text', '')}\n\n")

        file.write(f"---\n*Analyse abgeschlossen am: {data.get('date', 'N/A')}*\n")
