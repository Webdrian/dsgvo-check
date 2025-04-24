import json
import os
from bs4 import BeautifulSoup

def detect_wordpress_theme(html):
    if "/wp-content/themes/" in html:
        start = html.find("/wp-content/themes/") + len("/wp-content/themes/")
        end = html.find("/", start)
        theme = html[start:end]
        return theme
    return None

def detect_cms(html):
    cms_patterns = {
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Wix": ["wix.com", "wixsite", "Wix.ads", "viewerWix"],
        "Webflow": ["webflow.js", "webflow.css", "data-wf-page"],
        "Joomla": ["joomla"],
        "Drupal": ["drupal", "sites/all", "misc/drupal.js"],
        "Typo3": ["typo3"],
        "Squarespace": ["static.squarespace.com"],
        "Shopify": ["cdn.shopify.com", "shopify"]
    }

    builder_patterns = {
        "Elementor": ["elementor"],
        "Divi": ["et_pb_section", "et_pb_module", "et_pb_row", "et_pb_column"]
    }

    cms_found = []
    builders_found = []

    for name, patterns in cms_patterns.items():
        for pattern in patterns:
            if pattern.lower() in html.lower():
                cms_found.append(name)
                break

    for name, patterns in builder_patterns.items():
        for pattern in patterns:
            if pattern.lower() in html.lower():
                builders_found.append(name)
                break

    return sorted(set(cms_found)), sorted(set(builders_found))


def load_dsgvo_plugins():
    path = os.path.join(os.path.dirname(__file__), "json/dsgvo_plugins.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("plugins", [])

def detect_plugins(html):
    soup = BeautifulSoup(html, "html.parser")
    plugins = []
    dsgvo_plugins = load_dsgvo_plugins()

    for tag in soup.find_all(["link", "script"], href=True):
        if "/wp-content/plugins/" in tag.get("href", ""):
            plugin = tag["href"].split("/wp-content/plugins/")[1].split("/")[0]
            if plugin in dsgvo_plugins and plugin not in plugins:
                plugins.append(plugin)

    for tag in soup.find_all(["link", "script"], src=True):
        if "/wp-content/plugins/" in tag.get("src", ""):
            plugin = tag["src"].split("/wp-content/plugins/")[1].split("/")[0]
            if plugin in dsgvo_plugins and plugin not in plugins:
                plugins.append(plugin)

    return plugins


# Erweiterte Technologie-Erkennung
def detect_technologies(html, headers=None):
    cms, builders = detect_cms(html)
    plugins = detect_plugins(html)
    theme = detect_wordpress_theme(html)

    # Framework-Erkennung
    frameworks = []
    html_lower = html.lower()
    if "data-reactroot" in html_lower or "__react_devtools_global_hook__" in html_lower:
        frameworks.append("React")
    if "data-v-app" in html_lower or "__vue_devtools_global_hook__" in html_lower:
        frameworks.append("Vue")
    if "ng-version" in html_lower:
        frameworks.append("Angular")
    if "jquery" in html_lower:
        frameworks.append("jQuery")

    # Hosting/CDN-Erkennung
    hosting = []
    if "cloudflare" in html_lower:
        hosting.append("Cloudflare")
    if "cdn.jsdelivr.net" in html_lower:
        hosting.append("jsDelivr")
    if "netlify.app" in html_lower:
        hosting.append("Netlify")
    if "vercel.app" in html_lower:
        hosting.append("Vercel")
    if "wp.com" in html_lower or "s.w.org" in html_lower:
        hosting.append("WordPress.com")

    # Shopsysteme
    shops = []
    if "woocommerce" in html_lower or "wc-ajax" in html_lower:
        shops.append("WooCommerce")
    if "shopware" in html_lower or "engine/shopware" in html_lower:
        shops.append("Shopware")
    if "mage" in html_lower or "magento_catalog" in html_lower:
        shops.append("Magento")

    # Tracker (Basis)
    trackers = []
    if "googletagmanager.com" in html_lower or "google-analytics.com" in html_lower:
        trackers.append("Google Analytics")
    if "connect.facebook.net" in html_lower or "fbevents.js" in html_lower:
        trackers.append("Meta Pixel")
    if "hotjar.com" in html_lower:
        trackers.append("Hotjar")
    if "matomo.js" in html_lower or "piwik.js" in html_lower:
        trackers.append("Matomo")

    return {
        "cms": cms,
        "builder": builders,
        "plugins": plugins,
        "theme": theme,
        "frameworks": frameworks,
        "hosting": hosting,
        "shop": shops,
        "trackers": trackers
    }