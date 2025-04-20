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

def detect_plugins(html):
    soup = BeautifulSoup(html, "html.parser")
    plugins = []
    for tag in soup.find_all("link", href=True):
        if "/wp-content/plugins/" in tag["href"]:
            plugin = tag["href"].split("/wp-content/plugins/")[1].split("/")[0]
            if plugin not in plugins:
                plugins.append(plugin)
    for tag in soup.find_all("script", src=True):
        if "/wp-content/plugins/" in tag["src"]:
            plugin = tag["src"].split("/wp-content/plugins/")[1].split("/")[0]
            if plugin not in plugins:
                plugins.append(plugin)
    return plugins