import requests
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QSizePolicy


def get_cybersecurity_news(api_key, query='cybersecurity best practices', count=5):
    """Fetch cybersecurity news articles from the GNews API."""
    # Check for internet connection first
    from .network_utils import check_internet_connection
    if not check_internet_connection():
        print("No internet connection, using fallback news")
        return get_fallback_cybersecurity_news()

    url = f'https://gnews.io/api/v4/search?q={query}&lang=en&country=us&max={count}&apikey={api_key}'
    try:
        response = requests.get(url, timeout=5)  # Add timeout to prevent long waits
        response.raise_for_status()
        data = response.json()
        articles = data.get('articles', [])
        result = []
        for item in articles:
            title = item.get('title', 'No Title')
            description = item.get('description', 'No description available')
            link = item.get('url', '#')
            image_url = item.get('image', None)
            result.append((title, description, link, image_url))
        return result
    except requests.exceptions.RequestException as e:
        print(f"Error fetching news: {e}")
        return get_fallback_cybersecurity_news()
    except ValueError as e:  # JSON decoding error
        print(f"Error parsing news data: {e}")
        return get_fallback_cybersecurity_news()
    except Exception as e:
        print(f"Unexpected error fetching news: {e}")
        return get_fallback_cybersecurity_news()


def get_fallback_cybersecurity_news():
    """Provide fallback news content pointing to well-recognized cybersecurity resources."""
    return [
        (
            "CISA: Cybersecurity & Infrastructure Security Agency",
            "The U.S. government's official cybersecurity agency providing resources, alerts, and guidance for all organizations. Visit for latest cybersecurity advisories and best practices.",
            "https://www.cisa.gov/cybersecurity",
            None
        ),
        (
            "NIST Cybersecurity Framework",
            "The National Institute of Standards and Technology's comprehensive framework for managing and reducing cybersecurity risk, widely adopted by organizations worldwide.",
            "https://www.nist.gov/cyberframework",
            None
        ),
        (
            "OWASP Top 10 Web Application Security Risks",
            "The Open Web Application Security Project's definitive list of the most critical web application security risks, essential for developers and security professionals.",
            "https://owasp.org/www-project-top-ten/",
            None
        ),
        (
            "SANS Internet Storm Center",
            "The SANS Internet Storm Center monitors global cyber threats and provides daily updates on emerging security issues and attacks via their handler diaries.",
            "https://isc.sans.edu/",
            None
        ),
        (
            "CVE Database: Common Vulnerabilities and Exposures",
            "The authoritative reference for publicly known cybersecurity vulnerabilities maintained by MITRE, essential for vulnerability management programs.",
            "https://cve.mitre.org/",
            None
        ),
        (
            "Krebs on Security",
            "Brian Krebs' in-depth blog covering cybersecurity news, data breaches, and emerging threats with deep investigative reporting.",
            "https://krebsonsecurity.com/",
            None
        ),
        (
            "The CyberWire: Cybersecurity News and Analysis",
            "Daily cybersecurity news, interviews, and podcasts from industry experts, providing clear and concise coverage of current threats.",
            "https://thecyberwire.com/",
            None
        ),
        (
            "Schneier on Security",
            "Bruce Schneier's respected blog on cybersecurity, cryptography, privacy, and related policy issues, widely followed in the security community.",
            "https://www.schneier.com/",
            None
        )
    ]


class NewsItemWidget(QWidget):
    """Widget for displaying news items in the UI."""

    def __init__(self, title, description, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        self.title_label.setWordWrap(True)
        self.title_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        self.desc_label = QLabel(description)
        self.desc_label.setStyleSheet("font-size: 12px; color: #aaaaaa;")
        self.desc_label.setWordWrap(True)
        self.desc_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        layout.addWidget(self.title_label)
        layout.addWidget(self.desc_label)

        self.setLayout(layout)
        self.setStyleSheet("background-color: transparent;")

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)