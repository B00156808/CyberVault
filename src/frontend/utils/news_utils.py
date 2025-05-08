import requests
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QSizePolicy

def get_cybersecurity_news(api_key, query='cybersecurity best practices', count=5):
    """Fetch cybersecurity news articles from the GNews API."""
    url = f'https://gnews.io/api/v4/search?q={query}&lang=en&country=us&max={count}&apikey={api_key}'
    try:
        response = requests.get(url)
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
        return []

def get_fallback_cybersecurity_news():
    """Provide fallback news content when API is unavailable."""
    return [
        (
            "What is a Vulnerability Scanner?",
            "A vulnerability scanner is a computer program designed to assess computers, networks or applications for known weaknesses.",
            "https://en.wikipedia.org/wiki/Vulnerability_scanner",
            None
        ),
        (
            "Best Practices for Software Security",
            "Regular updates, strong passwords, and principle of least privilege are fundamental to maintaining software security.",
            "#",
            None
        ),
        (
            "Common Vulnerability Scoring System (CVSS)",
            "CVSS provides a way to capture the principal characteristics of a vulnerability and produce a numerical score reflecting its severity.",
            "https://www.first.org/cvss/",
            None
        ),
        (
            "Why Software Updates Are Important",
            "Software updates patch security vulnerabilities, fix bugs, and can add new features to improve user experience.",
            "#",
            None
        ),
        (
            "Understanding CVE (Common Vulnerabilities and Exposures)",
            "CVE is a list of publicly disclosed computer security flaws that allows organizations to coordinate vulnerability handling.",
            "https://cve.mitre.org/",
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