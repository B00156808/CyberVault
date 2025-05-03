import sys
import os
import requests
import webbrowser
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QStackedWidget, QPushButton,
    QLabel, QHBoxLayout, QListWidget, QListWidgetItem, QTextEdit, QSizePolicy, QScrollArea
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QPainter, QBrush

# Import your custom system_info module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))
import system_info

API_KEY = '971cf28df41c8a5d09151bb993dd8f19'  # Your API key here

# === News Item Widget ===
class NewsItemWidget(QWidget):
    def __init__(self, title, description):
        super().__init__()
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

# === Get News Function ===
def get_cybersecurity_news(api_key, query='cybersecurity best practices', count=5):
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

# === Main App ===
class App(QWidget):
    def __init__(self, api_key):
        super().__init__()
        self.api_key = api_key
        self.setWindowTitle("Cybervault")
        self.setGeometry(100, 100, 1000, 600)
        self.setStyleSheet("background-color: #0d0d0d; color: white;")

        self.main_layout = QVBoxLayout()
        self.stacked_widget = QStackedWidget()
        self.initUI()

    def initUI(self):
        self.init_nav_bar()
        self.init_home_page()
        self.init_news_page()
        self.init_scanning_results_page()
        self.init_about_us_page()
        self.main_layout.addWidget(self.stacked_widget)
        self.setLayout(self.main_layout)

    def init_nav_bar(self):
        # Main nav layout
        main_nav_layout = QHBoxLayout()
        main_nav_layout.setAlignment(Qt.AlignCenter)

        # Left group layout
        left_layout = QHBoxLayout()
        left_layout.setSpacing(20)
        left_layout.addWidget(self.create_nav_button("Home", self.show_home_page))
        left_layout.addWidget(self.create_nav_button("Cyber News", self.show_news_page))

        # Center logo + label
        logo_layout = QVBoxLayout()
        logo_layout.setAlignment(Qt.AlignCenter)

        company_label = QLabel("CyberVault")
        company_label.setAlignment(Qt.AlignCenter)
        company_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #0de8f2;")

        logo_label = QLabel()
        pixmap = QPixmap("CyberVaultLogo.png")
        logo_label.setPixmap(pixmap.scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_label.setAlignment(Qt.AlignCenter)

        logo_layout.addWidget(company_label)
        logo_layout.addWidget(logo_label)
        logo_widget = QWidget()
        logo_widget.setLayout(logo_layout)

        # Right group layout
        right_layout = QHBoxLayout()
        right_layout.setSpacing(20)
        right_layout.addWidget(self.create_nav_button("Scanning Results", self.show_scanning_results_page))
        right_layout.addWidget(self.create_nav_button("About Us", self.show_about_us_page))

        # Wrap left, center, right in the main layout with controlled spacing
        main_nav_layout.addLayout(left_layout)
        main_nav_layout.addSpacing(30)  # Spacing between left and logo
        main_nav_layout.addWidget(logo_widget)
        main_nav_layout.addSpacing(30)  # Spacing between logo and right
        main_nav_layout.addLayout(right_layout)

        # Add to main layout
        nav_widget = QWidget()
        nav_widget.setLayout(main_nav_layout)
        self.main_layout.addWidget(nav_widget)

    def create_nav_button(self, text, callback):
        button = QPushButton(text)
        button.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                color: white;
                background-color: #1a1a1a;
                border: 1px solid #333;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #333333;
                border-color: #0de8f2;
            }
        """)
        button.setFixedWidth(150)
        button.clicked.connect(callback)
        return button

    def init_home_page(self):
        home_widget = QWidget()
        home_layout = QHBoxLayout()

        # Left: News Preview
        left_layout = QVBoxLayout()
        news_label = QLabel("Cyber News Preview")
        news_label.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #0de8f2;
        """)

        self.home_news_list = QListWidget()
        self.home_news_list.setStyleSheet("""
            QListWidget {
                background-color: #121212;  /* matches darker gray tones */
                color: white;
                border: none;
            }
            QListWidget::item {
                padding: 8px;
                background-color: transparent;
            }
            QListWidget::item:hover {
                background-color: #2a2a2a;
            }
        """)
        self.home_news_list.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Container for the preview and scan results
        left_container = QVBoxLayout()
        left_container.addWidget(news_label)

        # Top: News list (takes 3/4 of space)
        left_container.addWidget(self.home_news_list, stretch=3)

        # Bottom: Scan results viewer (1/4 of space)
        self.scan_results_box = QTextEdit()
        self.scan_results_box.setReadOnly(True)
        self.scan_results_box.setPlaceholderText("No scan results yet.")
        self.scan_results_box.setStyleSheet("""
            background-color: #1e1e1e;
            color: #0de8f2;
            font-size: 12px;
            border: 1px solid #333;
            padding: 5px;
        """)
        left_container.addWidget(self.scan_results_box, stretch=1)

        left_layout.addLayout(left_container)

        # Right: Welcome and Scan
        right_layout = QVBoxLayout()
        title = QLabel("Welcome to Cybervault")
        title.setStyleSheet("""
            font-size: 32px;
            font-weight: bold;
            color: #0de8f2;
        """)
        title.setAlignment(Qt.AlignCenter)

        scan_button = QPushButton("Start Scan")
        scan_button.setStyleSheet("""
            font-size: 18px;
            color: white;
            background-color: #1a1a1a;
            padding: 10px;
        """)
        scan_button.clicked.connect(self.scan)

        right_layout.addStretch()
        right_layout.addWidget(title)
        right_layout.addSpacing(20)
        right_layout.addWidget(scan_button)
        right_layout.addStretch()

        home_layout.addLayout(left_layout, 1)
        home_layout.addLayout(right_layout, 3)

        home_widget.setLayout(home_layout)
        self.stacked_widget.addWidget(home_widget)

        self.load_home_news_preview()


    def load_home_news_preview(self):
        self.home_news_list.clear()
        self.home_news_articles = get_cybersecurity_news(self.api_key)

        for title, description, link, image_url in self.home_news_articles:
            item_widget = NewsItemWidget(title, description)
            item = QListWidgetItem(self.home_news_list)
            item.setSizeHint(item_widget.sizeHint())

            self.home_news_list.addItem(item)
            self.home_news_list.setItemWidget(item, item_widget)

        self.home_news_list.itemClicked.connect(self.open_home_news_link)

    def open_home_news_link(self, item):
        index = self.home_news_list.row(item)
        if 0 <= index < len(self.home_news_articles):
            webbrowser.open(self.home_news_articles[index][2])

    def init_news_page(self):
        news_widget = QWidget()
        layout = QVBoxLayout()

        label = QLabel("Latest Cybersecurity News")
        label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #0de8f2;
        """)

        # Scrollable area to hold articles
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout()
        self.scroll_content.setLayout(self.scroll_layout)
        self.scroll_area.setWidget(self.scroll_content)

        layout.addWidget(label)
        layout.addWidget(self.scroll_area)

        self.load_news_articles()

        news_widget.setLayout(layout)
        self.stacked_widget.addWidget(news_widget)

    def create_circular_pixmap(self, pixmap, size=100):
        circular = QPixmap(size, size)
        circular.fill(Qt.transparent)

        painter = QPainter(circular)
        painter.setRenderHint(QPainter.Antialiasing)
        brush = QBrush(pixmap.scaled(size, size, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation))
        painter.setBrush(brush)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(0, 0, size, size)
        painter.end()

        return circular

    def load_news_articles(self):
        self.news_items = get_cybersecurity_news(self.api_key)
        for title, description, link, image_url in self.news_items:
            article_widget = QWidget()
            article_layout = QHBoxLayout()
            article_layout.setSpacing(10)

            # Load and prepare image
            image_label = QLabel()
            if image_url:
                try:
                    image_pixmap = QPixmap()
                    image_pixmap.loadFromData(requests.get(image_url).content)
                    image_pixmap = self.create_circular_pixmap(image_pixmap, 100)
                except Exception as e:
                    print(f"Failed to load image: {e}")
                    image_pixmap = QPixmap(50, 50)
                    image_pixmap.fill(Qt.darkGray)
                    image_pixmap = self.create_circular_pixmap(image_pixmap, 100)
            else:
                image_pixmap = QPixmap(50, 50)
                image_pixmap.fill(Qt.darkGray)
                image_pixmap = self.create_circular_pixmap(image_pixmap, 100)

            image_label.setPixmap(image_pixmap)
            image_label.setFixedSize(100, 100)

            # Text layout for title + description
            text_layout = QVBoxLayout()
            text_layout.setSpacing(1)
            title_label = QLabel(title)
            title_label.setWordWrap(True)
            title_label.setStyleSheet("""
                font-size: 16px;
                font-weight: bold;
                color: white;
            """)

            desc_label = QLabel(description)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("""
                font-size: 12px;
                color: #cccccc;
            """)

            text_layout.addWidget(title_label)
            text_layout.addWidget(desc_label)

            # Add image and text to the article layout
            article_layout.addWidget(image_label)
            article_layout.addLayout(text_layout)
            article_layout.addStretch()

            article_widget.setLayout(article_layout)
            article_widget.setStyleSheet("""
                padding: 10px 0;
            """)

            self.scroll_layout.addWidget(article_widget)

        self.scroll_layout.addStretch()


    def open_news_link(self, item):
        index = self.news_list.row(item)
        if 0 <= index < len(self.news_items):
            webbrowser.open(self.news_items[index][2])

    def init_scanning_results_page(self):
        scan_widget = QWidget()
        layout = QVBoxLayout()

        label = QLabel("Scanning Results")
        label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #0de8f2;
        """)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet("""
            background-color: #1e1e1e;
            border: 1px solid #333;
            padding: 10px;
            font-size: 14px;
        """)

        layout.addWidget(label)
        layout.addWidget(self.result_text)
        scan_widget.setLayout(layout)
        self.stacked_widget.addWidget(scan_widget)

    def init_about_us_page(self):
        about_widget = QWidget()
        layout = QVBoxLayout()

        label = QLabel("About Us")
        label.setStyleSheet("font-size: 24px; font-weight: bold; color: #0de8f2;")

        description = QLabel(
            "Cybervault is a tool for scanning system info and keeping you updated with the latest in cybersecurity."
        )
        description.setWordWrap(True)
        description.setStyleSheet("font-size: 16px; color: white;")

        credits = QLabel(
            "Developed by: Your Name or Team\n"
            "Version: 1.0\n"
            "For more information, visit our website."
        )
        credits.setWordWrap(True)
        credits.setStyleSheet("font-size: 14px; color: white; margin-top: 20px;")

        layout.addWidget(label)
        layout.addWidget(description)
        layout.addWidget(credits)

        layout.setAlignment(Qt.AlignTop)

        about_widget.setLayout(layout)
        self.stacked_widget.addWidget(about_widget)

    def scan(self):
        os_platform = system_info.get_OS_platform()
        os_version = system_info.get_OS_version()
        installed_programs = system_info.get_installed_programs()
        system_services = system_info.get_system_services()

        result = f"Operating System: {os_platform}\n"
        result += f"OS Version: {os_version}\n\nInstalled Programs:\n"
        result += "\n".join([f"{prog[0]} - {prog[1]}" for prog in installed_programs]) if isinstance(installed_programs, list) else str(installed_programs)
        result += "\n\nSystem Services:\n"
        result += "\n".join([f"{svc[0]} - {svc[1]} - {svc[2]}" for svc in system_services]) if isinstance(system_services, list) else str(system_services)

        self.result_text.setText(result)
        self.show_scanning_results_page()

    def show_home_page(self):
        self.stacked_widget.setCurrentIndex(0)

    def show_news_page(self):
        self.stacked_widget.setCurrentIndex(1)

    def show_scanning_results_page(self):
        self.stacked_widget.setCurrentIndex(2)

    def show_about_us_page(self):
        self.stacked_widget.setCurrentIndex(3)

# === Run the App ===
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = App(API_KEY)
    window.show()
    sys.exit(app.exec_())
