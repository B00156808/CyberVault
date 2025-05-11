import requests
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QPainter, QBrush, QColor
from ..utils.news_utils import get_cybersecurity_news


class NewsPage(QWidget):
    """News page showing cybersecurity news articles."""

    def __init__(self, api_key, parent=None):
        super().__init__(parent)
        self.api_key = api_key
        self.news_items = []
        self.initUI()

    def initUI(self):
        """Initialize the UI components."""
        layout = QHBoxLayout()

        # Left: Empty container
        left_layout = QVBoxLayout()
        left_layout.setSpacing(0)  # No spacing
        left_layout.addStretch(1)  # Take up flexible space
        left_container = QWidget()
        left_container.setLayout(left_layout)

        # Middle: Cyber News Preview (the actual content)
        middle_layout = QVBoxLayout()
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

        middle_layout.addWidget(label)
        middle_layout.addWidget(self.scroll_area)

        middle_container = QWidget()
        middle_container.setLayout(middle_layout)

        # Right: Empty container
        right_layout = QVBoxLayout()
        right_layout.setSpacing(0)  # No spacing
        right_layout.addStretch(1)  # Take up flexible space
        right_container = QWidget()
        right_container.setLayout(right_layout)

        # Add left, middle, and right containers to the layout
        layout.addWidget(left_container, 1)
        layout.addWidget(middle_container, 3)
        layout.addWidget(right_container, 1)

        self.setLayout(layout)
        self.load_news_articles()

    def create_circular_pixmap(self, pixmap, size=100):
        """Create a circular version of a pixmap for news article images."""
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
        """Load and display news articles with lines only under 'Read more'."""
        self.news_items = get_cybersecurity_news(self.api_key)

        # Clear any existing content
        for i in reversed(range(self.scroll_layout.count())):
            if self.scroll_layout.itemAt(i).widget():
                self.scroll_layout.itemAt(i).widget().deleteLater()

        # If no news items were returned, get fallback content
        if not self.news_items:
            from ..utils.news_utils import get_fallback_cybersecurity_news
            self.news_items = get_fallback_cybersecurity_news()

        # Add a header label if using fallback news
        if len(self.news_items) > 0 and "CISA" in self.news_items[0][0] or "CVE" in self.news_items[0][0]:
            fallback_header = QLabel("Online Cybersecurity Resources")
            fallback_header.setStyleSheet("""
                font-size: 18px;
                color: #0de8f2;
                font-weight: bold;
                margin-bottom: 10px;
            """)
            self.scroll_layout.addWidget(fallback_header)

            # Add explanatory text
            fallback_info = QLabel(
                "Below are links to trusted cybersecurity resources and organizations "
                "that provide the latest information on threats, vulnerabilities, and best practices. "
                "These resources are essential for staying informed about the current cybersecurity landscape."
            )
            fallback_info.setWordWrap(True)
            fallback_info.setStyleSheet("""
                font-size: 14px;
                color: #cccccc;
                margin-bottom: 20px;
            """)
            self.scroll_layout.addWidget(fallback_info)

        for title, description, link, image_url in self.news_items:
            article_widget = QWidget()
            article_layout = QVBoxLayout()  # Changed to QVBoxLayout to stack elements vertically
            article_layout.setSpacing(10)

            # Top section with image and text side by side
            top_section = QHBoxLayout()
            top_section.setSpacing(10)

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
                # Create a themed placeholder based on the title content
                image_pixmap = QPixmap(50, 50)

                # Choose color based on title content
                if "CISA" in title or "government" in title:
                    bg_color = QColor(0, 100, 150)  # Blue for government
                elif "NIST" in title:
                    bg_color = QColor(70, 100, 170)  # Blue-purple for standards
                elif "OWASP" in title:
                    bg_color = QColor(170, 70, 50)  # Red for web security
                elif "CVE" in title or "vulnerabilit" in title.lower():
                    bg_color = QColor(170, 100, 0)  # Orange for vulnerabilities
                elif "SANS" in title:
                    bg_color = QColor(50, 120, 50)  # Green for SANS
                elif "Krebs" in title:
                    bg_color = QColor(100, 50, 120)  # Purple for blogs
                else:
                    bg_color = Qt.darkGray  # Default gray

                image_pixmap.fill(bg_color)
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

            # Add image and text to the top section
            top_section.addWidget(image_label)
            top_section.addLayout(text_layout)
            top_section.addStretch()

            # Add the top section to the article layout
            article_layout.addLayout(top_section)

            # Add Read More link with a line under it
            read_more_section = QVBoxLayout()

            # Read more link
            read_more_label = QLabel(f"<a href='{link}' style='color: #0de8f2;'>Read more</a>")
            read_more_label.setOpenExternalLinks(True)  # Allow opening links
            read_more_label.setAlignment(Qt.AlignRight)
            read_more_section.addWidget(read_more_label)

            # Add a horizontal line under "Read more"
            line = QFrame()
            line.setFrameShape(QFrame.HLine)
            line.setFrameShadow(QFrame.Sunken)
            line.setStyleSheet("background-color: #333;")
            read_more_section.addWidget(line)

            # Add read more section to article layout
            article_layout.addLayout(read_more_section)

            article_widget.setLayout(article_layout)
            article_widget.setStyleSheet("""
                padding: 10px 0;
            """)

            self.scroll_layout.addWidget(article_widget)

        self.scroll_layout.addStretch()