import sys
import os
import requests
import webbrowser
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QTextEdit, QLabel,
    QHBoxLayout, QListWidget, QListWidgetItem, QHBoxLayout
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QPixmap
from GoogleNews import GoogleNews
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))
import system_info  

from GoogleNews import GoogleNews

def get_top_cybersecurity_news(count=5):
    googlenews = GoogleNews(lang='en', region='US')
    googlenews.search('cybersecurity')
    results = googlenews.results(sort=True)

    articles = []
    for item in results[:count]:
        title = item.get('title', 'No Title')
        link = item.get('link', '#')
        image = item.get('img', None)  #image not showing for me 
        articles.append((title, link, image))
    
    return articles

# === Main Application ===
class App(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('System Information Scanner')
        self.setGeometry(100, 100, 900, 500)

        # === Left Sidebar: Cyber News ===
        self.news_label = QLabel("Cyber News")
        self.news_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        self.news_list = QListWidget()
        self.news_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: white;
                border: none;
            }
            QListWidget::item {
                padding: 10px;
            }
            QListWidget::item:hover {
                background-color: #333;
            }
        """)

        sidebar_layout = QVBoxLayout()
        sidebar_layout.addWidget(self.news_label)
        sidebar_layout.addWidget(self.news_list)

        # === Main Area ===
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)

        self.scan_button = QPushButton('Scan')
        self.scan_button.clicked.connect(self.scan)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.result_text)
        main_layout.addWidget(self.scan_button)

        # === Full Layout ===
        full_layout = QHBoxLayout()
        sidebar_widget = QWidget()
        sidebar_widget.setLayout(sidebar_layout)
        sidebar_widget.setFixedWidth(300)

        main_widget = QWidget()
        main_widget.setLayout(main_layout)

        full_layout.addWidget(sidebar_widget)
        full_layout.addWidget(main_widget)

        self.setLayout(full_layout)

        # Load Cyber News
        self.load_news_articles()

        # Style
        self.setStyleSheet("""
            QWidget {
                background-color: #242424;
                color: #ffffff;
                font-family: system-ui, Avenir, Helvetica, Arial, sans-serif;
            }
            QPushButton {
                padding: 0.6em 1.2em;
                font-size: 1em;
                font-weight: 500;
                background-color: #1a1a1a;
                color: #fff;
                border-radius: 8px;
                border: 1px solid transparent;
            }
            QPushButton:hover {
                border-color: #646cff;
            }
            QTextEdit {
                font-size: 1em;
                background-color: #333333;
                border: 1px solid #444444;
                border-radius: 8px;
                padding: 10px;
            }
        """)

    def load_news_articles(self):
        self.news_list.clear()
        articles = get_top_cybersecurity_news()

        for title, link, image_url in articles:
            widget = QWidget()
            layout = QHBoxLayout()
            layout.setContentsMargins(5, 5, 5, 5)

            # Thumbnail
            img_label = QLabel()
            img_label.setFixedSize(60, 60)
            if image_url:
                try:
                    img_data = requests.get(image_url).content
                    pixmap = QPixmap()
                    pixmap.loadFromData(img_data)
                    pixmap = pixmap.scaled(60, 60, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    img_label.setPixmap(pixmap)
                except Exception as e:
                    print("Image load failed:", e)
            layout.addWidget(img_label)

            # Title
            title_label = QLabel(title)
            title_label.setWordWrap(True)
            layout.addWidget(title_label)

            widget.setLayout(layout)
            item = QListWidgetItem()
            item.setSizeHint(QSize(0, 70))
            self.news_list.addItem(item)
            self.news_list.setItemWidget(item, widget)

            # Connect click to open in browser
            def open_link(_, url=link):
                webbrowser.open(url)

            self.news_list.itemClicked.connect(open_link)

    def scan(self):
        os_platform = system_info.get_OS_platform()
        os_version = system_info.get_OS_version()
        installed_programs = system_info.get_installed_programs()
        system_services = system_info.get_system_services()

        result = f"Operating System: {os_platform}\n"
        result += f"OS Version: {os_version}\n\nInstalled Programs:\n"
        result += "\n".join([f"{prog[0]} - {prog[1]}" for prog in installed_programs]) if isinstance(installed_programs, list) else installed_programs
        result += "\n\nSystem Services:\n"
        result += "\n".join([f"{svc[0]} - {svc[1]} - {svc[2]}" for svc in system_services]) if isinstance(system_services, list) else system_services

        self.result_text.setText(result)

# === Run the Application ===
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec_())
