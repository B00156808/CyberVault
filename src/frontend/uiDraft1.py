import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QStackedWidget, QPushButton, QLabel, QHBoxLayout
from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtWebEngineWidgets import QWebEngineView

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cybervault")
        self.setGeometry(100, 100, 900, 600)
        self.setStyleSheet("background-color: #0d0d0d; color: white;")
        
        # Main Layout for the app
        self.main_layout = QVBoxLayout()

        # Stacked Widget for Pages
        self.stacked_widget = QStackedWidget()

        # Initialize layout and UI
        self.initUI()

    def initUI(self):
        # Initialize the navigation bar
        self.init_nav_bar()

        # Initialize all pages
        self.init_home_page()
        self.init_news_page()
        self.init_about_us_page()
        self.init_scanning_results_page()

        # Add StackedWidget for page switching
        self.main_layout.addWidget(self.stacked_widget)

        # Set the layout of the main widget
        self.setLayout(self.main_layout)

    def init_nav_bar(self):
        """Creates a simple navigation bar at the top of the window."""
        nav_bar = QHBoxLayout()

        # Create Navigation Buttons
        home_button = self.create_nav_button("Home", self.show_home_page)
        news_button = self.create_nav_button("Cyber News", self.show_news_page)
        scanning_button = self.create_nav_button("Scanning Results", self.show_scanning_results_page)
        about_us_button = self.create_nav_button("About Us", self.show_about_us_page)

        # Add buttons to nav bar
        nav_bar.addWidget(home_button)
        nav_bar.addWidget(news_button)
        nav_bar.addWidget(scanning_button)
        nav_bar.addWidget(about_us_button)

        # Create a nav bar widget and add it to the main layout
        nav_bar_widget = QWidget()
        nav_bar_widget.setLayout(nav_bar)

        # Add the nav bar at the top of the layout
        self.main_layout.addWidget(nav_bar_widget)

    def create_nav_button(self, text, callback):
        """Helper function to create a styled button for the nav bar."""
        button = QPushButton(text)
        button.setStyleSheet("""
            font-size: 16px;
            color: white;
            background-color: #1a1a1a;
            border: 1px solid #333;
            padding: 10px;
            text-align: center;
        """)
        button.setFixedWidth(150)
        button.clicked.connect(callback)
        return button

    def init_home_page(self):
        """Home page layout."""
        home_widget = QWidget()
        home_layout = QVBoxLayout()

        # Add title with a neon effect
        title = QLabel("Welcome to Cybervault")
        title.setStyleSheet("""
            font-size: 36px;
            font-weight: bold;
            color: #0de8f2;
            text-align: center;
            text-shadow: 0 0 10px #0de8f2, 0 0 20px #0de8f2;
        """)
        home_layout.addWidget(title)

        # Add a scan button with hover effect
        scan_button = QPushButton("Start Scan")
        scan_button.setStyleSheet("""
            font-size: 18px;
            color: white;
            background-color: #1a1a1a;
            border: 1px solid #333;
            padding: 10px;
            text-align: center;
        """)
        home_layout.addWidget(scan_button)

        # Add home page widget to stacked widget
        home_widget.setLayout(home_layout)
        self.stacked_widget.addWidget(home_widget)

    def init_news_page(self):
        """News page layout with embedded webview."""
        news_widget = QWidget()
        news_layout = QVBoxLayout()

        # Add title with a glowing effect
        news_label = QLabel("Cyber News")
        news_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #0de8f2;
            text-shadow: 0 0 10px #0de8f2, 0 0 20px #0de8f2;
        """)
        news_layout.addWidget(news_label)

        # Add Web Engine for embedded browsing
        web_view = QWebEngineView()
        web_view.setUrl(QUrl("https://www.bbc.com/news/technology"))
        news_layout.addWidget(web_view)

        # Add News page widget to stacked widget
        news_widget.setLayout(news_layout)
        self.stacked_widget.addWidget(news_widget)

    def init_about_us_page(self):
        """About Us page layout."""
        about_us_widget = QWidget()
        about_us_layout = QVBoxLayout()

        # Add title
        about_us_label = QLabel("About Us")
        about_us_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #0de8f2;
            text-shadow: 0 0 10px #0de8f2, 0 0 20px #0de8f2;
        """)
        about_us_layout.addWidget(about_us_label)

        about_us_text = QLabel("Cybervault is a platform that provides real-time system scanning and cybersecurity updates.")
        about_us_text.setStyleSheet("""
            font-size: 16px;
            color: white;
        """)
        about_us_layout.addWidget(about_us_text)

        # Add About Us page widget to stacked widget
        about_us_widget.setLayout(about_us_layout)
        self.stacked_widget.addWidget(about_us_widget)

    def init_scanning_results_page(self):
        """Scanning Results page layout."""
        scanning_widget = QWidget()
        scanning_layout = QVBoxLayout()

        # Add title
        scanning_label = QLabel("Scanning Results")
        scanning_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #0de8f2;
            text-shadow: 0 0 10px #0de8f2, 0 0 20px #0de8f2;
        """)
        scanning_layout.addWidget(scanning_label)

        # Simulated results (you can update this later with actual scan results)
        results_text = QLabel("No recent scan results found.")
        results_text.setStyleSheet("""
            font-size: 16px;
            color: white;
        """)
        scanning_layout.addWidget(results_text)

        # Add Scanning Results page widget to stacked widget
        scanning_widget.setLayout(scanning_layout)
        self.stacked_widget.addWidget(scanning_widget)

    def show_home_page(self):
        """Navigate to the home page."""
        self.stacked_widget.setCurrentIndex(0)

    def show_news_page(self):
        """Navigate to the news page."""
        self.stacked_widget.setCurrentIndex(1)

    def show_about_us_page(self):
        """Navigate to the about us page."""
        self.stacked_widget.setCurrentIndex(2)

    def show_scanning_results_page(self):
        """Navigate to the scanning results page."""
        self.stacked_widget.setCurrentIndex(3)


# Run the application
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec_())

