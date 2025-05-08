import os
import sys
import threading
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QStackedWidget, QHBoxLayout,
    QPushButton, QLabel, QMessageBox
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QTimer
from PyQt5.QtGui import QPixmap

# Import from other modules (adjust paths to match your structure)
from src.config.settings import API_KEY
from src.backend import cve_checker

# Import custom components
from src.frontend.components.home_page import HomePage
from src.frontend.components.news_page import NewsPage
from src.frontend.components.scan_results_page import ScanResultsPage
from src.frontend.components.about_page import AboutPage


# Worker class for background processing
class ScanWorker(QObject):
    scan_complete = pyqtSignal(dict)
    scan_progress = pyqtSignal(int, str)
    scan_error = pyqtSignal(str)

    def run_scan(self):
        try:
            # Send progress updates
            self.scan_progress.emit(10, "Initializing scan...")

            # Run the scan in background
            results = cve_checker.run_scan()

            if results:
                # Emit the results
                self.scan_complete.emit(results)
            else:
                self.scan_error.emit("Scan failed to complete. Please check logs for details.")
        except Exception as e:
            # Handle any errors
            self.scan_error.emit(f"Error during scan: {str(e)}")


class App(QWidget):
    """Main application window for CyberVault."""

    def __init__(self, api_key):
        super().__init__()
        self.api_key = api_key
        self.setWindowTitle("CyberVault")
        self.setStyleSheet("background-color: #0d0d0d; color: white;")
        self.worker = None
        self.worker_thread = None

        self.main_layout = QVBoxLayout()
        self.stacked_widget = QStackedWidget()
        self.initUI()

    def initUI(self):
        """Initialize the UI components."""
        self.init_nav_bar()

        # Initialize pages
        self.home_page = HomePage(self.api_key)
        self.news_page = NewsPage(self.api_key)
        self.scan_results_page = ScanResultsPage()
        self.about_page = AboutPage()

        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.home_page)
        self.stacked_widget.addWidget(self.news_page)
        self.stacked_widget.addWidget(self.scan_results_page)
        self.stacked_widget.addWidget(self.about_page)

        # Connect signals
        self.home_page.scan_button.clicked.connect(self.scan)

        # Add stacked widget to main layout
        self.main_layout.addWidget(self.stacked_widget)
        self.setLayout(self.main_layout)

    def init_nav_bar(self):
        """Initialize the navigation bar with a larger logo without pushing content away."""
        import os
        from PyQt5.QtGui import QPixmap

        # Main nav layout
        main_nav_layout = QHBoxLayout()
        main_nav_layout.setAlignment(Qt.AlignCenter)
        main_nav_layout.setContentsMargins(10, 0, 10, 0)  # Reduce top/bottom margins

        # Left group layout
        left_layout = QHBoxLayout()
        left_layout.setSpacing(20)
        left_layout.addWidget(self.create_nav_button("Home", self.show_home_page))
        left_layout.addWidget(self.create_nav_button("Cyber News", self.show_news_page))

        # Center logo + label
        logo_layout = QVBoxLayout()
        logo_layout.setAlignment(Qt.AlignCenter)
        logo_layout.setContentsMargins(0, 0, 0, 0)  # No margins to reduce height
        logo_layout.setSpacing(0)  # No spacing

        # Just create the logo label
        logo_label = QLabel()
        logo_label.setAlignment(Qt.AlignCenter)

        # Try to load the logo from the specified path
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        logo_path = os.path.join(project_root, "resources", "images", "CyberVaultLogo.png")

        if os.path.exists(logo_path):
            pixmap = QPixmap(logo_path)
            # Make the logo larger - 300px width while keeping aspect ratio
            pixmap = pixmap.scaled(400, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(pixmap)
            print(f"Logo loaded from: {logo_path}")
        else:
            # Try fallback paths
            fallback_paths = [
                os.path.join(os.path.dirname(__file__), "CyberVaultLogo.png"),
                os.path.join(project_root, "CyberVaultLogo.png"),
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources", "images", "CyberVaultLogo.png")
            ]

            logo_found = False
            for path in fallback_paths:
                if os.path.exists(path):
                    pixmap = QPixmap(path)
                    pixmap = pixmap.scaled(300, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    logo_label.setPixmap(pixmap)
                    print(f"Logo loaded from fallback path: {path}")
                    logo_found = True
                    break

        # Add logo to layout
        logo_layout.addWidget(logo_label)
        logo_widget = QWidget()
        logo_widget.setLayout(logo_layout)

        # Set maximum height for the logo widget to prevent it from pushing content
        logo_widget.setMaximumHeight(110)

        # Right group layout
        right_layout = QHBoxLayout()
        right_layout.setSpacing(20)
        right_layout.addWidget(self.create_nav_button("Scanning Results", self.show_scanning_results_page))
        right_layout.addWidget(self.create_nav_button("About Us", self.show_about_us_page))

        # Add left, center, right to the main layout
        main_nav_layout.addLayout(left_layout)
        main_nav_layout.addSpacing(20)
        main_nav_layout.addWidget(logo_widget)
        main_nav_layout.addSpacing(20)
        main_nav_layout.addLayout(right_layout)

        # Add to main layout
        nav_widget = QWidget()
        nav_widget.setLayout(main_nav_layout)
        nav_widget.setMaximumHeight(120)  # Limit the height of the entire nav bar

        # Remove any spacing before and after the nav widget
        self.main_layout.addWidget(nav_widget)
        self.main_layout.setSpacing(0)  # Reduce spacing between widgets


    def create_nav_button(self, text, callback):
        """Create a navigation button with consistent styling."""
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

    def scan(self):
        """Run a vulnerability scan in the background."""
        # Show the results page
        self.show_scanning_results_page()

        # Set up progress indicators
        self.scan_results_page.progress_bar.setValue(0)
        self.scan_results_page.show_progress(0, "Preparing for scan...")

        # Create worker in a new thread
        self.worker = ScanWorker()
        self.worker_thread = threading.Thread(target=self.worker.run_scan)

        # Connect signals
        self.worker.scan_complete.connect(self.on_scan_complete)
        self.worker.scan_progress.connect(self.on_scan_progress)
        self.worker.scan_error.connect(self.on_scan_error)

        # Start the scan
        self.worker_thread.daemon = True
        self.worker_thread.start()

    def on_scan_complete(self, results):
        """Handle scan completion."""
        # Update the UI with results
        self.scan_results_page.update_results(results['scan_data'])
        self.scan_results_page.set_pdf_report_path(results['pdf_path'])

        # Update reports list on home page
        self.home_page.update_reports_list()

    def on_scan_progress(self, progress, message):
        """Update scan progress."""
        self.scan_results_page.show_progress(progress, message)

    def on_scan_error(self, error_message):
        """Handle scan errors."""
        self.scan_results_page.progress_bar.setVisible(False)
        self.scan_results_page.progress_label.setVisible(False)

        QMessageBox.critical(self, "Scan Error", error_message)

    def show_home_page(self):
        self.stacked_widget.setCurrentIndex(0)

    def show_news_page(self):
        self.stacked_widget.setCurrentIndex(1)

    def show_scanning_results_page(self):
        self.stacked_widget.setCurrentIndex(2)

    def show_about_us_page(self):
        self.stacked_widget.setCurrentIndex(3)