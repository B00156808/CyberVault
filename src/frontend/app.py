import threading
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QStackedWidget, QHBoxLayout,
    QPushButton, QLabel, QMessageBox, QMainWindow
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QTimer


# Import from other modules (adjust paths to match your structure)
from src.backend import cve_checker

# Import custom components
from src.frontend.components.home_page import HomePage
from src.frontend.components.news_page import NewsPage
from src.frontend.components.scan_results_page import ScanResultsPage
from src.frontend.components.about_page import AboutPage
from src.frontend.components.connection_overlay import ConnectionOverlay
from src.frontend.components.status_bar import StatusBar

# Import network utilities
from src.frontend.utils.network_utils import NetworkMonitor, check_internet_connection


# Worker class for background processing
class ScanWorker(QObject):
    scan_complete = pyqtSignal(dict)
    scan_progress = pyqtSignal(int, str)
    scan_error = pyqtSignal(str)

    def run_scan(self):
        try:
            # Send initial progress update
            self.scan_progress.emit(10, "Initializing scan...")

            # Simulate database check progress
            import time
            time.sleep(0.5)  # Short delay for UI responsiveness
            self.scan_progress.emit(25, "Checking vulnerability database...")
            time.sleep(0.5)  # Short delay for UI responsiveness

            # Simulate software scanning progress
            self.scan_progress.emit(50, "Scanning installed software...")
            time.sleep(0.5)  # Short delay for UI responsiveness

            # Simulate matching vulnerabilities progress
            self.scan_progress.emit(75, "Matching with known vulnerabilities...")
            time.sleep(0.5)  # Short delay for UI responsiveness

            # Run the actual scan which will generate the report
            self.scan_progress.emit(90, "Generating vulnerability report...")

            # Run the scan in background
            results = cve_checker.run_scan()

            # Final progress update before completion
            self.scan_progress.emit(100, "Scan complete!")

            if results:
                # Emit the results
                self.scan_complete.emit(results)
            else:
                self.scan_error.emit("Scan failed to complete. Please check logs for details.")
        except Exception as e:
            # Handle any errors
            self.scan_error.emit(f"Error during scan: {str(e)}")


class MainWindow(QMainWindow):
    """Main window class for CyberVault application with status bar."""

    def __init__(self, api_key):
        super().__init__()
        self.api_key = api_key
        self.setWindowTitle("CyberVault")
        self.setStyleSheet("background-color: #0d0d0d; color: white;")

        # Initialize network monitor
        self.network_monitor = NetworkMonitor(check_interval=10)
        self.network_monitor.connection_lost.connect(self.on_connection_lost)
        self.network_monitor.connection_established.connect(self.on_connection_restored)

        # Create central widget to hold the content
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Set up main layout for central widget
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Create app content
        self.app_content = AppContent(api_key, self)

        # Add app content to main layout
        self.main_layout.addWidget(self.app_content)

        # Create and set the status bar
        self.status_bar = StatusBar()
        self.setStatusBar(self.status_bar)

        # Initial network check on startup
        self.is_connected = check_internet_connection()
        self.status_bar.update_connection_status(self.is_connected)

        # Create connection overlay
        self.connection_overlay = ConnectionOverlay(self)
        self.connection_overlay.hide()

        # Start network monitoring
        self.network_monitor.start_monitoring()

        # If not connected on startup, show the overlay
        if not self.is_connected:
            QTimer.singleShot(500, self.show_connection_overlay)

    def show_connection_overlay(self):
        """Show the connection lost overlay."""
        # Position the overlay to cover the entire window
        self.connection_overlay.setGeometry(self.rect())
        self.connection_overlay.show()
        self.connection_overlay.raise_()

    def hide_connection_overlay(self):
        """Hide the connection lost overlay."""
        self.connection_overlay.hide()

    def on_connection_lost(self):
        """Handle internet connection lost event."""
        print("Network connection lost.")
        self.is_connected = False

        # Update status bar
        self.status_bar.update_connection_status(False)

        # Show the overlay on the main thread
        QTimer.singleShot(0, self.show_connection_overlay)

    def on_connection_restored(self):
        """Handle internet connection restored event."""
        print("Network connection restored.")
        self.is_connected = True

        # Update status bar
        self.status_bar.update_connection_status(True)

        # Hide the overlay on the main thread
        QTimer.singleShot(0, self.hide_connection_overlay)

        # Refresh app content
        QTimer.singleShot(500, self.refresh_application)

    def refresh_application(self):
        """Refresh the application content after connection is restored."""
        if hasattr(self.app_content, 'refresh_content'):
            self.app_content.refresh_content()

        print("Application content refreshed.")

    def resizeEvent(self, event):
        """Handle resize events to adjust overlay size."""
        super().resizeEvent(event)
        if self.connection_overlay and self.connection_overlay.isVisible():
            self.connection_overlay.setGeometry(self.rect())

    def closeEvent(self, event):
        """Clean up before closing the application."""
        # Stop network monitoring
        if hasattr(self, 'network_monitor'):
            self.network_monitor.stop_monitoring()

        # Accept the event to close the window
        event.accept()


class AppContent(QWidget):
    """Content widget for CyberVault application."""

    def __init__(self, api_key, parent=None):
        super().__init__(parent)
        self.api_key = api_key
        self.worker = None
        self.worker_thread = None

        # Set up layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Stacked widget to hold main content
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
        # Check for internet connection first
        if not check_internet_connection():
            parent = self.parent()
            if isinstance(parent, MainWindow):
                parent.show_connection_overlay()
            return

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

    def refresh_content(self):
        """Refresh the application content after connection is restored."""
        current_index = self.stacked_widget.currentIndex()

        # Update news content on home page
        if hasattr(self.home_page, 'load_news_preview'):
            self.home_page.load_news_preview()

        # Update news page if it's currently shown
        if current_index == 1 and hasattr(self.news_page, 'load_news_articles'):
            self.news_page.load_news_articles()

        print("AppContent content refreshed.")


# For backward compatibility, simplified App class that uses MainWindow
class App(MainWindow):
    """For compatibility with existing code: redirects to MainWindow."""

    def __init__(self, api_key):
        super().__init__(api_key)
        print("Using updated App class with network connectivity monitoring")