import sys
import os
import requests
import webbrowser
import subprocess
from collections import Counter
from datetime import datetime
import re
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QStackedWidget, QPushButton,
    QLabel, QHBoxLayout, QListWidget, QListWidgetItem, QTextEdit, QSizePolicy, QScrollArea,
    QFrame, QProgressBar, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QPixmap, QPainter, QBrush, QColor
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import sqlite3
import threading
from packaging.version import parse as parse_version

# Import your custom system_info module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))
import system_info

# Add path to the directory containing your CVE checker script
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))
import cve_checker_test  # Import the CVE checker script

# Fix the database path issue by setting the DB_FILE to an absolute path
if hasattr(cve_checker_test, 'DB_FILE'):
    # Get the filename from the original path
    db_filename = os.path.basename(cve_checker_test.DB_FILE)

    # Create an absolute path to the backend directory
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend'))

    # Create the full absolute path to the database file
    db_absolute_path = os.path.join(backend_dir, db_filename)

    # Override the DB_FILE in the module
    cve_checker_test.DB_FILE = db_absolute_path

    print(f"Updated database path: {cve_checker_test.DB_FILE}")
    print(f"Database exists: {os.path.exists(cve_checker_test.DB_FILE)}")

API_KEY = '971cf28df41c8a5d09151bb993dd8f19'  # Your API key here


# === Helper Functions ===
def classify_cvss(score):
    """Classify CVSS score into severity levels"""
    if score is None:
        return "Unknown"

    score = float(score)
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    else:
        return "None"


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


# === Pie Chart Canvas ===
class VulnerabilityPieChart(FigureCanvas):
    def __init__(self, parent=None, width=5, height=5, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111)
        super(VulnerabilityPieChart, self).__init__(self.fig)
        self.setParent(parent)

        # Make the background match the application theme
        self.fig.patch.set_facecolor('#1e1e1e')
        self.axes.set_facecolor('#1e1e1e')

        # Set text color to white for better visibility
        self.axes.tick_params(colors='white')
        for text in self.axes.texts:
            text.set_color('white')

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def update_chart(self, severity_data):
        self.axes.clear()

        labels = []
        sizes = []

        # Define the order we want
        severity_order = ["Critical", "High", "Medium", "Low", "None", "Unknown"]

        # Sort data by predefined order
        for severity in severity_order:
            if severity in severity_data and severity_data[severity] > 0:
                labels.append(f"{severity} ({severity_data[severity]})")
                sizes.append(severity_data[severity])

        colors = {
            "Critical": "red",
            "High": "orange",
            "Medium": "gold",
            "Low": "lightgreen",
            "None": "gray",
            "Unknown": "darkgray"
        }

        color_list = [colors[severity] for severity in severity_order if
                      severity in severity_data and severity_data[severity] > 0]
        explode = [0.1 if l.startswith("Critical") else 0 for l in labels]

        if sizes:  # Only create pie if we have data
            self.axes.pie(
                sizes,
                labels=labels,
                autopct='%1.1f%%',
                colors=color_list,
                explode=explode,
                startangle=140,
                textprops={'color': 'white'}
            )
            self.axes.set_title("Distribution of CVE Severities", color='white')
            self.axes.axis("equal")

        self.fig.tight_layout()
        self.draw()


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


# === Worker for background processing ===
class ScanWorker(QObject):
    scan_complete = pyqtSignal(dict, str, str)
    scan_progress = pyqtSignal(int, str)
    scan_error = pyqtSignal(str)


# === Main App ===
class App(QWidget):
    def __init__(self, api_key):
        super().__init__()
        self.api_key = api_key
        self.setWindowTitle("Cybervault")
        self.setStyleSheet("background-color: #0d0d0d; color: white;")
        self.pdf_report_path = None
        self.available_reports = []

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

    def get_available_reports(self):
        """Get a list of all available reports with timestamps"""
        # Use the frontend/reports path directly
        output_dir = os.path.join(os.path.dirname(__file__), 'reports')
        print(f"Looking for reports in: {output_dir}")

        # List to store reports with their timestamps
        reports = []

        try:
            # Make sure the directory exists
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                print(f"Created reports directory: {output_dir}")

            # Find all PDF files in the reports directory
            for file in os.listdir(output_dir):
                if file.lower().endswith('.pdf'):
                    file_path = os.path.join(output_dir, file)
                    # Extract timestamp from filename
                    timestamp_match = re.search(r'cybervault-report-(\d{8})_(\d{6})\.pdf', file)
                    if timestamp_match:
                        date_str, time_str = timestamp_match.groups()
                        # Format: YYYYMMDD to YYYY-MM-DD
                        formatted_date = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}"
                        # Format: HHMMSS to HH:MM:SS
                        formatted_time = f"{time_str[:2]}:{time_str[2:4]}:{time_str[4:6]}"
                        timestamp = f"{formatted_date} {formatted_time}"
                    else:
                        # If can't extract from filename, use file modification time
                        mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                        timestamp = mod_time.strftime("%Y-%m-%d %H:%M:%S")

                    reports.append({
                        'path': file_path,
                        'filename': file,
                        'timestamp': timestamp
                    })
                    print(f"Found report: {file}")
        except Exception as e:
            print(f"Error getting reports: {e}")

        # Sort by timestamp (newest first)
        reports.sort(key=lambda x: x['timestamp'], reverse=True)
        return reports

    def update_reports_list(self):
        """Update the scan_results_box to show available reports"""
        # Get all available reports
        reports = self.get_available_reports()

        # Format the reports list as text
        if reports:
            text = "Available Reports (double-click to open):\n\n"
            for i, report in enumerate(reports):
                text += f"{i + 1}. Report from {report['timestamp']}\n"

            # Set the new text
            self.scan_results_box.setText(text)

            # Store report paths for retrieval
            self.available_reports = reports
        else:
            self.scan_results_box.setText("No reports available yet.")

    def scan_results_box_clicked(self, event):
        """Handle double-clicks in the scan results box"""
        # Get the cursor position at the click location
        cursor = self.scan_results_box.cursorForPosition(event.pos())

        # Get the line number at the cursor position
        line_number = cursor.blockNumber()

        # Get all lines of text
        text = self.scan_results_box.toPlainText().split('\n')

        # Check if this is a report line (starts with a number followed by a dot)
        if line_number < len(text):
            line = text[line_number]
            # Check if the line is a report line (numbered list item)
            match = re.match(r'(\d+)\.\s', line)
            if match and hasattr(self, 'available_reports'):
                # Get the report index (1-based in display, 0-based in list)
                report_index = int(match.group(1)) - 1
                if 0 <= report_index < len(self.available_reports):
                    # Open the report
                    file_path = self.available_reports[report_index]['path']
                    self.open_report_file(file_path)

    def open_report_file(self, file_path):
        """Open a report file"""
        if file_path and os.path.exists(file_path):
            try:
                # Use the default system PDF viewer to open the report
                if sys.platform == "win32":
                    os.startfile(file_path)
                elif sys.platform == "darwin":  # macOS
                    subprocess.run(["open", file_path])
                else:  # Linux
                    subprocess.run(["xdg-open", file_path])
            except Exception as e:
                QMessageBox.warning(self, "Error Opening Report",
                                    f"Could not open the report:\n\n{str(e)}")
        else:
            QMessageBox.information(self, "Report Not Available",
                                    "The report file could not be found.")

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

        # Bottom: Scan results viewer (1/4 of space) - Now used for PDF reports
        self.scan_results_box = QTextEdit()
        self.scan_results_box.setReadOnly(True)
        self.scan_results_box.setPlaceholderText("No reports available yet.")
        self.scan_results_box.setStyleSheet("""
            background-color: #1e1e1e;
            color: #0de8f2;
            font-size: 12px;
            border: 1px solid #333;
            padding: 5px;
        """)
        # Set up double-click handling for scan results box
        self.scan_results_box.mouseDoubleClickEvent = self.scan_results_box_clicked

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
        # Update the reports list when the application starts
        self.update_reports_list()

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
        layout.addWidget(left_container, 1)  # Left takes flexible space
        layout.addWidget(middle_container, 3)  # Middle takes 3 times as much space
        layout.addWidget(right_container, 1)  # Right takes flexible space

        news_widget.setLayout(layout)
        self.stacked_widget.addWidget(news_widget)

        self.load_news_articles()  # Load the news articles

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
        main_layout = QVBoxLayout()

        # Header Section with timestamp
        header_layout = QHBoxLayout()

        header_label = QLabel("Scanning Results")
        header_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #0de8f2;
        """)
        header_layout.addWidget(header_label)

        # Add timestamp label (will be populated during scan)
        self.timestamp_label = QLabel("")
        self.timestamp_label.setStyleSheet("""
            font-size: 14px;
            color: #aaaaaa;
            padding-left: 20px;
        """)
        self.timestamp_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        header_layout.addWidget(self.timestamp_label)

        main_layout.addLayout(header_layout)

        # Content Section - Split into chart and results
        content_layout = QHBoxLayout()

        # Left side - Chart
        chart_container = QVBoxLayout()
        chart_title = QLabel("Vulnerability Severity Distribution")
        chart_title.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: white;
            margin-bottom: 10px;
        """)
        chart_container.addWidget(chart_title)

        # Create the pie chart widget
        self.pie_chart = VulnerabilityPieChart(width=5, height=5)
        chart_container.addWidget(self.pie_chart)

        # Right side - Text Results
        results_container = QVBoxLayout()

        severity_title = QLabel("Severity Breakdown")
        severity_title.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: white;
            margin-bottom: 10px;
        """)
        results_container.addWidget(severity_title)

        # Severity breakdown list
        self.severity_list = QTextEdit()
        self.severity_list.setReadOnly(True)
        self.severity_list.setStyleSheet("""
            background-color: #1e1e1e;
            border: 1px solid #333;
            padding: 10px;
            font-size: 14px;
            color: white;
        """)
        results_container.addWidget(self.severity_list)

        # System details text area
        system_info_title = QLabel("System Information")
        system_info_title.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: white;
            margin-top: 15px;
            margin-bottom: 10px;
        """)
        results_container.addWidget(system_info_title)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet("""
            background-color: #1e1e1e;
            border: 1px solid #333;
            padding: 10px;
            font-size: 14px;
            color: #cccccc;
        """)
        results_container.addWidget(self.result_text)

        # Add chart and results to the content layout
        content_layout.addLayout(chart_container, 1)
        content_layout.addLayout(results_container, 1)

        # Add the content layout to the main layout
        main_layout.addLayout(content_layout)

        # Add PDF report button at the bottom
        self.report_button = QPushButton("Open PDF Report")
        self.report_button.setStyleSheet("""
            font-size: 16px;
            color: white;
            background-color: #007BFF;
            border: none;
            padding: 10px;
            margin-top: 15px;
        """)
        self.report_button.clicked.connect(self.open_pdf_report)
        self.report_button.setVisible(False)  # Hide until a report is generated
        main_layout.addWidget(self.report_button, alignment=Qt.AlignCenter)

        # Add progress bar for scan status
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #30B2BA;
                border-radius: 5px;
                text-align: center;
                background-color: #1e1e1e;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #0de8f2;
            }
        """)
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # Progress status label
        self.progress_label = QLabel()
        self.progress_label.setStyleSheet("color: #0de8f2; font-size: 14px;")
        self.progress_label.setAlignment(Qt.AlignCenter)
        self.progress_label.setVisible(False)
        main_layout.addWidget(self.progress_label)

        scan_widget.setLayout(main_layout)
        self.stacked_widget.addWidget(scan_widget)

    def open_pdf_report(self):
        """Open the PDF report if it exists"""
        if not hasattr(self, 'pdf_report_path') or not self.pdf_report_path:
            # Try to find the most recent report
            output_dir = getattr(cve_checker_test, 'OUTPUT_DIR', 'reports')

            # Ensure the path is absolute
            if not os.path.isabs(output_dir):
                backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend'))
                output_dir = os.path.join(backend_dir, output_dir)

            # Look for any PDF files
            pdf_files = []
            try:
                for file in os.listdir(output_dir):
                    if file.lower().endswith('.pdf') and file.startswith("cybervault-report-"):
                        pdf_files.append(os.path.join(output_dir, file))
            except Exception as e:
                print(f"Error listing reports directory: {e}")

            # Sort by modification time (newest first)
            if pdf_files:
                pdf_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                self.pdf_report_path = pdf_files[0]
            else:
                QMessageBox.information(self, "Report Not Available",
                                        "No PDF reports were found. Please run a scan first.")
                return

        # Now we have a report path, try to open it
        if os.path.exists(self.pdf_report_path):
            try:
                print(f"Opening PDF report: {self.pdf_report_path}")

                # Use the default system PDF viewer to open the report
                if sys.platform == "win32":
                    os.startfile(self.pdf_report_path)
                elif sys.platform == "darwin":  # macOS
                    subprocess.run(["open", self.pdf_report_path])
                else:  # Linux
                    subprocess.run(["xdg-open", self.pdf_report_path])

            except Exception as e:
                QMessageBox.warning(self, "Error Opening Report",
                                    f"Could not open the PDF report:\n\n{str(e)}")
        else:
            QMessageBox.information(self, "Report Not Available",
                                    "The PDF report file doesn't exist. Please run a scan first.")

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
        """Unified scanning function that uses the same data for both PDF and UI"""
        # Show progress bar and set initial state
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.progress_label.setText("Preparing scan...")
        self.progress_label.setVisible(True)
        self.report_button.setVisible(False)

        # Force UI update
        QApplication.processEvents()

        try:
            # Update progress - Initializing
            self.progress_bar.setValue(10)
            self.progress_label.setText("Initializing scan...")
            QApplication.processEvents()

            # First, let's modify the cve_checker_test.match_installed_software function to return more data
            # We need to store the original function
            original_match_installed_software = cve_checker_test.match_installed_software

            # Now let's create a wrapper function to capture the data we need
            def match_with_data_collection():
                # To store the data we collect during the scan
                scan_data = {
                    'grouped': {},  # Vulnerable software
                    'severity_data': {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0, "Unknown": 0},
                }

                # Store the original insert_cve function
                original_insert_cve = cve_checker_test.insert_cve

                # Create a wrapper to track vulnerabilities as they're found
                def insert_cve_wrapper(conn, cve_id, vendor, product, version_start, version_end, description,
                                       published_date, cvss_score):
                    # Call the original function
                    result = original_insert_cve(conn, cve_id, vendor, product, version_start, version_end, description,
                                                 published_date, cvss_score)

                    # We don't need to track the database insertions, so we return the result
                    return result

                # We can't easily intercept match_installed_software's processing, so we'll use
                # a different approach - we'll let the function run normally and then extract data from
                # the database after it's done but before we disconnect

                # Run the original function to get the PDF path
                pdf_path = original_match_installed_software()

                # Capture the data we need here
                # Get the installed programs
                programs = cve_checker_test.get_installed_programs()

                # Open the database connection
                conn = sqlite3.connect(cve_checker_test.DB_FILE)
                c = conn.cursor()

                # Same logic as in the original scanning function
                from packaging.version import parse as parse_version

                for name, version in programs:
                    if not isinstance(name, str) or not isinstance(version, str):
                        continue

                    try:
                        # Try to parse the version
                        installed_version = parse_version(str(version))
                    except Exception:
                        continue

                    # Try to match with broader terms for better results
                    name_terms = name.split()
                    if not name_terms:
                        continue

                    # Try with first word and then with multiple words for better matching
                    search_terms = [name_terms[0]]
                    if len(name_terms) > 1:
                        search_terms.append(f"{name_terms[0]} {name_terms[1]}")

                    # Add common software names that might be referenced differently in CVEs
                    if "chrome" in name.lower():
                        search_terms.append("chromium")
                    elif "microsoft" in name.lower():
                        for term in ["office", "excel", "word", "powerpoint", "outlook"]:
                            if term in name.lower():
                                search_terms.append(term)
                    elif "adobe" in name.lower():
                        for term in ["reader", "acrobat", "flash"]:
                            if term in name.lower():
                                search_terms.append(term)

                    for term in search_terms:
                        like_name = f"%{term.lower()}%"
                        c.execute('''
                                  SELECT id, cvss_score, version_start, version_end, description
                                  FROM cves
                                  WHERE product LIKE ?
                                     OR vendor LIKE ?
                                  ''', (like_name, like_name))

                        results = c.fetchall()

                        for cve_id, cvss_score, version_start, version_end, description in results:
                            try:
                                if version_start:
                                    version_start = str(version_start).strip()
                                if version_end:
                                    version_end = str(version_end).strip()

                                # Check version constraints
                                version_match = True
                                if version_start and version_end:
                                    version_match = parse_version(version_start) <= installed_version <= parse_version(
                                        version_end)
                                elif version_start:
                                    version_match = installed_version >= parse_version(version_start)
                                elif version_end:
                                    version_match = installed_version <= parse_version(version_end)

                                # Only count vulnerabilities if the version actually matches
                                if version_match:
                                    # Add to our grouped results
                                    if (name, version) not in scan_data['grouped']:
                                        scan_data['grouped'][(name, version)] = []

                                    scan_data['grouped'][(name, version)].append((cve_id, cvss_score, description))

                                    # Count by severity
                                    severity = classify_cvss(cvss_score)
                                    scan_data['severity_data'][severity] += 1
                            except Exception as e:
                                continue

                conn.close()

                # Store system information
                scan_data['os_platform'] = system_info.get_OS_platform()
                scan_data['os_version'] = system_info.get_OS_version()
                scan_data['programs'] = programs

                # Return both the PDF path and our collected data
                return pdf_path, scan_data

            # Update progress - Scanning system
            self.progress_bar.setValue(30)
            self.progress_label.setText("Scanning system for installed software...")
            QApplication.processEvents()

            # Run our enhanced scanning function
            pdf_path, scan_data = match_with_data_collection()

            # Extract data from the scan results
            severity_data = scan_data['severity_data']
            grouped = scan_data['grouped']
            programs = scan_data['programs']
            os_platform = scan_data['os_platform']
            os_version = scan_data['os_version']

            # Store the PDF path for later use
            self.pdf_report_path = pdf_path

            # Build system info text with the collected data
            self.progress_bar.setValue(80)
            self.progress_label.setText("Preparing results...")
            QApplication.processEvents()

            system_info_text = f"Operating System: {os_platform}\n"
            system_info_text += f"OS Version: {os_version}\n\n"

            # Add information about vulnerable software
            system_info_text += f"Total Programs Scanned: {len(programs)}\n"
            system_info_text += f"Programs with Vulnerabilities: {len(grouped)}\n\n"

            # Add details about vulnerable programs
            if grouped:
                system_info_text += "Vulnerable Programs:\n"
                for i, ((name, version), cves) in enumerate(list(grouped.items())[:10]):  # Show first 10
                    system_info_text += f"{i + 1}. {name} (version: {version}) - {len(cves)} vulnerabilities\n"

                if len(grouped) > 10:
                    system_info_text += f"\n...and {len(grouped) - 10} more.\n"
            else:
                system_info_text += "No vulnerabilities were found in your installed software.\n"
                system_info_text += "This is good news! Keep your software updated to maintain security.\n"

            # Update progress - Completing
            self.progress_bar.setValue(90)
            self.progress_label.setText("Generating report...")
            QApplication.processEvents()

            # Add timestamp
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.timestamp_label.setText(f"Scan completed: {current_time}")

            # Update the pie chart with real data
            try:
                self.pie_chart.update_chart(severity_data)
            except Exception as e:
                print(f"Error updating chart: {e}")

            # Format and display the severity list with colored labels
            try:
                severity_html = "<style>table {width: 100%;} td {padding: 5px;}</style>"
                severity_html += "<table border='0'>"

                colors = {
                    "Critical": "red",
                    "High": "orange",
                    "Medium": "gold",
                    "Low": "lightgreen",
                    "None": "gray",
                    "Unknown": "darkgray"
                }

                total_issues = sum(severity_data.values())

                if total_issues > 0:
                    severity_html += f"<tr><td colspan='3'><b>Total Vulnerabilities Found: {total_issues}</b></td></tr>"
                    severity_html += "<tr><td colspan='3'><hr></td></tr>"  # Horizontal line

                    # Sort by severity level
                    severity_order = ["Critical", "High", "Medium", "Low", "None", "Unknown"]
                    for severity in severity_order:
                        count = severity_data.get(severity, 0)
                        if count > 0:
                            percentage = (count / total_issues) * 100
                            color_box = f"<div style='width: 15px; height: 15px; background-color: {colors[severity]}; display: inline-block; margin-right: 5px;'></div>"
                            severity_html += f"<tr><td>{color_box} {severity}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>"

                    severity_html += "</table>"

                    # Add recommendations based on severity
                    if severity_data.get("Critical", 0) > 0:
                        severity_html += "<p><b>Recommendation:</b> <span style='color: red;'>Critical vulnerabilities detected! Immediate action required.</span></p>"
                    elif severity_data.get("High", 0) > 0:
                        severity_html += "<p><b>Recommendation:</b> <span style='color: orange;'>High risk vulnerabilities found. Remediation advised within 7 days.</span></p>"
                    else:
                        severity_html += "<p><b>Recommendation:</b> <span style='color: lightgreen;'>System security is in good standing. Continue regular monitoring.</span></p>"
                else:
                    severity_html += "<tr><td colspan='3'><b>No Vulnerabilities Found</b></td></tr>"
                    severity_html += "</table>"
                    severity_html += "<p><b>Recommendation:</b> <span style='color: lightgreen;'>Your system appears secure. Continue regular updates and monitoring.</span></p>"

                self.severity_list.setHtml(severity_html)

            except Exception as e:
                self.severity_list.setText(f"Error displaying severity data: {str(e)}")

            # Set the result text
            self.result_text.setText(system_info_text)

            # Hide progress indicators
            self.progress_bar.setVisible(False)
            self.progress_label.setVisible(False)

            # Show PDF button if we have a report
            if pdf_path and os.path.exists(pdf_path):
                self.report_button.setVisible(True)
                # Log the path for debugging
                print(f"PDF report available at: {pdf_path}")

            # Update the reports list to include the new report
            self.update_reports_list()

            # Navigate to the scanning results page
            self.show_scanning_results_page()

        except Exception as e:
            # Handle unexpected errors
            self.progress_bar.setVisible(False)
            self.progress_label.setVisible(False)
            self.result_text.setText(f"Scan Error: {str(e)}")
            self.severity_list.setText("Scan failed. Please try again.")

            # Show error dialog
            QMessageBox.critical(self, "Scan Error", f"An error occurred during the scan:\n\n{str(e)}")
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
    window.resize(1200, 800)
    window.show()  # Must be shown first
    sys.exit(app.exec_())