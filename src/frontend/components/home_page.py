import os
import re
import webbrowser
from PyQt5.QtWidgets import (
    QPushButton, QListWidget, QListWidgetItem,
    QTextEdit, QFrame
)
from PyQt5.QtWidgets import QMessageBox
from datetime import datetime
from ..utils.news_utils import get_cybersecurity_news
from ...config.settings import REPORTS_DIR
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QSizePolicy
from PyQt5.QtCore import Qt, QSize

class HomePage(QWidget):
    """Home page of the CyberVault application."""

    def __init__(self, api_key, parent=None):
        super().__init__(parent)
        self.api_key = api_key
        self.home_news_articles = []
        self.available_reports = []
        self.initUI()

    def initUI(self):
        """Initialize the UI components."""
        home_layout = QHBoxLayout()

        # Left: News Preview
        self.left_layout = QVBoxLayout()
        news_label = QLabel("Cyber News Preview")
        news_label.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #0de8f2;
        """)

        self.home_news_list = QListWidget()
        self.home_news_list.setStyleSheet("""
            QListWidget {
                background-color: #121212;
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
        self.home_news_list.itemClicked.connect(self.open_home_news_link)

        # Container for the preview and scan results
        left_container = QVBoxLayout()
        left_container.addWidget(news_label)

        # Top: News list (takes 3/4 of space)
        left_container.addWidget(self.home_news_list, stretch=3)

        # Bottom: Scan results viewer (1/4 of space) - used for PDF reports
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

        # Reports header
        reports_label = QLabel("Recent Reports")
        reports_label.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #0de8f2;
            margin-top: 10px;
        """)

        left_container.addWidget(reports_label)
        left_container.addWidget(self.scan_results_box, stretch=1)
        self.left_layout.addLayout(left_container)

        # Right: Welcome and Scan
        self.right_layout = QVBoxLayout()

        # Add the layouts to the main layout
        home_layout.addLayout(self.left_layout, 1)
        home_layout.addLayout(self.right_layout, 3)

        self.setLayout(home_layout)

        # Call the enhanced welcome section
        self.welcome_section()

        # Load news and reports
        self.load_news_preview()
        self.update_reports_list()

    def welcome_section(self):
        """Welcome and scan section."""

        container = QFrame()
        container.setStyleSheet("""
            background-color: transparent;
        """)

        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(40, 60, 40, 60)
        main_layout.setSpacing(30)


        title = QLabel("CVE SCANNER")
        title.setStyleSheet("""
            font-size: 38px;
            font-weight: 700;
            letter-spacing: 4px;
            color: #0de8f2;
        """)
        title.setAlignment(Qt.AlignCenter)


        subtitle = QLabel("Vulnerability Scanner by CyberVault")
        subtitle.setStyleSheet("""
            font-size: 16px;
            color: #888888;
            letter-spacing: 1px;
        """)
        subtitle.setAlignment(Qt.AlignCenter)

        # Add horizontal rule
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setStyleSheet("""
            background-color: #333333;
            max-height: 1px;
        """)

        self.scan_button = QPushButton("SCAN SYSTEM")
        self.scan_button.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                font-weight: 600;
                letter-spacing: 2px;
                color: #000000;
                background-color: #0de8f2;
                border: none;
                border-radius: 4px;
                padding: 18px 36px;
                margin: 20px 40px;
            }
            QPushButton:hover {
                background-color: #ffffff;
            }
        """)
        self.scan_button.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Fixed)


        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(24)


        for value, label in [
            ("SCAN", "TO FIND VULNERABILITIES"),
            ("ANALYZE", "TO FIND SEVERITY"),
            ("ACT", "TO PREVENT ATTACKS")
        ]:
            # Vertical container
            stat_container = QVBoxLayout()
            stat_container.setSpacing(4)

            # Large statistic value
            value_label = QLabel(value)
            value_label.setStyleSheet("""
                font-size: 16px;
                font-weight: 600;
                color: #ffffff;
            """)
            value_label.setAlignment(Qt.AlignCenter)

            # Small label
            desc_label = QLabel(label)
            desc_label.setStyleSheet("""
                font-size: 9px;
                color: #666666;
                letter-spacing: 1px;
            """)
            desc_label.setAlignment(Qt.AlignCenter)

            # Add to container
            stat_container.addWidget(value_label)
            stat_container.addWidget(desc_label)

            # Add to horizontal layout
            stats_layout.addLayout(stat_container)

        # Build the layout from top to bottom
        main_layout.addStretch()
        main_layout.addWidget(title, 0, Qt.AlignCenter)
        main_layout.addWidget(subtitle, 0, Qt.AlignCenter)
        main_layout.addWidget(separator)
        main_layout.addWidget(self.scan_button, 0, Qt.AlignCenter)
        main_layout.addStretch()
        main_layout.addLayout(stats_layout)

        # Add the container to the right layout
        self.right_layout.addWidget(container)

        # button hover
        def on_button_hover():
            self.scan_button.setStyleSheet("""
                font-size: 16px;
                font-weight: 600;
                letter-spacing: 2px;
                color: #000000;
                background-color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 18px 36px;
                margin: 20px 40px;
            """)

        def on_button_leave():
            self.scan_button.setStyleSheet("""
                font-size: 16px;
                font-weight: 600;
                letter-spacing: 2px;
                color: #000000;
                background-color: #0de8f2;
                border: none;
                border-radius: 4px;
                padding: 18px 36px;
                margin: 20px 40px;
            """)

        self.scan_button.enterEvent = lambda e: on_button_hover()
        self.scan_button.leaveEvent = lambda e: on_button_leave()

    def load_news_preview(self):
        """Load news preview."""

        # Clear the existing content
        self.home_news_list.clear()

        # Get news articles
        self.home_news_articles = get_cybersecurity_news(self.api_key)

        # If no articles returned, use fallback content
        if not self.home_news_articles:
            print("No articles returned, using fallback content")
            from ..utils.news_utils import get_fallback_cybersecurity_news
            self.home_news_articles = get_fallback_cybersecurity_news()
            # Limit to 5 items for the home page preview
            if len(self.home_news_articles) > 5:
                self.home_news_articles = self.home_news_articles[:5]

        # Calculate available width - get the actual visible width of the list widget
        list_width = self.home_news_list.viewport().width()
        content_width = max(150, list_width - 20)
        print(f"Available width for news content: {content_width}px")

        # Apply a better style to the list widget with no horizontal scrollbar
        self.home_news_list.setStyleSheet("""
            QListWidget {
                background-color: #121212;
                border: none;
                border-radius: 8px;
                padding: 0px;
            }
            QListWidget::item {
                background-color: #1a1a1a;
                border-radius: 4px;
                margin: 3px 3px;
                padding: 0px;
            }
            QListWidget::item:hover {
                background-color: #252525;
            }
            QListWidget::item:selected {
                background-color: #252525;
                border: 1px solid #0de8f2;
            }
            /* Hide horizontal scrollbar */
            QListWidget QScrollBar:horizontal {
                height: 0px;
            }
        """)

        # Disable horizontal scrollbar
        self.home_news_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # Force list widget to size its contents to fit the viewport width
        self.home_news_list.setResizeMode(QListWidget.Adjust)
        self.home_news_list.setTextElideMode(Qt.ElideRight)

        # Add articles
        for title, description, link, image_url in self.home_news_articles:
            # Create a custom widget
            article_widget = QWidget()
            article_layout = QVBoxLayout(article_widget)
            article_layout.setContentsMargins(6, 6, 6, 6)  # Minimal margins
            article_layout.setSpacing(2)  # Minimal spacing

            # Add a small tag at the top - Use different tags for different cybersecurity topics
            tag_text = "CYBERSECURITY"
            if "CISA" in title or "government" in description.lower():
                tag_text = "GOVERNMENT"
            elif "NIST" in title:
                tag_text = "STANDARDS"
            elif "OWASP" in title:
                tag_text = "WEB SECURITY"
            elif "CVE" in title:
                tag_text = "VULNERABILITIES"
            elif "SANS" in title:
                tag_text = "THREAT INTEL"
            elif "privacy" in title.lower() or "privacy" in description.lower():
                tag_text = "PRIVACY"

            tag_label = QLabel(tag_text)
            tag_label.setFixedWidth(content_width - 15)
            tag_label.setStyleSheet("""
                color: #0de8f2;
                font-size: 8px;
                font-weight: bold;
                background-color: rgba(13, 232, 242, 0.1);
                border-radius: 2px;
                padding: 1px 4px;
                max-width: 100px;
            """)
            article_layout.addWidget(tag_label, 0, Qt.AlignLeft)

            # Shorten title to fit
            short_title = title
            if len(short_title) > 50:
                short_title = short_title[:47] + "..."

            # Add title
            title_label = QLabel(short_title)
            title_label.setFixedWidth(content_width - 15)  # Constrain width
            title_label.setWordWrap(True)
            title_label.setStyleSheet("""
                font-size: 10px;
                font-weight: bold;
                color: white;
                margin-top: 2px;
            """)
            article_layout.addWidget(title_label)

            # Very short description
            short_desc = description
            if len(short_desc) > 40:
                short_desc = short_desc[:37] + "..."

            desc_label = QLabel(short_desc)
            desc_label.setFixedWidth(content_width - 15)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("""
                font-size: 9px;
                color: #aaaaaa;
            """)
            article_layout.addWidget(desc_label)

            # Add "Read article" link
            read_more_widget = QWidget()
            read_more_widget.setCursor(Qt.PointingHandCursor)
            read_more_widget.setProperty("link", link)

            read_more_layout = QHBoxLayout(read_more_widget)
            read_more_layout.setContentsMargins(0, 0, 0, 0)
            read_more_layout.setSpacing(1)

            read_more_label = QLabel("Read article →")
            read_more_label.setStyleSheet("""
                color: #0de8f2;
                font-size: 9px;
                font-weight: bold;
            """)
            read_more_layout.addWidget(read_more_label)
            read_more_layout.addStretch()

            # Add underline effect on hover
            read_more_widget.enterEvent = lambda e, w=read_more_label: w.setStyleSheet("""
                color: #0de8f2;
                font-size: 9px;
                font-weight: bold;
                text-decoration: underline;
            """)
            read_more_widget.leaveEvent = lambda e, w=read_more_label: w.setStyleSheet("""
                color: #0de8f2;
                font-size: 9px;
                font-weight: bold;
                text-decoration: none;
            """)

            # Connect click event to open link in new tab
            read_more_widget.mousePressEvent = lambda e, link=link: self.open_link_in_new_tab(link)

            article_layout.addWidget(read_more_widget)

            # Create the list item
            item = QListWidgetItem(self.home_news_list)

            # Set an appropriate fixed size
            item.setSizeHint(QSize(list_width - 10, 90))

            self.home_news_list.addItem(item)
            self.home_news_list.setItemWidget(item, article_widget)

        # Connect click event for the whole item
        self.home_news_list.itemClicked.connect(self.handle_news_item_click)

    def handle_news_item_click(self, item):
        """Handle click on a news item."""
        index = self.home_news_list.row(item)
        if 0 <= index < len(self.home_news_articles):
            self.open_link_in_new_tab(self.home_news_articles[index][2])

    def open_link_in_new_tab(self, url):
        """Open a link in a new browser tab."""
        import webbrowser
        webbrowser.open_new_tab(url)

    def open_home_news_link(self, item):
        """Open the news link when clicked."""
        index = self.home_news_list.row(item)
        if 0 <= index < len(self.home_news_articles):
            webbrowser.open(self.home_news_articles[index][2])

    def get_available_reports(self, output_dir=None):
        """Get a list of all available reports with timestamps"""


        # If no output directory is specified, use the one from settings
        if output_dir is None:
            output_dir = REPORTS_DIR

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

    def scan_results_box_clicked(self, event):
        """Handle double-clicks in the scan results box"""


        # Get the cursor position at the click location
        cursor = self.scan_results_box.cursorForPosition(event.pos())

        # Get the block of text that was clicked
        block = cursor.block().text().strip()

        print(f"Clicked on text: {block}")  # Debug info

        # Check if we clicked on a report line
        if "Report from" in block or "Generated at" in block:
            # Find which report this belongs to by counting blocks up to this point
            block_number = cursor.blockNumber()

            # Each report takes approximately 4 blocks (title, date, content, hr)
            # So we can estimate which report was clicked
            report_index = block_number // 4

            print(f"Estimated report index: {report_index}")

            # Make sure we have reports and the index is valid
            if hasattr(self, 'available_reports') and 0 <= report_index < len(self.available_reports):
                # Get the report path
                file_path = self.available_reports[report_index]['path']
                print(f"Opening report: {file_path}")  # Debug info

                # Check if the file exists
                if os.path.exists(file_path):
                    try:
                        os.startfile(file_path)
                    except Exception as e:
                        print(f"Error opening file: {e}")  # Debug info
                        QMessageBox.warning(self, "Error Opening Report",
                                            f"Could not open the report:\n\n{str(e)}")
                else:
                    print(f"File not found: {file_path}")  # Debug info
                    QMessageBox.information(self, "Report Not Available",
                                            "The report file could not be found.")

    def open_report_file(self, file_path):
        """Open a report file using the system's default PDF viewer."""
        if file_path and os.path.exists(file_path):
            try:
                os.startfile(file_path)
            except Exception as e:
                QMessageBox.warning(self, "Error Opening Report",
                                    f"Could not open the report:\n\n{str(e)}")
        else:
            QMessageBox.information(self, "Report Not Available",
                                    "The report file could not be found.")

    def update_reports_list(self):
        """Update the scan_results_box to show reports"""

        # Clear the existing content
        self.scan_results_box.clear()

        # Get all available reports
        reports = self.get_available_reports()

        # Store report paths for retrieval
        self.available_reports = reports

        # Create styled text for the header
        header_style = "color: white; font-size: 15px; font-weight: bold; margin-bottom: 10px;"
        instruction_style = "color: #888888; font-size: 11px; font-style: italic; margin-bottom: 15px;"
        no_reports_style = "color: #888888; font-size: 14px; text-align: center; margin-top: 20px;"

        # Add header
        self.scan_results_box.append(f"<div style='{header_style}'>Available Reports</div>")
        self.scan_results_box.append(f"<div style='{instruction_style}'>Double-click on a report to open it</div>")

        if reports:
            # For each report
            for i, report in enumerate(reports):
                timestamp = report['timestamp']
                date_part = timestamp.split(' ')[0]
                time_part = timestamp.split(' ')[1]

                # Create a complete report entry with both date and time in one div
                self.scan_results_box.append(f"""
                <div style='
                    padding: 8px 5px;
                    margin-bottom: 0px;
                '>
                    <div style='
                        color: white;
                        font-weight: bold;
                        font-size: 13px;
                        margin-bottom: 3px;
                    '>
                        📄 Report from {date_part}
                    </div>
                    <div style='
                        color: #aaaaaa;
                        font-size: 11px;
                    '>
                        Generated at {time_part}
                    </div>
                </div>
                """)

                # Only add a horizontal line if this is not the last report
                if i < len(reports) - 1:
                    self.scan_results_box.append(
                        "<hr style='border: 0; height: 1px; background-color: #333; margin: 5px 0 10px 0;'>")

        else:
            self.scan_results_box.append(f"<div style='{no_reports_style}'>No reports available yet.</div>")

        # Ensure clicking works by connecting the double click event
        self.scan_results_box.mouseDoubleClickEvent = self.scan_results_box_clicked