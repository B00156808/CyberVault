import os
import sys
import subprocess
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTextEdit, QProgressBar, QMessageBox
)
from PyQt5.QtCore import Qt
from ..utils.chart_utils import VulnerabilityPieChart
from src.config.constants import SEVERITY_COLORS_UI

# Import reports directory from settings
from src.config.settings import REPORTS_DIR



class ScanResultsPage(QWidget):
    """Page displaying vulnerability scan results."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.pdf_report_path = None
        self.initUI()

    def initUI(self):
        """Initialize the UI components."""
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

        self.setLayout(main_layout)

    def set_pdf_report_path(self, path):
        """Set the path to the PDF report."""
        self.pdf_report_path = path
        self.report_button.setVisible(True if path and os.path.exists(path) else False)

    def open_pdf_report(self):
        """Open the PDF report if it exists."""

        if not hasattr(self, 'pdf_report_path') or not self.pdf_report_path:
            # Try to find the most recent report
            output_dir = REPORTS_DIR  # Use the path from settings

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
                os.startfile(self.pdf_report_path)

            except Exception as e:
                QMessageBox.warning(self, "Error Opening Report",
                                    f"Could not open the PDF report:\n\n{str(e)}")
        else:
            QMessageBox.information(self, "Report Not Available",
                                    "The PDF report file doesn't exist. Please run a scan first.")


    def update_results(self, scan_data):
        """Update the results display with scan data."""
        from datetime import datetime
        from collections import Counter

        # Extract data
        severity_data = scan_data['severity_totals']
        grouped = scan_data['grouped']
        programs = scan_data['programs']

        # Update timestamp
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.timestamp_label.setText(f"Scan completed: {current_time}")

        # Update pie chart
        try:
            self.pie_chart.update_chart(severity_data)
        except Exception as e:
            print(f"Error updating chart: {e}")

        # Format and display the severity list with colored labels
        try:
            severity_html = "<style>table {width: 100%;} td {padding: 5px;}</style>"
            severity_html += "<table border='0'>"

            colors = SEVERITY_COLORS_UI

            total_issues = sum(severity_data.values())

            if total_issues > 0:
                severity_html += f"<tr><td colspan='3'><b>Total Vulnerabilities Found: {total_issues}</b></td></tr>"
                severity_html += "<tr><td colspan='3'><hr></td></tr>"  # Horizontal line

                # Sort by severity level
                severity_order = ["Critical", "High", "Medium", "Low", "None"]
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

        # Build system info text
        try:
            # Get system info
            import platform
            os_platform = platform.system()
            os_version = platform.version()

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

            self.result_text.setText(system_info_text)
        except Exception as e:
            self.result_text.setText(f"Error displaying system information: {str(e)}")

        # Hide progress indicators
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)

        # Show PDF button if we have a report
        self.report_button.setVisible(True)

    def show_progress(self, value, message):
        """Update the progress bar and status message."""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)