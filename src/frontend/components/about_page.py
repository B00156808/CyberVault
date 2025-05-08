from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt5.QtCore import Qt


class AboutPage(QWidget):
    """About page with information about the application."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        """Initialize the UI components."""
        layout = QVBoxLayout()

        label = QLabel("About CyberVault")
        label.setStyleSheet("font-size: 24px; font-weight: bold; color: #0de8f2;")

        description = QLabel(
            "CyberVault is a powerful tool for scanning your system for security vulnerabilities "
            "and keeping you updated with the latest in cybersecurity news and best practices."
        )
        description.setWordWrap(True)
        description.setStyleSheet("font-size: 16px; color: white;")

        features = QLabel(
            "<b>Key Features:</b><br>"
            "• Scans installed software for known security vulnerabilities (CVEs)<br>"
            "• Generates detailed PDF reports with severity classifications<br>"
            "• Provides actionable recommendations to improve security<br>"
            "• Displays the latest cybersecurity news and trends<br>"
            "• User-friendly interface with interactive charts"
        )
        features.setTextFormat(Qt.RichText)
        features.setWordWrap(True)
        features.setStyleSheet("font-size: 14px; color: white; margin-top: 20px;")

        credits = QLabel(
            "Developed by: Marlon Marishta and Luke Pettigrew<br>"
            "Version: 1.0<br>"
            "<br>"
            "This software uses data from the National Vulnerability Database (NVD)"
        )
        credits.setTextFormat(Qt.RichText)
        credits.setWordWrap(True)
        credits.setStyleSheet("font-size: 14px; color: white; margin-top: 30px;")

        layout.addWidget(label)
        layout.addWidget(description)
        layout.addWidget(features)
        layout.addWidget(credits)
        layout.addStretch()

        layout.setAlignment(Qt.AlignTop)
        self.setLayout(layout)