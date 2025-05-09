"""
Connection overlay component for CyberVault.
Displays when internet connection is lost.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton,
    QHBoxLayout, QFrame, QSizePolicy
)
from PyQt5.QtCore import Qt, QTimer



class ConnectionOverlay(QWidget):
    """Overlay widget displayed when internet connection is lost."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.retry_timer = None
        self.retry_count = 0
        self.initUI()

    def initUI(self):
        """Initialize the UI components."""
        # Set up the overlay properties
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Semi-transparent background
        self.setStyleSheet("""
            ConnectionOverlay {
                background-color: rgba(13, 13, 13, 0.9);
                border-radius: 10px;
            }
        """)

        # Main layout
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignCenter)

        # Warning icon/animation can be added here

        # Create message panel
        message_panel = QFrame()
        message_panel.setStyleSheet("""
            QFrame {
                background-color: rgba(30, 30, 30, 0.8);
                border-radius: 8px;
                padding: 20px;
            }
        """)

        panel_layout = QVBoxLayout(message_panel)
        panel_layout.setSpacing(15)

        # Title
        title_label = QLabel("No Internet Connection")
        title_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ff5555;
        """)
        title_label.setAlignment(Qt.AlignCenter)
        panel_layout.addWidget(title_label)

        # Description
        desc_label = QLabel(
            "CyberVault requires an internet connection to function properly. "
            "Please check your network settings and try again."
        )
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("""
            font-size: 14px;
            color: white;
            line-height: 150%;
        """)
        desc_label.setAlignment(Qt.AlignCenter)
        panel_layout.addWidget(desc_label)

        # Status message for retry attempts
        self.status_label = QLabel("Checking connection...")
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("""
            font-size: 12px;
            color: #aaaaaa;
        """)
        self.status_label.setAlignment(Qt.AlignCenter)
        panel_layout.addWidget(self.status_label)

        # Buttons layout
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)

        # Check again button
        self.check_button = QPushButton("Check Again")
        self.check_button.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                font-weight: bold;
                color: white;
                background-color: #0de8f2;
                border: none;
                border-radius: 4px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #0bcad3;
            }
            QPushButton:pressed {
                background-color: #09acb4;
            }
        """)
        self.check_button.clicked.connect(self.retry_connection)
        buttons_layout.addWidget(self.check_button)

        # Exit button
        exit_button = QPushButton("Exit App")
        exit_button.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                color: white;
                background-color: #444444;
                border: none;
                border-radius: 4px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #555555;
            }
            QPushButton:pressed {
                background-color: #666666;
            }
        """)
        exit_button.clicked.connect(lambda: exit(0))
        buttons_layout.addWidget(exit_button)

        panel_layout.addLayout(buttons_layout)

        # Add message panel to main layout
        layout.addWidget(message_panel)

        self.setLayout(layout)

    def retry_connection(self):
        """Try to check internet connection again."""
        from ..utils.network_utils import check_internet_connection

        self.check_button.setEnabled(False)
        self.status_label.setText("Checking connection...")
        self.retry_count += 1

        # Check connection
        is_connected = check_internet_connection()

        if is_connected:
            self.status_label.setText("Connection restored! Refreshing...")
            self.status_label.setStyleSheet("font-size: 12px; color: #00ff00;")
            QTimer.singleShot(2000, self.hide)
            self.parent().refresh_application()
        else:
            if self.retry_count >= 3:
                self.status_label.setText(
                    "Multiple connection attempts failed. Please check your network settings "
                    "or try again later."
                )
            else:
                self.status_label.setText(
                    f"Connection attempt failed. Will try again automatically in 10 seconds. "
                    f"(Attempt {self.retry_count}/3)"
                )

                # Start automatic retry timer
                if self.retry_timer is None:
                    self.retry_timer = QTimer(self)
                    self.retry_timer.timeout.connect(self.retry_connection)

                self.retry_timer.start(10000)  # 10 seconds

            self.check_button.setEnabled(True)

    def showEvent(self, event):
        """Reset state when overlay is shown."""
        super().showEvent(event)
        self.retry_count = 0
        self.check_button.setEnabled(True)
        self.status_label.setText("Checking connection...")
        self.status_label.setStyleSheet("font-size: 12px; color: #aaaaaa;")

        # Stop any existing timer
        if self.retry_timer and self.retry_timer.isActive():
            self.retry_timer.stop()

        # Start initial retry timer
        if self.retry_timer is None:
            self.retry_timer = QTimer(self)
            self.retry_timer.timeout.connect(self.retry_connection)

        self.retry_timer.start(5000)  # 5 seconds for first check

    def hideEvent(self, event):
        """Clean up when overlay is hidden."""
        super().hideEvent(event)
        # Stop the retry timer
        if self.retry_timer and self.retry_timer.isActive():
            self.retry_timer.stop()