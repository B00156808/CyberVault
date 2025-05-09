"""
Status bar component for CyberVault.
Displays connection status and application information.
"""
from PyQt5.QtWidgets import QStatusBar, QLabel, QWidget
from PyQt5.QtGui import QPainter, QColor, QBrush, QPen


class ConnectionStatusIndicator(QWidget):
    """Widget that indicates connection status with a colored dot."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(16, 16)
        self.connected = True

    def set_connected(self, connected):
        """Set the connection status."""
        if self.connected != connected:
            self.connected = connected
            self.update()  # Trigger repaint

    def paintEvent(self, event):
        """Paint the status indicator as a colored circle."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Choose color based on connection status
        if self.connected:
            color = QColor(0, 230, 0)  # Green for connected
        else:
            color = QColor(255, 0, 0)  # Red for disconnected

        # Draw colored circle
        painter.setPen(QPen(color.darker(120), 1))
        painter.setBrush(QBrush(color))
        painter.drawEllipse(3, 3, 10, 10)


class StatusBar(QStatusBar):
    """Status bar showing connection status and application info."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        """Initialize the UI components."""
        # Set status bar properties
        self.setStyleSheet("""
            QStatusBar {
                background-color: #1a1a1a;
                color: white;
                border-top: 1px solid #333;
            }
        """)

        # Create status indicator
        self.connection_indicator = ConnectionStatusIndicator()

        # Create status label
        self.connection_label = QLabel("Connected")
        self.connection_label.setStyleSheet("color: white; font-size: 12px;")

        # Create version label
        version_label = QLabel("CyberVault v1.0.0")
        version_label.setStyleSheet("color: #888; font-size: 11px;")

        # Add widgets to status bar
        self.addWidget(self.connection_indicator)
        self.addWidget(self.connection_label)
        self.addPermanentWidget(version_label)

    def update_connection_status(self, connected):
        """Update the connection status display."""
        self.connection_indicator.set_connected(connected)

        if connected:
            self.connection_label.setText("Connected")
            self.connection_label.setStyleSheet("color: white; font-size: 12px;")
        else:
            self.connection_label.setText("Disconnected")
            self.connection_label.setStyleSheet("color: #ff5555; font-size: 12px;")