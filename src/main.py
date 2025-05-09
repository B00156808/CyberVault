#!/usr/bin/env python3
"""
CyberVault - A cybersecurity vulnerability scanner
Main entry point for the application
"""

import os
import sys

# Add the project root to the path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Import required modules
from PyQt5.QtWidgets import QApplication, QSplashScreen, QMessageBox
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QFont
from src.frontend.app import App
from src.config.settings import API_KEY
from src.frontend.utils.network_utils import check_internet_connection


def ensure_directories():
    """Ensure required directories exist."""
    directories = [
        "data",
        "reports",
        os.path.join("resources", "images")
    ]

    for directory in directories:
        full_path = os.path.join(project_root, directory)
        if not os.path.exists(full_path):
            os.makedirs(full_path)
            print(f"Created directory: {full_path}")


def main():
    """Main function to run the application."""
    # Ensure required directories exist
    ensure_directories()

    # Create the Qt application
    app = QApplication(sys.argv)

    # Create and show splash screen
    splash_pixmap = QPixmap(500, 300)
    splash_pixmap.fill(Qt.black)
    splash = QSplashScreen(splash_pixmap, Qt.WindowStaysOnTopHint)
    splash.setStyleSheet("background-color: #0d0d0d; color: white;")

    # Set splash screen font
    font = QFont()
    font.setPointSize(12)
    splash.setFont(font)

    # Show the splash screen
    splash.show()
    app.processEvents()

    # Update splash screen with connection check
    splash.showMessage("Checking internet connection...",
                       alignment=Qt.AlignBottom | Qt.AlignCenter,
                       color=Qt.white)
    app.processEvents()

    # Check for internet connection
    if not check_internet_connection():
        splash.close()
        # Create a message box with dark styling
        msg_box = QMessageBox()
        msg_box.setWindowTitle("CyberVault - No Internet Connection")
        msg_box.setText("CyberVault requires an internet connection to function properly.")
        msg_box.setInformativeText("Please check your network connection and try again.")
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setStandardButtons(QMessageBox.Retry | QMessageBox.Cancel)
        msg_box.setDefaultButton(QMessageBox.Retry)
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #1a1a1a;
                color: white;
            }
            QLabel {
                color: white;
            }
            QPushButton {
                background-color: #333;
                color: white;
                padding: 5px 15px;
                border: none;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)

        # Show the message box and handle response
        response = msg_box.exec_()

        if response == QMessageBox.Retry:
            # Try again - restart the application
            python = sys.executable
            os.execl(python, python, *sys.argv)
        else:
            # User clicked Cancel, exit the application
            sys.exit(0)

    # Update splash message to "Loading application..."
    splash.showMessage("Loading application...",
                       alignment=Qt.AlignBottom | Qt.AlignCenter,
                       color=Qt.white)
    app.processEvents()

    # Create and set up the main window
    # Note: Using App for backward compatibility (it extends MainWindow)
    window = App(API_KEY)
    window.resize(1200, 800)

    # Close splash screen and show the main window
    splash.finish(window)
    window.show()

    # Run the application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()