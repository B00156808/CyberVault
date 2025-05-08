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
from PyQt5.QtWidgets import QApplication
from src.frontend.app import App
from src.config.settings import API_KEY


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

    # Create and run the Qt application
    app = QApplication(sys.argv)
    window = App(API_KEY)
    window.resize(1200, 800)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()