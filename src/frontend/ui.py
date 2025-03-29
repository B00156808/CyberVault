import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QTextEdit
from PyQt5.QtCore import Qt

# Import the system_info module from the backend directory
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

import system_info  # Now system_info.py can be imported

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Set up the window
        self.setWindowTitle('System Information Scanner')
        self.setGeometry(100, 100, 600, 400)

        # Create a button and connect it to the scan function
        self.scan_button = QPushButton('Scan', self)
        self.scan_button.clicked.connect(self.scan)

        # Create a text area to display results
        self.result_text = QTextEdit(self)
        self.result_text.setReadOnly(True)

        # Set up the layout
        layout = QVBoxLayout()
        layout.addWidget(self.scan_button)
        layout.addWidget(self.result_text)

        # Set the layout to the window
        self.setLayout(layout)

        # Apply CSS to the application window
        self.setStyleSheet("""
            body {
                font-family: system-ui, Avenir, Helvetica, Arial, sans-serif;
                line-height: 1.5;
                font-weight: 400;
                background-color: #242424;
                margin: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                color: rgba(255, 255, 255, 0.87);
            }

            QWidget {
                background-color: #242424;
            }

            h1 {
                font-size: 3.2em;
                line-height: 1.1;
                color: #ffffff;
            }

            QPushButton {
                padding: 0.6em 1.2em;
                font-size: 1em;
                font-weight: 500;
                background-color: #1a1a1a;
                color: #fff;
                border-radius: 8px;
                border: 1px solid transparent;
                cursor: pointer;
                transition: border-color 0.25s;
            }

            QPushButton:hover {
                border-color: #646cff;
            }

            QPushButton:focus,
            QPushButton:focus-visible {
                outline: 4px auto -webkit-focus-ring-color;
            }

            QTextEdit {
                font-size: 1em;
                font-weight: 400;
                color: rgba(255, 255, 255, 0.87);
                background-color: #333333;
                border: 1px solid #444444;
                border-radius: 8px;
                padding: 10px;
            }

            QTextEdit:focus {
                border-color: #646cff;
            }
        """)

    def scan(self):
        # Get system information by calling functions from system_info.py
        os_platform = system_info.get_OS_platform()
        os_version = system_info.get_OS_version()
        installed_programs = system_info.get_installed_programs()
        system_services = system_info.get_system_services()

        # Prepare the output to display in the text area
        result = f"Operating System: {os_platform}\n"
        result += f"OS Version: {os_version}\n\n"
        result += "Installed Programs:\n"
        if isinstance(installed_programs, list):
            for program in installed_programs:
                result += f"{program[0]} - {program[1]}\n"
        else:
            result += installed_programs + "\n"
        
        result += "\nSystem Services:\n"
        if isinstance(system_services, list):
            for service in system_services:
                result += f"{service[0]} - {service[1]} - {service[2]}\n"
        else:
            result += system_services + "\n"
        
        # Display the result in the text area
        self.result_text.setText(result)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec_())
