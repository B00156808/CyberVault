# CyberVault

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Overview

CyberVault is a user-friendly vulnerability scanner designed specifically for non-technical users. It scans Windows systems for installed software, identifies potential security vulnerabilities (CVEs), and presents the findings in an accessible format with clear recommendations for remediation. The application also includes cybersecurity news updates to keep users informed about the latest security trends and best practices.

## Features

- **Simple, Intuitive Interface**: Designed from the ground up for non-technical users with clear navigation and visual feedback
- **Comprehensive Software Detection**: Automatically scans the Windows Registry to identify installed applications
- **CVE Vulnerability Matching**: Identifies known vulnerabilities in detected software using the National Vulnerability Database
- **Severity Classification**: Visually represents vulnerability severity (Critical, High, Medium, Low) with color-coded indicators
- **Actionable Recommendations**: Provides clear guidance on how to address identified vulnerabilities
- **Detailed PDF Reports**: Generates comprehensive, non-technical reports explaining findings and recommended actions
- **Cybersecurity News Feed**: Displays the latest cybersecurity news and updates
- **Offline Database Support**: Functions without an internet connection using cached vulnerability data

## System Requirements

- Windows 10 or newer
- 4 GB RAM (minimum)
- 300 MB disk space for installation
- Internet connection  

## Installation

1. Download the latest release from the [Releases](https://github.com/B00156808/CyberVault/releases) page
2. Run the installer and follow the on-screen instructions
3. Launch CyberVault from the Start menu or desktop shortcut

## Usage

### Running a Vulnerability Scan

1. Launch CyberVault
2. Click the "SCAN SYSTEM" button on the home page
3. Wait for the scan to complete (typically 20-30 seconds)
4. Review the identified vulnerabilities organized by severity
5. Follow the recommended actions to address each vulnerability

### Viewing Reports

1. Navigate to the "Scanning Results" page
2. Click "Open PDF Report" to view the detailed report
3. Previous reports can be accessed from the home page under "Recent Reports"

### Staying Informed

1. Check the "Cyber News" page for the latest security updates and articles
2. Double-click any news item to open the full article in your browser

## Technical Architecture

CyberVault uses a modular architecture with three main components:

1. **Frontend**: PyQt5-based GUI with Matplotlib data visualizations
2. **Backend**: Windows Registry scanner, CVE matching engine, and ReportLab PDF generator
3. **Database**: Local SQLite database of Common Vulnerabilities and Exposures (CVEs) with remote update functionality

## Development

### Prerequisites

- Python 3.11 or newer
- Git
- PyQt5
- SQLite

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/cybervault.git
cd cybervault

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python src/main.py
```

### Project Structure
- `CyberVault/` - Project Folder
    - `resources/` - Resource Folder
      - `images/` - Images folder
        - `CyberVault.png` - Nav Bar Logo
        - `Logo.png` - Logo
        - `Logo.ico` - Logo icon
    - `src/` - Source code
      - `backend/` - Backend logic
        - `cve_checker.py` - Main scanning logic
        - `database.py` - Database management
        - `scanner.py` - System scanning functionality
        - `report_generation.py` - PDF report creation
      - `config/` - Configuration and constants
      - `frontend/` - User interface
        - `components/` - UI components
        - `utils/` - UI utilities
      - `main.py` - Application entry point

## Contributors

- Marlon Marishta
- Luke Pettigrew

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- National Vulnerability Database (NVD) for vulnerability data
- GNews API for cybersecurity news content
- PyQt5 for the GUI framework
- ReportLab for PDF generation
- Matplotlib for data visualization

## Contact

For questions, issues, or contributions, please open an issue on our GitHub repository or contact the project maintainers.