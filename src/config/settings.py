"""
Configuration settings for the application.
"""

import os
import sys
from datetime import datetime

def get_application_paths():
    """Get application paths based on whether we're running as executable or script."""
    # Check if we're running as a PyInstaller executable
    if getattr(sys, 'frozen', False):
        # We're running as an executable
        # Store both program data and reports in AppData\Local\CyberVault
        appdata_dir = os.path.join(os.environ['LOCALAPPDATA'], "CyberVault")

        # Create the directory if it doesn't exist
        if not os.path.exists(appdata_dir):
            os.makedirs(appdata_dir)
            print(f"Created CyberVault directory: {appdata_dir}")

        return {
            'DATA_DIR': os.path.join(appdata_dir, "data"),
            'REPORTS_DIR': os.path.join(appdata_dir, "reports"),
            'PROJECT_ROOT': appdata_dir,
            'SETTINGS_DIR': os.path.dirname(os.path.abspath(__file__))
        }
    else:
        settings_dir = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.dirname(settings_dir)
        project_root = os.path.dirname(src_dir)

        return {
            'DATA_DIR': os.path.join(project_root, "data"),
            'REPORTS_DIR': os.path.join(project_root, "reports"),
            'PROJECT_ROOT': project_root,
            'SETTINGS_DIR': settings_dir
        }

# Get the appropriate paths
paths = get_application_paths()
DATA_DIR = paths['DATA_DIR']
REPORTS_DIR = paths['REPORTS_DIR']
project_root = paths['PROJECT_ROOT']
settings_dir = paths['SETTINGS_DIR']

# Database settings
DB_FILE = os.path.join(DATA_DIR, "cves.db")
DB_DOWNLOAD_URL = "https://malice.games/cves.db"

# API settings
BASE_URL = "http://nvd.nist.gov/feeds/json/cve/1.1/"
YEARS = list(range(2002, datetime.now().year + 1))
MODIFIED_FEED = "nvdcve-1.1-modified.json.gz"

# News API
API_KEY = '971cf28df41c8a5d09151bb993dd8f19'  # GNews API key

# Debug print statements to verify paths
print("===== CyberVault Path Configuration =====")
print(f"Settings directory: {settings_dir}")
print(f"Project root: {project_root}")
print(f"Data directory: {DATA_DIR}")
print(f"Database path: {DB_FILE}")
print(f"Reports directory: {REPORTS_DIR}")
print("========================================")

# Ensure directories exist
for directory in [DATA_DIR, REPORTS_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")