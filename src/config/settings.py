"""
Configuration settings for the CyberVault application.
"""

import os
from datetime import datetime

# Calculate paths relative to the settings.py file
settings_dir = os.path.dirname(os.path.abspath(__file__))  # config directory
src_dir = os.path.dirname(settings_dir)                   # src directory
project_root = os.path.dirname(src_dir)                   # project root

# Set up paths for data and reports in the project root
DATA_DIR = os.path.join(project_root, "data")
REPORTS_DIR = os.path.join(project_root, "reports")

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