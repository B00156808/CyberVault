"""
Configuration package for CyberVault.
Contains application settings and constants.
"""

# Expose key settings at the package level for easier imports
from .settings import (
    API_KEY,
    DB_FILE,
    DB_DOWNLOAD_URL,
    REPORTS_DIR,
    DATA_DIR,

)


# Expose severity constants
from .constants import (
    SEVERITY_THRESHOLDS,
    SEVERITY_COLORS_UI,
    SEVERITY_COLORS_CHART,
    SEVERITY_ACTIONS
)