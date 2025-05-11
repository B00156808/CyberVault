"""
Constants used throughout the CyberVault application.
"""

# Severity classification thresholds
SEVERITY_THRESHOLDS = {
    "Critical": 9.0,
    "High": 7.0,
    "Medium": 4.0,
    "Low": 0.1,
    "None": 0.0,
}

# Severity colors for UI
SEVERITY_COLORS_UI = {
    "Critical": "red",
    "High": "orange",
    "Medium": "gold",
    "Low": "lightgreen",
    "None": "gray",
}

# Severity colors for reports (using reportlab color objects)
# This will be imported where needed
# from reportlab.lib import colors
# SEVERITY_COLORS_REPORT = {
#    "Critical": colors.red,
#    "High": colors.orangered,
#    "Medium": colors.orange,
#    "Low": colors.yellow,
#    "None": colors.lightgrey,
#    "Unknown": colors.grey
# }

# Severity colors for matplotlib
SEVERITY_COLORS_CHART = {
    "Critical": "red",
    "High": "orange",
    "Medium": "gold",
    "Low": "lightgreen",
    "None": "gray",
}

# Recommended actions based on severity
SEVERITY_ACTIONS = {
    "Critical": "Update immediately or uninstall",
    "High": "Update as soon as possible",
    "Medium": "Consider updating in the next maintenance cycle",
    "Low": "Optional update at your convenience",
    "None": "No action required",
}