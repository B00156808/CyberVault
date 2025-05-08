"""
Backend package for CyberVault.
Contains modules for vulnerability scanning, database management, and report generation.
"""

# You can optionally expose key functions at the package level
from .cve_checker import run_scan
from .cve_checker import run_scan
from .scanner import classify_cvss