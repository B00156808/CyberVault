import winreg
import sqlite3
from collections import defaultdict, Counter
from packaging.version import parse as parse_version
from subprocess import check_output, PIPE, STDOUT
from datetime import datetime

# Import from our own modules
from ..config.settings import DB_FILE
from ..config.constants import SEVERITY_THRESHOLDS

def classify_cvss(score):
    """Classify CVSS score into severity categories."""
    if score is None:
        return "Unknown"

    score = float(score)
    if score >= SEVERITY_THRESHOLDS["Critical"]:
        return "Critical"
    elif score >= SEVERITY_THRESHOLDS["High"]:
        return "High"
    elif score >= SEVERITY_THRESHOLDS["Medium"]:
        return "Medium"
    elif score >= SEVERITY_THRESHOLDS["Low"]:
        return "Low"
    else:
        return "None"


def get_installed_programs():
    """Get installed programs from Windows registry."""
    print("Scanning for installed programs...")
    programs = []
    reg_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]

    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for reg_path in reg_paths:
            try:
                with winreg.OpenKey(root, reg_path) as key:
                    for i in range(0, winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                    # Skip entries with empty or very short names/versions
                                    if len(name) <= 2 or len(version) <= 1:
                                        continue
                                    programs.append((name.lower(), version))
                                except (FileNotFoundError, ValueError):
                                    continue
                        except Exception as e:
                            continue
            except FileNotFoundError:
                continue

    # Add common system software that might not be in registry
    # Windows version
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            win_version = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
            display_version = winreg.QueryValueEx(key, "DisplayVersion")[0]
            programs.append((f"windows {display_version}", win_version))
    except Exception:
        pass  # Ignore if we can't get Windows version

    # Microsoft Edge - check a common path
    try:
        edge_version = check_output(
            ['powershell', '-command',
             "Get-AppxPackage -Name Microsoft.MicrosoftEdge | Select-Object -ExpandProperty Version"],
            stderr=STDOUT
        ).decode('utf-8').strip()
        if edge_version:
            programs.append(("microsoft edge", edge_version))
    except Exception:
        pass  # Ignore if we can't get Edge version

    print(f"Found {len(programs)} installed programs.")
    return programs


def match_installed_software(output_dir="reports", include_unknown=False):
    """
    Match installed software against CVE database and generate report.
    
    Args:
        output_dir (str): Directory to store reports
        include_unknown (bool): Whether to include Unknown severity vulnerabilities
    """
    print("Matching installed software against CVE database...")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Add a small delay to allow UI to update progress
    import time
    time.sleep(0.5)

    # Get installed programs
    programs = get_installed_programs()

    # Add another small delay
    time.sleep(0.5)

    grouped = defaultdict(list)
    full_details = defaultdict(list)

    for name, version in programs:
        try:
            installed_version = parse_version(str(version))
        except Exception:
            continue

        # Try to match with broader terms for better results
        name_terms = name.split()
        if not name_terms:
            continue

        # Try with first word and then with multiple words for better matching
        search_terms = [name_terms[0]]
        if len(name_terms) > 1:
            search_terms.append(f"{name_terms[0]} {name_terms[1]}")

        # Add common software names that might be referenced differently in CVEs
        if "chrome" in name.lower():
            search_terms.append("chromium")
        elif "microsoft" in name.lower():
            for term in ["office", "excel", "word", "powerpoint", "outlook"]:
                if term in name.lower():
                    search_terms.append(term)
        elif "adobe" in name.lower():
            for term in ["reader", "acrobat", "flash"]:
                if term in name.lower():
                    search_terms.append(term)

        for term in search_terms:
            like_name = f"%{term.lower()}%"
            c.execute('''
                      SELECT id, cvss_score, version_start, version_end, description
                      FROM cves
                      WHERE product LIKE ?
                         OR vendor LIKE ?
                      ''', (like_name, like_name))
            results = c.fetchall()

            for cve_id, cvss_score, version_start, version_end, description in results:
                try:
                    # Skip unknown severity if we're not including them
                    if not include_unknown and cvss_score is None:
                        continue
                        
                    if version_start:
                        version_start = str(version_start).strip()
                    if version_end:
                        version_end = str(version_end).strip()

                    # Check version constraints
                    version_match = True
                    if version_start and version_end:
                        version_match = parse_version(version_start) <= installed_version <= parse_version(version_end)
                    elif version_start:
                        version_match = installed_version >= parse_version(version_start)
                    elif version_end:
                        version_match = installed_version <= parse_version(version_end)

                    if version_match:
                        # Only include if severity is not Unknown or if include_unknown is True
                        if include_unknown or classify_cvss(cvss_score) != "Unknown":
                            grouped[(name, version)].append((cve_id, cvss_score))
                            full_details[(name, version)].append((cve_id, description, cvss_score))
                except Exception:
                    continue
    
    # Remove programs with no vulnerabilities after filtering
    empty_programs = []
    for program_key in list(grouped.keys()):
        if not grouped[program_key]:
            empty_programs.append(program_key)
            
    for program_key in empty_programs:
        del grouped[program_key]
        if program_key in full_details:
            del full_details[program_key]

    # Get timestamp for report identification
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Count vulnerabilities by severity - exclude Unknown if needed
    severity_totals = Counter()
    for values in grouped.values():
        for _, score in values:
            severity = classify_cvss(score)
            if include_unknown or severity != "Unknown":
                severity_totals[severity] += 1

    conn.close()

    # Add one more small delay before returning results
    time.sleep(0.5)

    # Return data for report generation
    return {
        'timestamp': timestamp,
        'programs': programs,
        'grouped': grouped,
        'full_details': full_details,
        'severity_totals': severity_totals
    }