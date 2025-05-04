
import os
import json
import gzip
import sqlite3
import requests
import winreg
from datetime import datetime
from urllib.parse import unquote
from time import *
from packaging import version as pkg_version
import csv  


# --- Configuration ---
DB_FILE = "cves.db"
BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
YEARS = list(range(2002, datetime.now().year + 1))
MODIFIED_FEED = "nvdcve-1.1-modified.json.gz"


# --- Database Setup ---
def create_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY,
            vendor TEXT,
            product TEXT,
            version_start TEXT,
            version_end TEXT,
            description TEXT,
            published_date TEXT,
            cvss_score REAL
        )
    ''')
    conn.commit()
    conn.close()


# --- Parse CPE URI ---
def parse_cpe(cpe_uri):
    # Example: cpe:2.3:a:microsoft:edge:96.0.1054.57:*:*:*:*:*:*:*
    parts = cpe_uri.split(":")
    if len(parts) >= 5:
        vendor = parts[3].lower()
        product = parts[4].lower()
        version = parts[5].lower()
        return vendor, product, version
    return None, None, None


# --- Insert CVEs into DB ---
def insert_cve(conn, cve_id, vendor, product, version_start, version_end, description, published_date, cvss_score):
    c = conn.cursor()
    try:
        c.execute('''
            INSERT OR IGNORE INTO cves 
            (id, vendor, product, version_start, version_end, description, published_date, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (cve_id, vendor, product, version_start, version_end, description, published_date, cvss_score))
    except Exception as e:
        print(f"Insert failed: {e}")
    conn.commit()



# --- Download + Parse JSON Feed ---
def process_feed(feed_name, conn):
    url = f"{BASE_URL}{feed_name}"
    print(f"Downloading: {url}")
    r = requests.get(url)
    if r.status_code != 200:
        print(f"Failed: {r.status_code}")
        return

    data = json.loads(gzip.decompress(r.content))
    for item in data.get("CVE_Items", []):
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        published_date = item["publishedDate"]

        # Try to get CVSS v3, fall back to v2
        impact = item.get("impact", {})
        cvss_score = None
        if "baseMetricV3" in impact:
            cvss_score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
        elif "baseMetricV2" in impact:
            cvss_score = impact["baseMetricV2"]["cvssV2"]["baseScore"]

        nodes = item.get("configurations", {}).get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpe_match", [])
            for cpe in cpe_matches:
                cpe_uri = cpe.get("cpe23Uri")
                vendor, product, version = parse_cpe(cpe_uri)
                if vendor and product and version:
                    insert_cve(conn, cve_id, vendor, product, version, version, description, published_date, cvss_score)



# --- Build or Update CVE DB ---
def build_or_update_db():
    create_db()
    conn = sqlite3.connect(DB_FILE)

    # Download each year feed
    for year in YEARS:
        sleep(6)
        try:
            process_feed(f"nvdcve-1.1-{year}.json.gz", conn)
        except Exception as e:
            print(f"Failed year {year}: {e}")

    # Process modified (recent updates)
    try:
        process_feed(MODIFIED_FEED, conn)
    except Exception as e:
        print(f"Failed modified feed: {e}")

    conn.close()


# --- Get Installed Programs on Windows ---
def get_installed_programs():
    programs = []

    # Registry locations
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
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                programs.append((name.lower(), version))
                        except FileNotFoundError:
                            continue
                        except Exception:
                            continue
            except FileNotFoundError:
                continue

    return programs


def classify_cvss(score):
    if score is None:
        return "Unknown"
    score = float(score)
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    return "None"

def suggest_action(score):
    severity = classify_cvss(score)
    if severity in ("Critical", "High"):
        return "Update immediately or uninstall"
    elif severity == "Medium":
        return "Consider updating soon"
    elif severity == "Low":
        return "Optional update"
    else:
        return "No action required"

# --- Match Installed Programs with CVEs ---
def match_installed_software():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    programs = get_installed_programs()
    print(f"Found {len(programs)} installed programs.")

    matched = []

    for name, installed_version in programs:
        base_name = name.split()[0].lower()
        like_name = f"%{base_name}%"

        c.execute('''
            SELECT id, vendor, product, version_start, version_end, description, published_date, cvss_score
            FROM cves
            WHERE product LIKE ?
        ''', (like_name,))
        results = c.fetchall()

        for row in results:
            cve_id, vendor, product, v_start, v_end, description, pub_date, cvss_score = row

            try:
                inst_ver = pkg_version.parse(installed_version)
                start_ver = pkg_version.parse(v_start) if v_start else None
                end_ver = pkg_version.parse(v_end) if v_end else None

                version_match = True
                if start_ver and inst_ver < start_ver:
                    version_match = False
                if end_ver and inst_ver > end_ver:
                    version_match = False

                if version_match:
                    matched.append({
                        "cve_id": cve_id,
                        "vendor": vendor,
                        "product": product,
                        "version_start": v_start,
                        "version_end": v_end,
                        "description": description,
                        "published_date": pub_date,
                        "cvss_score": cvss_score,
                        "cvss_severity": classify_cvss(cvss_score),
                        "suggested_action": suggest_action(cvss_score),
                        "matched_program": name,
                        "installed_version": installed_version
                    })

            except Exception as e:
                print(f"Version comparison failed for {name}: {e}")

    conn.close()

    if not matched:
        print("\n✅ No matching CVEs found for your installed software. Your system appears up to date and safe!")
        return

    # Display results
    total = len(matched)
    print(f"\nFound {total} matching CVEs:\n")
    for match in matched:
        print(f"[{match['cve_id']}] {match['matched_program']} (installed: {match['installed_version']})")
        print(f"-> {match['description'][:100]}...")
        print(f"Published: {match['published_date']}")
        print(f"Severity: {match['cvss_severity']}")
        print(f"Suggested Action: {match['suggested_action']}\n")

    # Severity breakdown
    critical = sum(1 for m in matched if m["cvss_severity"] == "Critical")
    high = sum(1 for m in matched if m["cvss_severity"] == "High")
    medium = sum(1 for m in matched if m["cvss_severity"] == "Medium")
    low = sum(1 for m in matched if m["cvss_severity"] == "Low")
    unknown = total - (critical + high + medium + low)

    print("\n--- CVE Summary ---")
    print(f"Total CVEs Found: {total}")
    print(f"Critical: {critical}")
    print(f"High: {high}")
    print(f"Medium: {medium}")
    print(f"Low: {low}")
    print(f"Unknown Severity: {unknown}")

    # Write to CSV
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    csv_filename = f"cybervault-scan-{timestamp}.csv"
    with open(csv_filename, mode="w", newline='', encoding="utf-8") as csvfile:
        fieldnames = [
            "cve_id", "vendor", "product", "version_start", "version_end", "description",
            "published_date", "cvss_score", "cvss_severity", "suggested_action",
            "matched_program", "installed_version"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in matched:
            writer.writerow(row)

    print(f"\nCSV report generated: {csv_filename}")




# --- Run All ---
print("Building or updating CVE database...")
#build_or_update_db()

print("\nScanning installed programs and matching with CVEs...")
match_installed_software()
