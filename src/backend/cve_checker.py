import os
import json
import gzip
import sqlite3
import requests
import winreg
from datetime import datetime
from urllib.parse import unquote
from time import *
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


# --- Match Installed Programs with CVEs ---

def match_installed_software():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    programs = get_installed_programs()
    print(f"Found {len(programs)} installed programs.")
    matched = []

    for prog_name, installed_version in programs:
        like_name = f"%{prog_name.split()[0]}%"
        c.execute('''
            SELECT id, vendor, product, version_start, version_end, description, published_date, cvss_score
            FROM cves
            WHERE product LIKE ?
        ''', (like_name,))
        results = c.fetchall()

        for row in results:
            cve_id, vendor, product, v_start, v_end, description, pub_date, cvss = row

            try:
                installed_v = vparse.parse(installed_version)
                v_start_parsed = vparse.parse(v_start) if v_start else None
                v_end_parsed = vparse.parse(v_end) if v_end else None

                if ((not v_start_parsed or installed_v >= v_start_parsed) and
                    (not v_end_parsed or installed_v <= v_end_parsed)):

                    severity = classify_cvss(cvss)
                    action = suggest_action(cvss)

                    matched.append({
                        "cve_id": cve_id,
                        "vendor": vendor,
                        "product": product,
                        "affected_version": f"{v_start or '?'} to {v_end or '?'}",
                        "description": description,
                        "published": pub_date,
                        "cvss_score": cvss,
                        "cvss_severity": severity,
                        "recommended_action": action,
                        "matched_program": prog_name,
                        "installed_version": installed_version
                    })
            except Exception:
                continue

    conn.close()

    print(f"\nFound {len(matched)} matching CVEs.\n")

    # --- Write Report ---
    with open("cve_report.csv", "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=matched[0].keys())
        writer.writeheader()
        writer.writerows(matched)

    for match in matched:
        print(f"[{match['cve_id']}] {match['matched_program']} (installed: {match['installed_version']})")
        print(f"-> {match['description'][:100]}...")
        print(f"CVSS: {match['cvss_score']} ({match['cvss_severity']}) | Action: {match['recommended_action']}")
        print(f"Published: {match['published']}\n")

    print("✅ Report saved to 'cve_report.csv'.")
    total = len(matched)
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



# --- Run All ---
if __name__ == "__main__":
    print("Building or updating CVE database...")
    build_or_update_db()

    print("\nScanning installed programs and matching with CVEs...")
    match_installed_software()
