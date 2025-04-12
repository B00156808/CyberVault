import os
import json
import gzip
import sqlite3
import requests
import winreg
from datetime import datetime
from urllib.parse import unquote
from time import *


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
            published_date TEXT
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
def insert_cve(conn, cve_id, vendor, product, version, description, published_date):
    c = conn.cursor()
    try:
        c.execute('''
            INSERT OR IGNORE INTO cves (id, vendor, product, version_start, version_end, description, published_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (cve_id, vendor, product, version, version, description, published_date))
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
        nodes = item.get("configurations", {}).get("nodes", [])

        for node in nodes:
            cpe_matches = node.get("cpe_match", [])
            for cpe in cpe_matches:
                cpe_uri = cpe.get("cpe23Uri")
                vendor, product, version = parse_cpe(cpe_uri)
                if vendor and product and version:
                    insert_cve(conn, cve_id, vendor, product, version, description, published_date)


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

    for name, version in programs:
        like_name = f"%{name.split()[0]}%"
        c.execute('''
            SELECT id, vendor, product, version_start, description, published_date
            FROM cves
            WHERE product LIKE ?
        ''', (like_name,))
        results = c.fetchall()
        for row in results:
            matched.append({
                "cve_id": row[0],
                "vendor": row[1],
                "product": row[2],
                "affected_version": row[3],
                "description": row[4],
                "published": row[5],
                "matched_program": name,
                "installed_version": version
            })

    conn.close()

    print(f"\nFound {len(matched)} matching CVEs:\n")
    for match in matched:
        print(f"[{match['cve_id']}] {match['matched_program']} (installed: {match['installed_version']})")
        print(f"-> {match['description'][:100]}...")
        print(f"Published: {match['published']}\n")


# --- Run All ---
if __name__ == "__main__":
    print("Building or updating CVE database...")
    build_or_update_db()

    print("\nScanning installed programs and matching with CVEs...")
    match_installed_software()
