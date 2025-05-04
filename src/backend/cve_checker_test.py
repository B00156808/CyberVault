import os
import json
import gzip
import sqlite3
import requests
import winreg
from datetime import datetime
from urllib.parse import unquote
from time import sleep
import csv
from collections import defaultdict, Counter
import matplotlib.pyplot as plt

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

    for year in YEARS:
        sleep(6)
        try:
            process_feed(f"nvdcve-1.1-{year}.json.gz", conn)
        except Exception as e:
            print(f"Failed year {year}: {e}")

    try:
        process_feed(MODIFIED_FEED, conn)
    except Exception as e:
        print(f"Failed modified feed: {e}")

    conn.close()


# --- Get Installed Programs on Windows ---
def get_installed_programs():
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


# --- Match Installed Software (Grouped Version) ---
def match_installed_software():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    programs = get_installed_programs()
    print(f"Found {len(programs)} installed programs.")

    grouped = defaultdict(list)

    for name, version in programs:
        like_name = f"%{name.split()[0]}%"
        c.execute('''
            SELECT id, cvss_score
            FROM cves
            WHERE product LIKE ?
        ''', (like_name,))
        results = c.fetchall()
        if results:
            grouped[(name, version)].extend(results)

    print(f"\nFound {len(grouped)} potentially vulnerable programs:\n")

    summary = []

    for (prog_name, prog_version), cves in grouped.items():
        severity_counts = Counter(classify_cvss(score) for _, score in cves)
        total_cves = len(cves)
        most_severe = (
            "Critical" if severity_counts["Critical"] > 0 else
            "High" if severity_counts["High"] > 0 else
            "Medium" if severity_counts["Medium"] > 0 else
            "Low" if severity_counts["Low"] > 0 else
            "Unknown"
        )
        summary.append({
            "program": prog_name,
            "version": prog_version,
            "total_cves": total_cves,
            "critical": severity_counts["Critical"],
            "high": severity_counts["High"],
            "medium": severity_counts["Medium"],
            "low": severity_counts["Low"],
            "unknown": severity_counts["Unknown"],
            "suggested_action": suggest_action(
                10 if most_severe == "Critical" else
                8 if most_severe == "High" else
                5 if most_severe == "Medium" else
                2
            )
        })

        print(f"{prog_name} (version: {prog_version})")
        print(f"-> Total CVEs: {total_cves} | Critical: {severity_counts['Critical']}, High: {severity_counts['High']}, Medium: {severity_counts['Medium']}")
        print(f"Suggested Action: {suggest_action(10 if most_severe == 'Critical' else 8 if most_severe == 'High' else 5 if most_severe == 'Medium' else 2)}\n")

    # Write grouped summary to CSV
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    csv_filename = f"cybervault-scan-summary-{timestamp}.csv"

    with open(csv_filename, mode="w", newline='', encoding="utf-8") as csvfile:
        fieldnames = [
            "program", "version", "total_cves",
            "critical", "high", "medium", "low", "unknown",
            "suggested_action"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary:
            writer.writerow(row)

    print(f"\nCSV summary report generated: {csv_filename}")

    conn.close()


    # Generate Pie Chart of CVE Severity
    severity_totals = Counter()
    for row in summary:
        severity_totals["Critical"] += row["critical"]
        severity_totals["High"] += row["high"]
        severity_totals["Medium"] += row["medium"]
        severity_totals["Low"] += row["low"]
        severity_totals["Unknown"] += row["unknown"]

    # Filter out zero counts
    labels = []
    sizes = []
    for k, v in severity_totals.items():
        if v > 0:
            labels.append(f"{k} ({v})")
            sizes.append(v)

    colors = ["red", "orange", "gold", "lightgreen", "gray"]
    explode = [0.1 if l.startswith("Critical") else 0 for l in labels]  # pop out Critical

    plt.figure(figsize=(8, 8))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors[:len(labels)], explode=explode, startangle=140)
    plt.title("Distribution of CVE Severities")
    plt.axis("equal")
    plt.tight_layout()
    plt.savefig("cve_severity_pie_chart.png")
    plt.show()

    print("📊 Pie chart saved as 'cve_severity_pie_chart.png'")



# --- Run ---
print("Scanning installed programs and matching with CVEs...")
match_installed_software()
