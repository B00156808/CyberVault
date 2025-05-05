import os
import json
import gzip
import sqlite3
import requests
import winreg
from datetime import datetime
from urllib.parse import unquote
from time import sleep
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
from packaging.version import parse as parse_version
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

DB_FILE = "cves.db"
BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
YEARS = list(range(2002, datetime.now().year + 1))
MODIFIED_FEED = "nvdcve-1.1-modified.json.gz"

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

def parse_cpe(cpe_uri):
    parts = cpe_uri.split(":")
    if len(parts) >= 6:
        vendor = parts[3].lower()
        product = parts[4].lower()
        version = parts[5].lower()
        return vendor, product, version
    return None, None, None

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
                version_start = cpe.get("versionStartIncluding") or cpe.get("versionStartExcluding")
                version_end = cpe.get("versionEndIncluding") or cpe.get("versionEndExcluding")
                if vendor and product:
                    insert_cve(conn, cve_id, vendor, product, version_start, version_end, description, published_date, cvss_score)

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

def generate_pdf_report(timestamp, programs, grouped, full_details, pie_chart_path):
    pdf_filename = f"cybervault-report-{timestamp}.pdf"
    c = canvas.Canvas(pdf_filename, pagesize=A4)
    width, height = A4

    # Page 1 - Summary
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, f"CyberVault Vulnerability Scan Report")
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 70, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(50, height - 90, f"Found {len(programs)} installed programs.")
    c.drawString(50, height - 110, f"Found {len(grouped)} potentially vulnerable programs:")

    y = height - 130
    for (prog_name, prog_version), cves in grouped.items():
        severity_counts = Counter(classify_cvss(score) for _, score in cves)
        most_severe = (
            "Critical" if severity_counts["Critical"] > 0 else
            "High" if severity_counts["High"] > 0 else
            "Medium" if severity_counts["Medium"] > 0 else
            "Low" if severity_counts["Low"] > 0 else
            "Unknown"
        )
        action = suggest_action(
            10 if most_severe == "Critical" else
            8 if most_severe == "High" else
            5 if most_severe == "Medium" else
            2
        )
        text = f"{prog_name} (version: {prog_version})"
        c.drawString(50, y, text)
        y -= 15
        c.drawString(60, y, f"-> Total CVEs: {len(cves)} | Critical: {severity_counts['Critical']}, High: {severity_counts['High']}, Medium: {severity_counts['Medium']}")
        y -= 15
        c.drawString(60, y, f"Suggested Action: {action}")
        y -= 25
        if y < 100:
            c.showPage()
            y = height - 50

    c.showPage()

    # Page 2 - Pie chart + details
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 50, "CVE Severity Breakdown")
    c.drawImage(ImageReader(pie_chart_path), 50, height - 400, width=500, height=300)

    y = height - 420
    c.setFont("Helvetica", 10)
    for (prog_name, prog_version), details in full_details.items():
        c.drawString(50, y, f"{prog_name} (version: {prog_version})")
        y -= 15
        for cve_id, desc, score in details:
            c.drawString(60, y, f"{cve_id} (Score: {score}): {desc[:100]}...")
            y -= 15
            if y < 100:
                c.showPage()
                y = height - 50
        y -= 10

    c.save()
    print(f"PDF report generated: {pdf_filename}")

def match_installed_software():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    programs = get_installed_programs()
    grouped = defaultdict(list)
    full_details = defaultdict(list)

    for name, version in programs:
        try:
            installed_version = parse_version(str(version))
        except Exception:
            continue

        like_name = f"%{name.split()[0]}%"
        c.execute('''
            SELECT id, cvss_score, version_start, version_end, description
            FROM cves
            WHERE product LIKE ?
        ''', (like_name,))
        results = c.fetchall()

        for cve_id, cvss_score, version_start, version_end, description in results:
            try:
                if version_start:
                    version_start = str(version_start).strip()
                if version_end:
                    version_end = str(version_end).strip()

                if version_start and version_end:
                    if not (parse_version(version_start) <= installed_version <= parse_version(version_end)):
                        continue
                elif version_start:
                    if installed_version < parse_version(version_start):
                        continue
                elif version_end:
                    if installed_version > parse_version(version_end):
                        continue

                grouped[(name, version)].append((cve_id, cvss_score))
                full_details[(name, version)].append((cve_id, description, cvss_score))
            except Exception:
                continue

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Pie chart
    severity_totals = Counter()
    for values in grouped.values():
        for _, score in values:
            severity_totals[classify_cvss(score)] += 1

    labels = []
    sizes = []
    for k, v in severity_totals.items():
        if v > 0:
            labels.append(f"{k} ({v})")
            sizes.append(v)

    colors = ["red", "orange", "gold", "lightgreen", "gray"]
    explode = [0.1 if l.startswith("Critical") else 0 for l in labels]

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors[:len(labels)], explode=explode, startangle=140)
    plt.title("Distribution of CVE Severities")
    plt.axis("equal")
    plt.tight_layout()
    pie_chart_path = "cve_severity_pie_chart.png"
    plt.savefig(pie_chart_path)
    plt.close()

    print("\n Summary of Vulnerable Programs:\n")
    for (prog_name, prog_version), cves in grouped.items():
        severity_counts = Counter(classify_cvss(score) for _, score in cves)
        most_severe = (
            "Critical" if severity_counts["Critical"] > 0 else
            "High" if severity_counts["High"] > 0 else
            "Medium" if severity_counts["Medium"] > 0 else
            "Low" if severity_counts["Low"] > 0 else
            "Unknown"
        )
        action = suggest_action(
            10 if most_severe == "Critical" else
            8 if most_severe == "High" else
            5 if most_severe == "Medium" else
            2
        )

        print(f"{prog_name} (v{prog_version})")
        print(f"Total CVEs: {len(cves)} | Critical: {severity_counts['Critical']}, High: {severity_counts['High']}, Medium: {severity_counts['Medium']}")
        print(f"Suggested Action: {action}\n")

    generate_pdf_report(timestamp, programs, grouped, full_details, pie_chart_path)
    conn.close()

# Run
print("Scanning installed programs and matching with CVEs...")
match_installed_software()
