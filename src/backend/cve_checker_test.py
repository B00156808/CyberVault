import os
import sqlite3
import requests
import winreg
from datetime import datetime
from urllib.parse import unquote
from time import sleep
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
from packaging.version import parse as parse_version
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.platypus import *


# Configuration
DB_FILE = "cves.db"
BASE_URL = "http://nvd.nist.gov/feeds/json/cve/1.1/"
YEARS = list(range(2002, datetime.now().year + 1))
MODIFIED_FEED = "nvdcve-1.1-modified.json.gz"
OUTPUT_DIR = "reports"

# ensure report directory exists
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# severity classification constants
SEVERITY_CLASSES = {
    "Critical": {"min": 9.0, "color": colors.red, "action": "Update immediately or uninstall"},
    "High": {"min": 7.0, "color": colors.orangered, "action": "Update as soon as possible"},
    "Medium": {"min": 4.0, "color": colors.orange, "action": "Consider updating in the next maintenance cycle"},
    "Low": {"min": 0.1, "color": colors.yellow, "action": "Optional update at your convenience"},
    "None": {"min": 0, "color": colors.lightgrey, "action": "No action required"},
    "Unknown": {"min": None, "color": colors.grey, "action": "Review when more information becomes available"}
}

# same colors as strings for matplotlib
SEVERITY_COLORS = {
    "Critical": "red",
    "High": "orangered",
    "Medium": "orange",
    "Low": "yellow",
    "None": "lightgrey",
    "Unknown": "grey"
}


def download_cve_database():
    """Download cves.db from a remote server and save it locally."""
    print("Downloading CVE database from remote server...")
    try:
        response = requests.get("https://malice.games/cves.db", timeout=60)
        response.raise_for_status()
        with open(DB_FILE, "wb") as f:
            f.write(response.content)
        print("CVE database downloaded successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to download CVE database: {e}")
        exit(1)



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
    
    # add common system software that might not be in registry
    # windows version
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            win_version = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
            display_version = winreg.QueryValueEx(key, "DisplayVersion")[0]
            programs.append((f"windows {display_version}", win_version))
    except Exception:
        pass  # ignore if cant get windows version
    
    # microsoft edge - check common path
    try:
        from subprocess import check_output, PIPE, STDOUT
        edge_version = check_output(
            ['powershell', '-command', 
             "Get-AppxPackage -Name Microsoft.MicrosoftEdge | Select-Object -ExpandProperty Version"],
            stderr=STDOUT
        ).decode('utf-8').strip()
        if edge_version:
            programs.append(("microsoft edge", edge_version))
    except Exception:
        pass  # ignore if we cant get edge version
    
    print(f"Found {len(programs)} installed programs.")
    return programs


# classify CVSS score into severity categories
def classify_cvss(score):
    if score is None:
        return "Unknown"
    
    score = float(score)
    for severity, info in sorted(SEVERITY_CLASSES.items(), 
                                key=lambda x: float('-inf') if x[1]["min"] is None else x[1]["min"], 
                                reverse=True):
        if info["min"] is None:
            continue
        if score >= info["min"]:
            return severity
    
    return "Unknown"


# create a pie chart image of CVE severities
def create_severity_pie_chart(severity_totals):
    plt.figure(figsize=(8, 6))
    
    # prepare data
    labels = []
    sizes = []
    colors = []
    explode = []
    
    # define matplotlib compatible colors
    matplotlib_colors = {
        "Critical": "red",
        "High": "orangered",
        "Medium": "orange",
        "Low": "yellow",
        "None": "lightgrey",
        "Unknown": "grey"
    }
    
    # sort by severity 
    priority_order = ["Critical", "High", "Medium", "Low", "None", "Unknown"]
    for severity in priority_order:
        count = severity_totals.get(severity, 0)
        if count > 0:
            labels.append(f"{severity} ({count})")
            sizes.append(count)
            colors.append(matplotlib_colors[severity])
            explode.append(0.1 if severity == "Critical" else 0)
    
    # dont create chart if no data
    if not sizes:
        print("No vulnerability data for pie chart")
        dummy_path = os.path.join(OUTPUT_DIR, "cve_severity_pie_chart.png")
        # create a blank image
        plt.figure(figsize=(8, 6))
        plt.text(0.5, 0.5, "No vulnerabilities found", ha='center', va='center', fontsize=16)
        plt.axis('off')
        plt.savefig(dummy_path)
        plt.close()
        return dummy_path
    
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, explode=explode, startangle=140, shadow=True)
    plt.title("Distribution of CVE Severities", fontsize=16, fontweight='bold')
    plt.axis("equal")
    plt.tight_layout()
    
    chart_path = os.path.join(OUTPUT_DIR, "cve_severity_pie_chart.png")
    plt.savefig(chart_path, dpi=300)
    plt.close()
    
    return chart_path


def generate_pdf_report(timestamp, programs, grouped, full_details, pie_chart_path):
    """Generate a comprehensive PDF report of vulnerability findings."""
    pdf_filename = os.path.join(OUTPUT_DIR, f"cybervault-report-{timestamp}.pdf")
    
    # create PDF 
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    # get styles
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading1"]
    heading2_style = styles["Heading2"]
    normal_style = styles["Normal"]
    
    # custom styles
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
    )
    
    cve_style = ParagraphStyle(
        'CVE',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        leftIndent=20,
    )
    
    highlight_style = ParagraphStyle(
        'Highlight',
        parent=styles['Normal'],
        fontSize=11,
        leading=15,
        textColor=colors.darkblue,
        borderWidth=1,
        borderColor=colors.lightblue,
        borderPadding=6,
        borderRadius=3,
        backColor=colors.lightblue.clone(alpha=0.2),
    )
    
    # document elements
    elements = []
    
    # cover page
    elements.append(Paragraph("CyberVault Vulnerability Scan", title_style))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 24))
    
    # calculate total vulnerabilities by severity
    all_severities = Counter()
    for program_info, cves in grouped.items():
        for cve_id, score in cves:
            all_severities[classify_cvss(score)] += 1
    
    # --- NONTECHNICAL SECTION ---
    elements.append(Paragraph("What This Report Means For You", heading_style))
    elements.append(Spacer(1, 12))
    
    # explain vulns
    elements.append(Paragraph(
        "This report found security vulnerabilities in software installed on your computer. " +
        "A vulnerability is like a weak spot in your software that could potentially be exploited by hackers. " +
        "The higher the severity level, the more urgent it is to address the issue.",
        body_style
    ))
    elements.append(Spacer(1, 12))
    
    # findings in nontechnichal terms
    critical_count = all_severities.get('Critical', 0)
    high_count = all_severities.get('High', 0)
    total_count = sum(all_severities.values())
    vulnerable_programs = len(grouped)
    total_programs = len(programs)
    
    key_findings = f"""
    <b>Key Findings:</b><br/><br/>
    • We scanned {total_programs} software programs on your computer<br/><br/>
    • {vulnerable_programs} of these programs have potential security issues<br/><br/>
    • We found a total of {total_count} vulnerabilities<br/><br/>
    """
    
    if critical_count > 0:
        key_findings += f"• <b>{critical_count} critical vulnerabilities require immediate attention</b><br/><br/>"
    if high_count > 0:
        key_findings += f"• <b>{high_count} high-severity vulnerabilities should be addressed soon</b>\n"
        
    elements.append(Paragraph(key_findings, highlight_style))
    elements.append(Spacer(1, 12))
    
    # nontechnichal action steps
    elements.append(Paragraph("What You Should Do", heading2_style))
    elements.append(Spacer(1, 6))
    
    what_to_do = ""
    if critical_count > 0 or high_count > 0:
        what_to_do += """
        <b>1. Update Your Software</b>: Most vulnerabilities can be fixed by updating to the latest version of the software. Look for "Check for updates" options in your programs or visit the software providers' websites.<br/><br/>
        <b>2. Prioritize Critical and High Severity Issues</b>: Focus on updating the programs listed with Critical and High severity ratings first.<br/><br/>
        <b>3. Consider Alternatives</b>: If updates are not available for vulnerable software, consider replacing it with more secure alternatives.<br/><br/>
        """
    else:
        what_to_do += """
        <b>1. Regular Updates</b>: Continue to keep your software updated to maintain good security.<br/><br/>
        
        <b>2. Periodic Scanning</b>: Run this vulnerability scan regularly (e.g., monthly) to check for new issues.<br/><br/>
        """
    
    what_to_do += """
    <b>Need Help?</b> If you're unsure how to update specific software, search online for "[software name] update guide" or contact your IT support.
    """
    
    elements.append(Paragraph(what_to_do, body_style))
    elements.append(Spacer(1, 24))
    
    # add pie chart
    if os.path.exists(pie_chart_path):
        elements.append(Paragraph("Vulnerability Severity Overview", heading2_style))
        elements.append(Spacer(1, 6))
        img = Image(pie_chart_path, width=400, height=300)
        elements.append(img)
        
        # add legend explaining severity levels
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("Understanding Severity Levels:", heading2_style))
        elements.append(Spacer(1, 6))
        
        severity_explanation = """
        <b>Critical</b>: Urgent security issues that could allow attackers to take control of your computer or steal sensitive information.<br/><br/>
        
        <b>High</b>: Serious vulnerabilities that should be fixed as soon as possible to protect your system.<br/><br/>
        
        <b>Medium</b>: Important issues that should be addressed during your next regular maintenance.<br/><br/>
        
        <b>Low</b>: Minor security weaknesses that pose limited risk.<br/><br/>
        
        <b>Unknown</b>: Issues where the severity couldn't be determined.<br/><br/>
        """
        elements.append(Paragraph(severity_explanation, body_style))
    
    elements.append(PageBreak())
    # --- END OF NONTECHNICHAL SECTION ---
    
    # summary table data
    elements.append(Paragraph("Detailed Summary", heading_style))
    elements.append(Spacer(1, 12))
    
    data = [["Severity", "Count", "Action Required"]]
    
    # sort by priority
    for severity in ["Critical", "High", "Medium", "Low", "None", "Unknown"]:
        count = all_severities.get(severity, 0)
        if count > 0:
            data.append([
                severity, 
                count, 
                SEVERITY_CLASSES[severity]["action"]
            ])
    
    # create table
    table = Table(data, colWidths=[80, 60, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (0, -1), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 24))
    
    # page break before detailed findings
    elements.append(Paragraph("Detailed Findings", heading_style))
    elements.append(Spacer(1, 12))
    
    # sort programs by their severity 
    def get_highest_severity(program_cves):
        highest = -1
        for _, score in program_cves[1]:
            if score is not None and float(score) > highest:
                highest = float(score)
        return highest
    
    sorted_programs = sorted(grouped.items(), key=get_highest_severity, reverse=True)
    
    # program details
    for (prog_name, prog_version), cves in sorted_programs:
        severity_counts = Counter(classify_cvss(score) for _, score in cves)
        
        # determine highest severity
        highest_severity = "Unknown"
        for severity in ["Critical", "High", "Medium", "Low", "None"]:
            if severity_counts[severity] > 0:
                highest_severity = severity
                break
        
        # program heading with color-coded severity
        color = SEVERITY_CLASSES[highest_severity]["color"]
        action = SEVERITY_CLASSES[highest_severity]["action"]
        
        program_style = ParagraphStyle(
            'Program',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=color,
        )
        
        elements.append(Paragraph(f"{prog_name} (version: {prog_version})", program_style))
        elements.append(Spacer(1, 6))
        
        # add simple explanation for this program
        if highest_severity in ["Critical", "High"]:
            action_text = f"<b>Recommended Action</b>: {action} - This software has serious security issues that need attention."
        elif highest_severity == "Medium":
            action_text = f"<b>Recommended Action</b>: {action} - This software has important but less urgent security issues."
        else:
            action_text = f"<b>Recommended Action</b>: {action} - This software has minor security concerns."
            
        elements.append(Paragraph(action_text, body_style))
        elements.append(Spacer(1, 6))
        
        # vuln statistics
        elements.append(Paragraph(f"Total vulnerabilities: {len(cves)}", body_style))
        elements.append(Paragraph(
            f"Severity breakdown: Critical: {severity_counts['Critical']}, " +
            f"High: {severity_counts['High']}, Medium: {severity_counts['Medium']}, " +
            f"Low: {severity_counts['Low']}", body_style
        ))
        elements.append(Spacer(1, 12))
        
        # if there are detailed findings for this program
        if (prog_name, prog_version) in full_details:
            # sort by severity
            sorted_details = sorted(
                full_details[(prog_name, prog_version)],
                key=lambda x: float(-999 if x[2] is None else x[2]),
                reverse=True
            )
            
            # show top vulnerabilities (limit to 5 to keep report manageable)
            elements.append(Paragraph("Top Vulnerabilities:", body_style))
            for i, (cve_id, desc, score) in enumerate(sorted_details[:5]):
                severity = classify_cvss(score)
                elements.append(Paragraph(
                    f"<b>{cve_id}</b> (Score: {score}, {severity}): {desc[:150]}{'...' if len(desc) > 150 else ''}",
                    cve_style
                ))
            
            if len(sorted_details) > 5:
                elements.append(Paragraph(f"... and {len(sorted_details) - 5} more vulnerabilities", cve_style))
            
        elements.append(Spacer(1, 18))
    
    # buld PDF
    doc.build(elements)
    print(f"PDF report generated: {pdf_filename}")
    return pdf_filename


# match installed software against CVE database and generate report
def match_installed_software():
    print("Matching installed software against CVE database...")
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

        # try to match with broader terms for better results
        name_terms = name.split()
        if not name_terms:
            continue
            
        # try with first word and then multiple words for better matching
        search_terms = [name_terms[0]]
        if len(name_terms) > 1:
            search_terms.append(f"{name_terms[0]} {name_terms[1]}")
        
        # add common software names that might be referenced differently in CVEs
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
                WHERE product LIKE ? OR vendor LIKE ?
            ''', (like_name, like_name))
            results = c.fetchall()

            for cve_id, cvss_score, version_start, version_end, description in results:
                try:
                    if version_start:
                        version_start = str(version_start).strip()
                    if version_end:
                        version_end = str(version_end).strip()

                    # check version constraints
                    version_match = True
                    if version_start and version_end:
                        version_match = parse_version(version_start) <= installed_version <= parse_version(version_end)
                    elif version_start:
                        version_match = installed_version >= parse_version(version_start)
                    elif version_end:
                        version_match = installed_version <= parse_version(version_end)

                    if version_match:
                        grouped[(name, version)].append((cve_id, cvss_score))
                        full_details[(name, version)].append((cve_id, description, cvss_score))
                except Exception:
                    continue

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # count vulnerabilities by severity
    severity_totals = Counter()
    for values in grouped.values():
        for _, score in values:
            severity_totals[classify_cvss(score)] += 1

    # create pie chart
    pie_chart_path = create_severity_pie_chart(severity_totals)

    # print summary to terminal
    print("\nSummary of Vulnerable Programs:\n")
    for (prog_name, prog_version), cves in grouped.items():
        severity_counts = Counter(classify_cvss(score) for _, score in cves)
        
        # determine highest severity
        highest_severity = "Unknown"
        for severity in ["Critical", "High", "Medium", "Low", "None"]:
            if severity_counts[severity] > 0:
                highest_severity = severity
                break
                
        action = SEVERITY_CLASSES[highest_severity]["action"]

        print(f"{prog_name} (v{prog_version})")
        print(f"Total CVEs: {len(cves)} | Critical: {severity_counts['Critical']}, High: {severity_counts['High']}, Medium: {severity_counts['Medium']}")
        print(f"Suggested Action: {action}\n")

    # generate PDF report
    pdf_path = generate_pdf_report(timestamp, programs, grouped, full_details, pie_chart_path)
    conn.close()
    
    print(f"\nScan complete! Report saved to: {pdf_path}")
    return pdf_path


def main():
    print("CyberVault Vulnerability Scanner")
    print("===============================")
    
    # download latest cve db version
    download_cve_database()
    
    # Scan system and generate report
    match_installed_software()


if __name__ == "__main__":
    main()