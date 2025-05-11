import os
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak, Image
)
from collections import Counter
from datetime import datetime

from ..config.settings import REPORTS_DIR
from .scanner import classify_cvss

# Ensure report directory exists
OUTPUT_DIR = REPORTS_DIR
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

from reportlab.lib import colors
from src.config import (
    SEVERITY_THRESHOLDS,
    SEVERITY_ACTIONS
)
# Construct severity classes for reporting
SEVERITY_CLASSES = {
    "Critical": {"min": SEVERITY_THRESHOLDS["Critical"], "color": colors.red, "action": SEVERITY_ACTIONS["Critical"]},
    "High": {"min": SEVERITY_THRESHOLDS["High"], "color": colors.orangered, "action": SEVERITY_ACTIONS["High"]},
    "Medium": {"min": SEVERITY_THRESHOLDS["Medium"], "color": colors.orange, "action": SEVERITY_ACTIONS["Medium"]},
    "Low": {"min": SEVERITY_THRESHOLDS["Low"], "color": colors.yellow, "action": SEVERITY_ACTIONS["Low"]},
    "None": {"min": SEVERITY_THRESHOLDS["None"], "color": colors.lightgrey, "action": SEVERITY_ACTIONS["None"]},
}


def create_severity_pie_chart(severity_totals):
    """Create a pie chart image of CVE severities."""
    plt.figure(figsize=(8, 6))

    # Prepare data
    labels = []
    sizes = []
    colors = []
    explode = []

    # Define matplotlib-compatible colors
    matplotlib_colors = {
        "Critical": "red",
        "High": "orangered",
        "Medium": "orange",
        "Low": "yellow",
        "None": "lightgrey",
        # "Unknown": "grey"
    }

    # Sort by severity (Critical first)
    priority_order = ["Critical", "High", "Medium", "Low", "None"]
    for severity in priority_order:
        count = severity_totals.get(severity, 0)
        if count > 0:
            labels.append(f"{severity} ({count})")
            sizes.append(count)
            colors.append(matplotlib_colors[severity])
            explode.append(0.1 if severity == "Critical" else 0)

    # Don't create chart if no data
    if not sizes:
        print("No vulnerability data for pie chart")
        dummy_path = os.path.join(OUTPUT_DIR, "cve_severity_pie_chart.png")
        # Create a blank image
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


def generate_pdf_report(scan_data):
    """Generate a comprehensive PDF report of vulnerability findings."""
    import os
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    from reportlab.lib.units import inch
    from datetime import datetime
    from collections import Counter

    timestamp = scan_data['timestamp']
    programs = scan_data['programs']
    grouped = scan_data['grouped']
    full_details = scan_data['full_details']
    severity_totals = scan_data['severity_totals']

    # Create pie chart
    pie_chart_path = create_severity_pie_chart(severity_totals)

    # Generate PDF
    pdf_filename = os.path.join(OUTPUT_DIR, f"cybervault-report-{timestamp}.pdf")

    # Create the PDF document
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )

    # Get styles
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading1"]
    heading2_style = styles["Heading2"]
    normal_style = styles["Normal"]

    # Custom styles
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

    # Document elements
    elements = []

    # Try to find and add the company logo
    logo_found = False
    try:
        # Get the project root directory
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        logo_path = os.path.join(project_root, "resources", "images", "CyberVaultLogo.png")

        if os.path.exists(logo_path):
            # Add logo to the report
            logo = Image(logo_path, width=2.5 * inch, height=2 * inch)
            elements.append(logo)
            elements.append(Spacer(1, 12))
            logo_found = True
            print(f"Added logo to PDF: {logo_path}")
    except Exception as e:
        print(f"Could not add logo to PDF: {e}")

    # If logo wasn't found, use the text title as fallback
    if not logo_found:
        elements.append(Paragraph("CyberVault Vulnerability Scan", title_style))
        elements.append(Spacer(1, 12))

    elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 24))

    # Calculate total vulnerabilities by severity
    all_severities = Counter()
    for program_info, cves in grouped.items():
        for cve_id, score in cves:
            all_severities[classify_cvss(score)] += 1

    # --- ENHANCED SECTION FOR NON-TECHNICAL USERS ---
    elements.append(Paragraph("What This Report Means For You", heading_style))
    elements.append(Spacer(1, 12))

    # Simple explanation of what vulnerabilities are
    elements.append(Paragraph(
        "This report found security vulnerabilities in software installed on your computer. " +
        "A vulnerability is like a weak spot in your software that could potentially be exploited by hackers. " +
        "The higher the severity level, the more urgent it is to address the issue.",
        body_style
    ))
    elements.append(Spacer(1, 12))

    # Key findings in simple language
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

    # What to do next - simple action steps
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

    # Add pie chart
    if os.path.exists(pie_chart_path):
        elements.append(Paragraph("Vulnerability Severity Overview", heading2_style))
        elements.append(Spacer(1, 6))
        img = Image(pie_chart_path, width=400, height=300)
        elements.append(img)

        # Add legend explaining severity levels
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("Understanding Severity Levels:", heading2_style))
        elements.append(Spacer(1, 6))

        severity_explanation = """
        <b>Critical</b>: Urgent security issues that could allow attackers to take control of your computer or steal sensitive information.<br/><br/>

        <b>High</b>: Serious vulnerabilities that should be fixed as soon as possible to protect your system.<br/><br/>

        <b>Medium</b>: Important issues that should be addressed during your next regular maintenance.<br/><br/>

        <b>Low</b>: Minor security weaknesses that pose limited risk.<br/><br/>

        """
        elements.append(Paragraph(severity_explanation, body_style))

    elements.append(PageBreak())
    # --- END OF ENHANCED SECTION ---

    # Summary table data
    elements.append(Paragraph("Detailed Summary", heading_style))
    elements.append(Spacer(1, 12))

    data = [["Severity", "Count", "Action Required"]]

    # Sort by priority
    for severity in ["Critical", "High", "Medium", "Low", "None"]:
        count = all_severities.get(severity, 0)
        if count > 0:
            data.append([
                severity,
                count,
                SEVERITY_CLASSES[severity]["action"]
            ])

    # Create table
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

    # Page break before detailed findings
    elements.append(Paragraph("Detailed Findings", heading_style))
    elements.append(Spacer(1, 12))

    # Sort programs by their highest severity vulnerability
    def get_highest_severity(program_cves):
        highest = -1
        for _, score in program_cves[1]:
            if score is not None and float(score) > highest:
                highest = float(score)
        return highest

    sorted_programs = sorted(grouped.items(), key=get_highest_severity, reverse=True)

    # Program details
    for (prog_name, prog_version), cves in sorted_programs:
        severity_counts = Counter(classify_cvss(score) for _, score in cves)

        # Determine highest severity
        highest_severity = "None"
        for severity in ["Critical", "High", "Medium", "Low", "None"]:
            if severity_counts[severity] > 0:
                highest_severity = severity
                break

        # Program heading with color-coded severity
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

        # Add simple explanation for this program
        if highest_severity in ["Critical", "High"]:
            action_text = f"<b>Recommended Action</b>: {action} - This software has serious security issues that need attention."
        elif highest_severity == "Medium":
            action_text = f"<b>Recommended Action</b>: {action} - This software has important but less urgent security issues."
        else:
            action_text = f"<b>Recommended Action</b>: {action} - This software has minor security concerns."

        elements.append(Paragraph(action_text, body_style))
        elements.append(Spacer(1, 6))

        # Vulnerability statistics
        elements.append(Paragraph(f"Total vulnerabilities: {len(cves)}", body_style))
        elements.append(Paragraph(
            f"Severity breakdown: Critical: {severity_counts['Critical']}, " +
            f"High: {severity_counts['High']}, Medium: {severity_counts['Medium']}, " +
            f"Low: {severity_counts['Low']}", body_style
        ))
        elements.append(Spacer(1, 12))

        # If there are detailed findings for this program
        if (prog_name, prog_version) in full_details:
            # Sort details by severity
            sorted_details = sorted(
                full_details[(prog_name, prog_version)],
                key=lambda x: float(-999 if x[2] is None else x[2]),
                reverse=True
            )

            # Show top vulnerabilities (limit to 5 to keep report manageable)
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

    # Build the PDF
    doc.build(elements)
    print(f"PDF report generated: {pdf_filename}")

    # Delete the pie chart image after the PDF has been generated
    try:
        if os.path.exists(pie_chart_path):
            os.remove(pie_chart_path)
            print(f"Deleted temporary pie chart: {pie_chart_path}")
    except Exception as e:
        print(f"Warning: Could not delete pie chart file: {e}")

    return pdf_filename