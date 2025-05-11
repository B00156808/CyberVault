"""
Main module for handling CVE checking functionality.
This module coordinates the scanning process, database operations, and report generation.
"""

import os
import sqlite3
from datetime import *

# Import from config module
from ..config.settings import DB_FILE, REPORTS_DIR

# Import from our modules
from .database import download_cve_database, create_db, verify_database, populate_test_data
from .scanner import match_installed_software
from .report_generation import generate_pdf_report

# Configuration
OUTPUT_DIR = REPORTS_DIR  # Use the path from settings

# Ensure report directory exists
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)




def ensure_database_exists():
    """Make sure the database exists and has the required tables."""
    print("Checking database...")
   
    # Get current time
    now = datetime.now()
    current_day = now.weekday()  
    current_time = now.time()
   
    # Check if scheduled server update is currently happening
    is_sunday_night = current_day == 6 and current_time >= time(23, 55)
    is_monday_early = current_day == 0 and current_time <= time(1, 0)
    in_exclusion_window = is_sunday_night or is_monday_early
   
    # First check if database exists and is valid
    if verify_database():
        if in_exclusion_window:
            print("Database is valid. Not updating during maintenance window (Sunday 23:55 - Monday 1:00).")
            return True
        else:
            print("Updating database...")
            if download_cve_database():
                if verify_database():
                    print("Updated database verified and ready.")
                    return True
                else:
                    print("Downloaded database failed verification.")
            return True
           
    # If verification failed, try to download the database
    # Even during exclusion window, we need to ensure a valid database exists
    print("Database not valid. Attempting to download...")
    if download_cve_database():
        if verify_database():
            print("Downloaded database verified and ready.")
            return True
        else:
            print("Downloaded database failed verification.")
   
    # If download failed or verification still fails, create a new database
    print("Creating new database...")
    if create_db():
        print("New database created.")
        # For testing, add some sample data so we can test the application
        print("Adding test data for development...")
        populate_test_data()
        return verify_database()
   
    print("Failed to set up database.")
    return False

def run_scan():
    """Run a complete vulnerability scan and generate a report.

    Returns:
        dict: A dictionary containing the PDF report path and scan data
    """
    print("CyberVault Vulnerability Scanner")
    print("===============================")

    # Make sure database exists and is ready
    if not ensure_database_exists():
        print("Cannot proceed with scan: Database not ready.")
        return None

    # Scan system
    print("Starting vulnerability scan...")
    try:
        # Small delay to allow the UI progress bar to update properly
        import time
        time.sleep(0.5)

        # Perform the scan
        scan_data = match_installed_software(OUTPUT_DIR)

        # Small delay for UI responsiveness
        time.sleep(0.5)

        # Generate report
        print("Generating vulnerability report...")
        pdf_path = generate_pdf_report(scan_data)

        print(f"\nScan complete! Report saved to: {pdf_path}")

        # Return both the PDF path and scan data for UI integration
        return {
            'pdf_path': pdf_path,
            'scan_data': scan_data
        }
    except Exception as e:
        print(f"Error during scan: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    """Main function to run the vulnerability scanner from command line."""
    results = run_scan()
    if results:
        print(f"Report generated successfully: {results['pdf_path']}")
    else:
        print("Scan failed to complete.")


if __name__ == "__main__":
    main()