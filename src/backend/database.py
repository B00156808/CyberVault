import os
import json
import gzip
import sqlite3
import requests
from datetime import datetime

# Import settings
from ..config.settings import DB_FILE, BASE_URL, YEARS, MODIFIED_FEED, DATA_DIR


def create_db():
    """Create SQLite database for storing CVE information."""
    # Ensure data directory exists
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        print(f"Created data directory: {DATA_DIR}")

    print(f"Creating database at: {DB_FILE}")

    try:
        # Try to connect and create the table
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()

        # Drop the table if it exists to ensure a clean start
        c.execute('DROP TABLE IF EXISTS cves')

        # Create the table
        c.execute('''
                  CREATE TABLE cves
                  (
                      id             TEXT PRIMARY KEY,
                      vendor         TEXT,
                      product        TEXT,
                      version_start  TEXT,
                      version_end    TEXT,
                      description    TEXT,
                      published_date TEXT,
                      cvss_score     REAL
                  )
                  ''')

        # Create indices for faster queries
        c.execute('CREATE INDEX IF NOT EXISTS idx_vendor ON cves(vendor)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_product ON cves(product)')

        conn.commit()
        conn.close()
        print(f"Database initialized: {DB_FILE}")
        return True
    except sqlite3.Error as e:
        print(f"Error creating database: {e}")

        # If the file exists but is corrupt, delete it and try again
        if os.path.exists(DB_FILE):
            try:
                os.remove(DB_FILE)
                print(f"Removed corrupt database file: {DB_FILE}")
                # Try one more time
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute('''
                          CREATE TABLE cves
                          (
                              id             TEXT PRIMARY KEY,
                              vendor         TEXT,
                              product        TEXT,
                              version_start  TEXT,
                              version_end    TEXT,
                              description    TEXT,
                              published_date TEXT,
                              cvss_score     REAL
                          )
                          ''')
                conn.commit()
                conn.close()
                print(f"Successfully recreated database: {DB_FILE}")
                return True
            except Exception as e2:
                print(f"Failed to recreate database: {e2}")
                return False
        return False


def download_cve_database():
    """Download cves.db from a remote server and save it locally."""
    # Ensure data directory exists
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        print(f"Created data directory: {DATA_DIR}")

    print(f"Downloading CVE database to: {DB_FILE}")
    try:
        response = requests.get("https://malice.games/cves.db", timeout=60)
        response.raise_for_status()

        # First, write to a temporary file
        temp_file = f"{DB_FILE}.temp"
        with open(temp_file, "wb") as f:
            f.write(response.content)

        # Verify the downloaded file is a valid SQLite database
        try:
            conn = sqlite3.connect(temp_file)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cves'")
            if not cursor.fetchone():
                print("Downloaded file is not a valid CVE database (missing 'cves' table)")
                conn.close()
                os.remove(temp_file)
                return False
            conn.close()

            # If we got here, the database is valid, so move it to the final location
            if os.path.exists(DB_FILE):
                os.remove(DB_FILE)
            os.rename(temp_file, DB_FILE)
            print("CVE database downloaded and verified successfully.")
            return True
        except sqlite3.Error as e:
            print(f"Downloaded file is not a valid SQLite database: {e}")
            if os.path.exists(temp_file):
                os.remove(temp_file)
            return False

    except requests.exceptions.RequestException as e:
        print(f"Failed to download CVE database: {e}")
        return False


def populate_test_data():
    """Populate the database with a few test CVE entries to enable testing."""
    if not os.path.exists(DB_FILE):
        create_db()

    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()

        # Check if we already have data
        c.execute("SELECT COUNT(*) FROM cves")
        count = c.fetchone()[0]
        if count > 0:
            print(f"Database already contains {count} records. Skipping test data.")
            conn.close()
            return True

        # Add some test CVE entries for common software
        test_data = [
            # Windows
            ('CVE-2023-0001', 'microsoft', 'windows', '10.0', '10.0.19045', 'Test vulnerability in Windows',
             '2023-01-01', 7.5),
            ('CVE-2023-0002', 'microsoft', 'windows', '11.0', '11.0', 'Test critical vulnerability in Windows 11',
             '2023-01-15', 9.2),

            # Chrome
            ('CVE-2023-0003', 'google', 'chrome', '100.0.0.0', '110.0.0.0', 'Test vulnerability in Chrome browser',
             '2023-02-01', 8.1),
            ('CVE-2023-0004', 'google', 'chromium', '100.0.0.0', '110.0.0.0', 'Test medium severity in Chromium',
             '2023-02-15', 5.5),

            # Adobe
            ('CVE-2023-0005', 'adobe', 'acrobat', '22.0.0', '23.0.0', 'Test vulnerability in Adobe Acrobat',
             '2023-03-01', 6.8),
            ('CVE-2023-0006', 'adobe', 'reader', '22.0.0', '23.0.0', 'Test low severity in Adobe Reader', '2023-03-15',
             3.2),

            # Microsoft Office
            ('CVE-2023-0007', 'microsoft', 'office', '16.0.0', '16.0.15000', 'Test vulnerability in MS Office',
             '2023-04-01', 7.2),
            ('CVE-2023-0008', 'microsoft', 'excel', '16.0.0', '16.0.15000', 'Test high severity in Excel', '2023-04-15',
             8.7),

            # Firefox
            ('CVE-2023-0009', 'mozilla', 'firefox', '100.0', '110.0', 'Test vulnerability in Firefox browser',
             '2023-05-01', 6.5),
        ]

        # Insert test data
        c.executemany('''
                      INSERT
                      OR IGNORE INTO cves 
            (id, vendor, product, version_start, version_end, description, published_date, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                      ''', test_data)

        conn.commit()
        conn.close()
        print(f"Added {len(test_data)} test CVE entries to the database.")
        return True
    except sqlite3.Error as e:
        print(f"Error adding test data: {e}")
        return False


def verify_database():
    """Verify database exists and has the correct structure."""
    if not os.path.exists(DB_FILE):
        print(f"Database does not exist: {DB_FILE}")
        return False

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Check for cves table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cves'")
        if not cursor.fetchone():
            print("Database is missing 'cves' table")
            conn.close()
            return False

        # Check table structure
        cursor.execute("PRAGMA table_info(cves)")
        columns = [col[1] for col in cursor.fetchall()]
        expected_columns = ['id', 'vendor', 'product', 'version_start', 'version_end', 'description', 'published_date',
                            'cvss_score']

        for col in expected_columns:
            if col not in columns:
                print(f"Table is missing column: {col}")
                conn.close()
                return False

        # Check for data
        cursor.execute("SELECT COUNT(*) FROM cves")
        count = cursor.fetchone()[0]
        print(f"Database has {count} CVE entries")

        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Error verifying database: {e}")
        return False