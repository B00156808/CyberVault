
import matplotlib
matplotlib.use('Agg')

# --- Standard Library Imports ---
import os
import shutil  # For directory and file operations (e.g., removing test directories)
import sqlite3 # For interacting with the SQLite database if needed directly in tests
import sys     # For modifying Python's search path for modules

# --- Third-Party Imports ---
import pytest  # The testing framework

# --- Dynamic Path Setup for Project Modules ---
current_file_path = os.path.abspath(__file__)
# os.path.dirname(current_file_path) is .../tests/integration/
# os.path.dirname(os.path.dirname(current_file_path)) is .../tests/
# os.path.dirname(os.path.dirname(os.path.dirname(current_file_path))) is .../CyberVault-main/ (project root)
project_root_for_tests = os.path.dirname(os.path.dirname(os.path.dirname(current_file_path)))
# Add the project root to the beginning of sys.path so 'from src...' imports work.
sys.path.insert(0, project_root_for_tests)

# --- Application Module Imports ---
# Attempt to import the modules from your application that the test will interact with.
try:
    # Main function to be tested from the CVE checker module
    from src.backend.cve_checker import run_scan
    # Database utility functions
    from src.backend.database import create_db, populate_test_data
    
    # Import the modules themselves. This allows the test to modify module-level variables
    # (like DB_FILE) for testing purposes, isolating tests from actual application settings.
    import src.backend.database as database_module
    import src.backend.cve_checker as cve_checker_module
    import src.backend.report_generation as report_generation_module
    import src.backend.scanner as scanner_module # For mocking get_installed_programs
    
    # Import application settings to see original values or for reference
    from src.config import settings as config_settings 
except ImportError as e:
    # If imports fail, print helpful error messages and exit to prevent further issues.
    print(f"Critical Error: Failed to import project modules for testing: {e}")
    print(f"Calculated Project Root (should contain 'src' and 'tests' folders): {project_root_for_tests}")
    print("Please ensure:")
    print("  1. Your project structure is correct (e.g., CyberVault-main/src/backend/, CyberVault-main/src/config/).")
    print("  2. All necessary '__init__.py' files are present in 'src/', 'src/backend/', 'src/config/', 'tests/', and 'tests/integration/'.")
    print("  3. Internal imports within your 'src/backend/' files use correct relative paths (e.g., 'from .database import ...' or 'from ..config import ...').")
    sys.exit(1) # Exit the test process if essential modules can't be imported.

# --- Test Environment Configuration ---
# Define constants for paths used exclusively by the tests.
# These paths point to temporary directories that will be created for test artifacts.
TEST_BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # This test file's directory: .../tests/integration/
TEST_DATA_DIR_PYTEST = os.path.join(TEST_BASE_DIR, "test_app_data_pytest")     # For temporary test databases
TEST_REPORTS_DIR_PYTEST = os.path.join(TEST_BASE_DIR, "test_reports_pytest") # For temporary test reports
TEST_DB_FILE_PYTEST = os.path.join(TEST_DATA_DIR_PYTEST, "test_cves_pytest.db") # Specific test DB file name

# --- Pytest Fixtures: Reusable Setup and Teardown Logic ---

@pytest.fixture(scope="session", autouse=True)
def configure_paths_for_tests():
    """
    Pytest fixture to set up and tear down the test environment for the ENTIRE test session.
    - scope="session": This fixture runs once when pytest starts the session and tears down once when it ends.
    - autouse=True: This fixture will be automatically used by all tests in the session; no need to pass it as an argument.
    
    It overrides module-level path variables in your application code to point to temporary
    test directories. This isolates tests and prevents them from using or modifying actual
    application data or report locations.
    """
    print(f"\n--- (Session Fixture) Setting up Test Environment & Overriding Paths ---")
    
    # Store original paths from the application modules to restore them after the session.
    original_paths = {
        'db_module_db_file': database_module.DB_FILE,
        'db_module_data_dir': database_module.DATA_DIR,
        'cve_checker_db_file': cve_checker_module.DB_FILE,
        'cve_checker_reports_dir': cve_checker_module.REPORTS_DIR,
        'cve_checker_output_dir': cve_checker_module.OUTPUT_DIR,
        'report_gen_reports_dir': report_generation_module.REPORTS_DIR,
        'report_gen_output_dir': report_generation_module.OUTPUT_DIR,
    }
    # Useful for debugging to see what the original paths were.
    # print(f"Original DB_FILE (from config.settings via module): {original_paths['db_module_db_file']}")

    # Override paths in the imported application modules to use test-specific locations.
    database_module.DB_FILE = TEST_DB_FILE_PYTEST
    database_module.DATA_DIR = TEST_DATA_DIR_PYTEST
    cve_checker_module.DB_FILE = TEST_DB_FILE_PYTEST # ensure_database_exists uses this
    cve_checker_module.REPORTS_DIR = TEST_REPORTS_DIR_PYTEST
    cve_checker_module.OUTPUT_DIR = TEST_REPORTS_DIR_PYTEST # cve_checker.py also uses OUTPUT_DIR
    report_generation_module.REPORTS_DIR = TEST_REPORTS_DIR_PYTEST
    report_generation_module.OUTPUT_DIR = TEST_REPORTS_DIR_PYTEST # report_generation.py also uses OUTPUT_DIR

    # Clean up any old test directories and create fresh ones.
    if os.path.exists(TEST_DATA_DIR_PYTEST): shutil.rmtree(TEST_DATA_DIR_PYTEST)
    if os.path.exists(TEST_REPORTS_DIR_PYTEST): shutil.rmtree(TEST_REPORTS_DIR_PYTEST)
    os.makedirs(TEST_DATA_DIR_PYTEST)
    os.makedirs(TEST_REPORTS_DIR_PYTEST)

    print(f"Test DB will be created at: {TEST_DB_FILE_PYTEST}")
    print(f"Test Reports will be saved in: {TEST_REPORTS_DIR_PYTEST}")
    print(f"--- (Session Fixture) Path Setup Complete ---")

    yield # This is where pytest runs the collected tests for the session.

    # Teardown: This code runs after all tests in the session have completed.
    print(f"\n--- (Session Fixture) Tearing Down Test Environment & Restoring Paths ---")
    # Remove temporary test directories.
    if os.path.exists(TEST_DATA_DIR_PYTEST):
        shutil.rmtree(TEST_DATA_DIR_PYTEST)
        print(f"Removed test data directory: {TEST_DATA_DIR_PYTEST}")
    if os.path.exists(TEST_REPORTS_DIR_PYTEST):
        shutil.rmtree(TEST_REPORTS_DIR_PYTEST)
        print(f"Removed test reports directory: {TEST_REPORTS_DIR_PYTEST}")

    # Restore original paths in the application modules.
    # This is good practice if tests might be run as part of a larger suite or in an interactive session.
    database_module.DB_FILE = original_paths['db_module_db_file']
    database_module.DATA_DIR = original_paths['db_module_data_dir']
    cve_checker_module.DB_FILE = original_paths['cve_checker_db_file']
    cve_checker_module.REPORTS_DIR = original_paths['cve_checker_reports_dir']
    cve_checker_module.OUTPUT_DIR = original_paths['cve_checker_output_dir']
    report_generation_module.REPORTS_DIR = original_paths['report_gen_reports_dir']
    report_generation_module.OUTPUT_DIR = original_paths['report_gen_output_dir']
    # print(f"Restored original DB_FILE to: {database_module.DB_FILE}")
    print(f"--- (Session Fixture) Teardown Complete ---")


@pytest.fixture(scope="function")
def setup_test_database(configure_paths_for_tests): # Implicitly depends on configure_paths_for_tests (autouse)
    """
    Pytest fixture to set up a fresh, populated database for EACH test function that uses it.
    - scope="function": This fixture runs before each test function that lists it as an argument.
    
    It ensures that each test starts with a known database state.
    """
    print(f"--- (Function Fixture) Setting up Test Database for a test ---")
    # Ensure the test DB file is removed if it somehow exists from a previous, failed test within the session.
    if os.path.exists(TEST_DB_FILE_PYTEST):
        os.remove(TEST_DB_FILE_PYTEST)
    
    # Use the application's own functions to create and populate the database.
    # This also implicitly tests these database functions as part of the setup.
    assert create_db(), "Test database creation failed in 'setup_test_database' fixture."
    assert populate_test_data(), "Populating test data failed in 'setup_test_database' fixture."

    # Verify that data was actually added to the test database.
    conn = sqlite3.connect(TEST_DB_FILE_PYTEST)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cves")
    count = cursor.fetchone()[0]
    conn.close()
    assert count > 0, "Test data was not populated in the database by the 'setup_test_database' fixture."
    print(f"--- (Function Fixture) Test DB populated with {count} entries ---")
    # No need to return anything; the side effect is a ready database.

@pytest.fixture(scope="function")
def mock_installed_programs(monkeypatch):
    """
    Pytest fixture to mock (replace) the 'get_installed_programs' function from the scanner module.
    - scope="function": Applied per test function.
    - monkeypatch: A built-in pytest fixture for safely modifying objects, classes, or modules during tests.
    
    This allows the test to control the "installed software" data without actually scanning the system,
    making the test predictable and faster.
    """
    print("--- (Function Fixture) Mocking 'get_installed_programs' ---")
    def mock_get_installed_programs_func():
        # This function will replace the real get_installed_programs during the test.
        print("--- (Mock Function) Returning predefined list of 'installed' programs ---")
        return [
            ("microsoft windows", "10.0.19045"), # Designed to match an entry in populate_test_data()
            ("google chrome", "105.0.0.0"),   # Designed to match an entry in populate_test_data()
            ("non existent app", "1.0")      # Should not match any CVEs in test data
        ]
    
    # Replace the 'get_installed_programs' function in 'scanner_module' with our mock version.
    monkeypatch.setattr(scanner_module, "get_installed_programs", mock_get_installed_programs_func)
    print("--- (Function Fixture) 'get_installed_programs' has been mocked ---")

# --- The Main Integration Test Function ---
def test_run_full_scan_and_generate_report_pytest(setup_test_database, mock_installed_programs):
    """
    The core integration test.
    It verifies that the main 'run_scan' process executes successfully and produces a PDF report.
    
    - setup_test_database: This argument tells pytest to run the 'setup_test_database' fixture before this test.
    - mock_installed_programs: This argument tells pytest to run the 'mock_installed_programs' fixture.
    """
    print("\n>>> Test: 'test_run_full_scan_and_generate_report_pytest' Starting <<<")

    # At this point:
    # 1. Paths have been overridden by 'configure_paths_for_tests'.
    # 2. A fresh, populated test database has been created by 'setup_test_database'.
    # 3. 'get_installed_programs' has been mocked by 'mock_installed_programs'.

    print("--- Test: Calling the main 'run_scan()' function from 'cve_checker.py' ---")
    # Execute the primary function from your application that orchestrates the scan.
    scan_results = run_scan() 

    # --- Assertions: Verify the outcome of the scan ---
    print("--- Test: Performing assertions on scan results ---")

    # 1. Check if 'run_scan' returned a result dictionary.
    assert scan_results is not None, "'run_scan()' should return a dictionary of results, not None (which might indicate an internal error)."
    
    # 2. Check if the result dictionary contains the expected 'pdf_path' key.
    assert 'pdf_path' in scan_results, "The dictionary returned by 'run_scan()' should contain a 'pdf_path' key."
    
    pdf_report_path = scan_results['pdf_path']
    # 3. Check if the 'pdf_path' itself is not None.
    assert pdf_report_path is not None, "The 'pdf_path' value in the scan results should not be None."
    
    print(f"--- Test: 'run_scan()' reported PDF path as: {pdf_report_path} ---")

    # 4. Verify that the PDF report file actually exists at the reported path.
    assert os.path.exists(pdf_report_path), f"The PDF report file was not found at the expected path: '{pdf_report_path}'."
    
    # 5. Verify that the path is indeed a file (not a directory).
    assert os.path.isfile(pdf_report_path), f"The report path '{pdf_report_path}' exists, but it is not a file."
    
    # 6. Verify that the PDF file has a reasonable size (e.g., greater than 1KB).
    # An empty or near-empty file might indicate an error during report generation.
    report_size = os.path.getsize(pdf_report_path)
    assert report_size > 1000, \
        f"The generated PDF report '{pdf_report_path}' seems too small (size: {report_size} bytes), possibly indicating an empty or corrupted report."

    print(f">>> Test: PASSED! Report generated successfully at '{pdf_report_path}' with size {report_size} bytes. <<<")
