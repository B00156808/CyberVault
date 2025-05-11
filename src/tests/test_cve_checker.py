# tests/backend/test_cve_checker.py
import pytest
# We only need Counter if we unskip the run_scan tests later.
# from collections import Counter

# Import the specific function we are primarily testing from cve_checker
from src.backend.cve_checker import ensure_database_exists
# from src.backend.cve_checker import run_scan # Keep commented for now

@pytest.fixture(autouse=True) # Run this fixture automatically for all tests in this file
def mock_cve_checker_dependencies(mocker):
    """Mocks essential dependencies for cve_checker.py for all tests in this module."""

    # 1. Mock settings used by cve_checker.py at its module level (for OUTPUT_DIR)
    #    cve_checker.py does 'from ..config.settings import REPORTS_DIR'
    #    So, we patch 'src.config.settings.REPORTS_DIR'
    mocker.patch('src.config.settings.REPORTS_DIR', "mocked_reports_dir_for_cve_checker_tests")
    #    DB_FILE is used by the .database module, not directly by cve_checker's own logic being tested here.
    #    Patching it ensures consistency if the underlying (mocked) .database calls were to somehow
    #    depend on it in an unexpected way during these high-level tests.
    mocker.patch('src.config.settings.DB_FILE', "mocked_db_file_for_cve_checker_tests.db", create=True)


    # 2. Mock os functions used at cve_checker.py module level for OUTPUT_DIR creation
    #    cve_checker.py does 'import os' and then 'os.path.exists' and 'os.makedirs'.
    #    So, we patch these global os functions.
    mocker.patch('os.path.exists', return_value=True)  # Assume OUTPUT_DIR "exists" by default
    mocker.patch('os.makedirs')                       # So makedirs is not called by default for OUTPUT_DIR

    # 3. Mock functions that cve_checker.py imports from its sibling '.database' module.
    #    cve_checker.py has: from .database import verify_database, download_cve_database, etc.
    #    This means these names ('verify_database', etc.) are in cve_checker's namespace.
    #    So we patch them as attributes of the cve_checker module.
    db_mocks = {
        'verify_database': mocker.patch('src.backend.cve_checker.verify_database'),
        'download_cve_database': mocker.patch('src.backend.cve_checker.download_cve_database'),
        'create_db': mocker.patch('src.backend.cve_checker.create_db'),
        'populate_test_data': mocker.patch('src.backend.cve_checker.populate_test_data')
    }

    # Mock other direct dependencies if needed by active tests (run_scan uses these)
    # mocker.patch('src.backend.cve_checker.match_installed_software')
    # mocker.patch('src.backend.cve_checker.generate_pdf_report')

    # 4. Mock standard library functions that cve_checker.py imports and uses directly.
    #    cve_checker.py run_scan() has 'import time' and then calls 'time.sleep()'.
    #    We patch 'time.sleep' at its source.
    mocker.patch('time.sleep')
    #    cve_checker.py run_scan() has 'import traceback' and then calls 'traceback.print_exc()'.
    #    We patch 'traceback.print_exc' at its source.
    mocker.patch('traceback.print_exc')

    # Return the mocks that the active tests will need to configure.
    # For the two active tests below, we only need 'db_mocks'.
    return {"db": db_mocks}

# --- Minimal and Focused Tests for ensure_database_exists ---

def test_db_is_fine_initially(mock_cve_checker_dependencies, capsys):
    """Test: ensure_database_exists when the first verify_database() call returns True."""
    db_mocks = mock_cve_checker_dependencies['db']
    db_mocks['verify_database'].return_value = True # Configure the mock

    result = ensure_database_exists() # Call the function from cve_checker

    assert result is True
    db_mocks['verify_database'].assert_called_once()
    db_mocks['download_cve_database'].assert_not_called()
    db_mocks['create_db'].assert_not_called()
    db_mocks['populate_test_data'].assert_not_called()
    # Check for the specific print from cve_checker.py based on its logic
    assert "Database verified and ready." in capsys.readouterr().out

def test_all_db_setup_attempts_fail(mock_cve_checker_dependencies, capsys):
    """Test: ensure_database_exists when all underlying database operations fail."""
    db_mocks = mock_cve_checker_dependencies['db']
    db_mocks['verify_database'].return_value = False     # verify_database always fails
    db_mocks['download_cve_database'].return_value = False # download_cve_database fails
    db_mocks['create_db'].return_value = False           # create_db fails
    # populate_test_data should not be called if create_db returns False

    result = ensure_database_exists() # Call the function from cve_checker

    assert result is False
    # Based on cve_checker.ensure_database_exists logic:
    # 1. verify_database() (initial) -> False
    # 2. download_cve_database() -> False
    #    (The inner 'if verify_database()' after download is skipped because download_cve_database returned False)
    # 3. create_db() -> False
    #    (populate_test_data and the final verify_database are skipped because create_db returned False)
    db_mocks['verify_database'].assert_called_once() # Only the initial call
    db_mocks['download_cve_database'].assert_called_once()
    db_mocks['create_db'].assert_called_once()
    db_mocks['populate_test_data'].assert_not_called()
    assert "Failed to set up database." in capsys.readouterr().out

# --- All other tests are effectively removed for this very short version ---
# You can uncomment them one by one later.