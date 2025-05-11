# tests/backend/test_scanner.py
import pytest
from collections import Counter # Used by scanner.py, good to have if testing match_installed_software
from datetime import datetime # For mocking datetime.now later

# Attempt to import SEVERITY_THRESHOLDS as scanner.py would.
# scanner.py (in src/backend/) uses 'from ..config.constants import SEVERITY_THRESHOLDS'
# This means constants.py is expected in src/config/
# For tests, if PYTHONPATH is set up (e.g. via pyproject.toml to include 'src' or '.'),
# this should resolve.
try:
    from src.config.constants import SEVERITY_THRESHOLDS
except ImportError:
    # This fallback is primarily for environments where test path setup might be tricky initially.
    # Ideally, the test environment should mirror the application's import capabilities.
    print("WARNING: Could not import SEVERITY_THRESHOLDS from src.config.constants. "
          "Using a hardcoded fallback for testing classify_cvss. "
          "Ensure your PYTHONPATH is correctly configured for pytest to find 'src'.")
    SEVERITY_THRESHOLDS = {
        "Critical": 9.0,
        "High": 7.0,
        "Medium": 4.0,
        "Low": 0.1,
        # "None" severity is usually for scores of 0.0 or where no score is applicable.
        # The classify_cvss function handles 0.0 specifically as "None".
    }

# Import the functions to be tested from src.backend.scanner
# This assumes scanner.py is in src/backend/
from src.backend.scanner import classify_cvss #, get_installed_programs, match_installed_software


# --- Tests for classify_cvss ---

@pytest.mark.parametrize("score, expected_severity", [
    (None, "Unknown"),
    (0.0, "None"),
    (0.09, "None"), # Just below "Low" threshold
    (0.1, "Low"),
    (3.9, "Low"),
    (3.99, "Low"), # Just below "Medium" threshold
    (4.0, "Medium"),
    (6.9, "Medium"),
    (6.99, "Medium"), # Just below "High" threshold
    (7.0, "High"),
    (8.9, "High"),
    (8.99, "High"), # Just below "Critical" threshold
    (9.0, "Critical"),
    (10.0, "Critical"),
    ("7.5", "High"), # Test with string input that needs float conversion
    ("0.0", "None"),
    ("9.8", "Critical"),
])
def test_classify_cvss_various_scores(score, expected_severity):
    """Test classify_cvss with a range of CVSS scores, including None and string inputs."""
    assert classify_cvss(score) == expected_severity

def test_classify_cvss_boundary_values_from_constants():
    """Test scores exactly at the boundaries defined in SEVERITY_THRESHOLDS."""
    if "Low" in SEVERITY_THRESHOLDS: # Check if key exists, useful if fallback is used
        assert classify_cvss(SEVERITY_THRESHOLDS["Low"]) == "Low" # e.g., 0.1 should be Low
        if SEVERITY_THRESHOLDS["Low"] > 0: # Avoid testing -0.09 if Low is 0.0
             assert classify_cvss(SEVERITY_THRESHOLDS["Low"] - 0.01) == "None"

    if "Medium" in SEVERITY_THRESHOLDS:
        assert classify_cvss(SEVERITY_THRESHOLDS["Medium"]) == "Medium" # e.g., 4.0 should be Medium
        assert classify_cvss(SEVERITY_THRESHOLDS["Medium"] - 0.01) == "Low"

    if "High" in SEVERITY_THRESHOLDS:
        assert classify_cvss(SEVERITY_THRESHOLDS["High"]) == "High" # e.g., 7.0 should be High
        assert classify_cvss(SEVERITY_THRESHOLDS["High"] - 0.01) == "Medium"

    if "Critical" in SEVERITY_THRESHOLDS:
        assert classify_cvss(SEVERITY_THRESHOLDS["Critical"]) == "Critical" # e.g., 9.0 should be Critical
        assert classify_cvss(SEVERITY_THRESHOLDS["Critical"] - 0.01) == "High"


# --- Placeholder for get_installed_programs tests (requires heavy mocking) ---

@pytest.mark.skip(reason="get_installed_programs requires extensive mocking of winreg and subprocess")
def test_get_installed_programs_example(mocker):
    # Conceptual outline for mocking winreg and subprocess:
    # mock_winreg_open_key = mocker.patch('winreg.OpenKey')
    # mock_winreg_query_value = mocker.patch('winreg.QueryValueEx')
    # mock_subprocess_check_output = mocker.patch('subprocess.check_output')
    # ... configure return values and side effects for these mocks ...
    # programs = get_installed_programs()
    # assert ("expected_program_name", "expected_version") in programs
    pass


# --- Placeholder for match_installed_software tests (requires heavy mocking) ---

@pytest.fixture
def mock_db_connection_scanner(mocker): 
    """Mocks the sqlite3 connection and cursor for scanner tests."""
    mock_conn = mocker.MagicMock(name="MockSqliteConnection")
    mock_cursor = mocker.MagicMock(name="MockSqliteCursor")
    mock_conn.cursor.return_value = mock_cursor
    # Patch sqlite3.connect as it's used by scanner.py
    mocker.patch('sqlite3.connect', return_value=mock_conn)
    return mock_conn, mock_cursor

@pytest.fixture
def mock_scanner_get_installed_programs(mocker):
    """Mocks the get_installed_programs function within the scanner module."""
    # Assuming scanner.py is src/backend/scanner.py
    return mocker.patch('src.backend.scanner.get_installed_programs')

@pytest.mark.skip(reason="match_installed_software requires extensive mocking of DB and get_installed_programs")
def test_match_installed_software_no_matches(mocker, mock_db_connection_scanner, mock_scanner_get_installed_programs):
    mock_conn, mock_cursor = mock_db_connection_scanner
    mock_scanner_get_installed_programs.return_value = [("test program", "1.0"), ("another app", "2.3.4")]
    mock_cursor.fetchall.return_value = [] # Simulate no CVEs found

    mock_fixed_dt = datetime(2023, 10, 26, 12, 0, 0)
    # Assuming scanner.py does 'from datetime import datetime' then calls 'datetime.now()'
    mocker.patch('src.backend.scanner.datetime.now', return_value=mock_fixed_dt)
    # If scanner.py does 'import datetime' then 'datetime.datetime.now()'
    # mocker.patch('datetime.datetime.now', return_value=mock_fixed_dt) # Use this if the above fails

    mocker.patch('time.sleep') # To speed up tests

    # from src.backend.scanner import match_installed_software # Ensure it's imported if not at top
    results = match_installed_software()

    assert len(results['grouped']) == 0
    assert results['severity_totals'] == Counter()
    assert results['timestamp'] == "20231026_120000"
    mock_scanner_get_installed_programs.assert_called_once()
    assert mock_cursor.execute.call_count > 0 # Check that DB was queried

@pytest.mark.skip(reason="match_installed_software requires extensive mocking")
def test_match_installed_software_with_matches(mocker, mock_db_connection_scanner, mock_scanner_get_installed_programs):
    mock_conn, mock_cursor = mock_db_connection_scanner
    mock_scanner_get_installed_programs.return_value = [("vulnerable app", "1.0")]
    mock_cursor.fetchall.return_value = [
        ("CVE-2023-1234", 7.5, "0.1", "1.5", "A high severity vulnerability.")
    ]

    mock_fixed_dt = datetime(2023, 10, 26, 12, 30, 0)
    # Adjust mock path for datetime.now based on how scanner.py imports datetime
    mocker.patch('src.backend.scanner.datetime.now', return_value=mock_fixed_dt)
    # mocker.patch('datetime.datetime.now', return_value=mock_fixed_dt) # Alternative if above fails

    mocker.patch('time.sleep')

    # from src.backend.scanner import match_installed_software # Ensure it's imported if not at top
    results = match_installed_software()

    expected_program_key = ("vulnerable app", "1.0")
    assert expected_program_key in results['grouped']
    assert results['grouped'][expected_program_key] == [("CVE-2023-1234", 7.5)]
    assert results['severity_totals'] == Counter({"High": 1})
    assert results['timestamp'] == "20231026_123000"