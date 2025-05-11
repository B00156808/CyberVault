# tests/frontend/test_scan_results_page.py
import pytest
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QTextEdit, QPushButton, QProgressBar,
    QVBoxLayout, QHBoxLayout
)
# QMessageBox will be mocked via its original path
from PyQt5.QtCore import Qt
import os
import sys # For mocking sys.platform
import subprocess # For mocking subprocess.run
from collections import Counter
from datetime import datetime # For type hinting and creating datetime objects

# Import the class we are testing
from src.frontend.components.scan_results_page import ScanResultsPage

@pytest.fixture
def mock_pie_chart(mocker):
    """Mocks the VulnerabilityPieChart instance created by ScanResultsPage."""
    mock_chart_instance = mocker.MagicMock(name="MockedPieChartInstance")
    # ScanResultsPage has 'from ..utils.chart_utils import VulnerabilityPieChart'
    mocker.patch('src.frontend.components.scan_results_page.VulnerabilityPieChart',
                 return_value=mock_chart_instance)
    return mock_chart_instance

@pytest.fixture(scope="session")
def qt_app():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app

# --- Kept Tests (Previously Passing or Close) ---

def test_scan_results_page_initialization(qt_app, mock_pie_chart, mocker):
    # Mock layout methods broadly for this initialization test
    mocker.patch.object(QVBoxLayout, 'addWidget')
    mocker.patch.object(QVBoxLayout, 'addLayout')
    mocker.patch.object(QHBoxLayout, 'addWidget')
    mocker.patch.object(QHBoxLayout, 'addLayout')

    page = ScanResultsPage() # This calls initUI

    assert isinstance(page.timestamp_label, QLabel)
    assert page.pie_chart == mock_pie_chart
    assert isinstance(page.severity_list, QTextEdit)
    assert isinstance(page.result_text, QTextEdit)
    assert isinstance(page.report_button, QPushButton)
    assert isinstance(page.progress_bar, QProgressBar)
    assert isinstance(page.progress_label, QLabel)
    assert page.timestamp_label.text() == ""
    assert page.report_button.isVisible() is False
    assert page.progress_bar.isVisible() is False
    assert page.progress_label.isVisible() is False
    assert page.pdf_report_path is None

@pytest.mark.parametrize("path_exists_val, report_path, expected_visibility", [
    (True, "/fake/report.pdf", True), (False, "/fake/nonexistent.pdf", False),
    (True, None, False), (True, "", False)
])
def test_set_pdf_report_path_visibility(qt_app, mocker, path_exists_val, report_path, expected_visibility):
    # scan_results_page.py uses 'import os', so patch 'os.path.exists'
    mocker.patch('os.path.exists', return_value=path_exists_val) # Target global os.path.exists
    # Minimal mocks to allow ScanResultsPage to instantiate
    mocker.patch.object(QVBoxLayout, 'addWidget'); mocker.patch.object(QHBoxLayout, 'addWidget')
    mocker.patch.object(QVBoxLayout, 'addLayout'); mocker.patch.object(QHBoxLayout, 'addLayout')
    mocker.patch('src.frontend.components.scan_results_page.VulnerabilityPieChart')

    page = ScanResultsPage()
    page.report_button.setVisible(False)
    page.set_pdf_report_path(report_path)
    assert page.pdf_report_path == report_path
    assert page.report_button.isVisible() == expected_visibility

def test_show_progress_updates_widgets(qt_app, mocker):
    mocker.patch.object(QVBoxLayout, 'addWidget'); mocker.patch.object(QHBoxLayout, 'addWidget')
    mocker.patch.object(QVBoxLayout, 'addLayout'); mocker.patch.object(QHBoxLayout, 'addLayout')
    mocker.patch('src.frontend.components.scan_results_page.VulnerabilityPieChart')
    page = ScanResultsPage()
    page.show_progress(50, "Scanning...")
    assert page.progress_bar.value() == 50
    assert page.progress_label.text() == "Scanning..."
    assert page.progress_bar.isVisible() is True
    assert page.progress_label.isVisible() is True

# Fixture for open_pdf_report related mocks
@pytest.fixture
def mock_report_utils_passing(mocker):
    mocks = {
        'exists': mocker.patch('os.path.exists', return_value=True), # Default to True
        'listdir': mocker.patch('os.listdir', return_value=[]),    # Default to no files
         # For other os functions, if needed by a test that's kept:
        'getmtime': mocker.patch('os.path.getmtime', return_value=0),
        'startfile': mocker.patch('os.startfile', side_effect=AttributeError("Mocked os.startfile")), # Keep this structure
        'run': mocker.patch('subprocess.run'),
        'sys_platform': mocker.patch('sys.platform', return_value="win32")
    }
    # Patch REPORTS_DIR where it's defined, as it's imported by name in open_pdf_report
    mocker.patch('src.config.settings.REPORTS_DIR', "C:/mock_reports_dir", create=True)
    # Patch QMessageBox.information where it's defined, as it's imported by name in open_pdf_report
    mocks['qmessagebox_info'] = mocker.patch('PyQt5.QtWidgets.QMessageBox.information')
    return mocks

def test_open_pdf_report_no_reports_shows_messagebox(qt_app, mocker, mock_report_utils_passing):
    # Minimal mocks for ScanResultsPage instantiation
    mocker.patch.object(QVBoxLayout, 'addWidget'); mocker.patch.object(QHBoxLayout, 'addWidget')
    mocker.patch.object(QVBoxLayout, 'addLayout'); mocker.patch.object(QHBoxLayout, 'addLayout')
    mocker.patch('src.frontend.components.scan_results_page.VulnerabilityPieChart')

    # Configure mocks for this specific scenario from the fixture
    mock_report_utils_passing['listdir'].return_value = [] # Ensure no files are found

    # Ensure the REPORTS_DIR itself is seen as existing for the os.listdir call
    def exists_side_effect_dir_only(path_to_check):
        if path_to_check == "C:/mock_reports_dir": # This is what REPORTS_DIR is mocked to
            return True
        return False # Other paths (like specific PDF files) might not exist
    mock_report_utils_passing['exists'].side_effect = exists_side_effect_dir_only

    page = ScanResultsPage()
    page.pdf_report_path = None # Ensure we trigger the "find latest report" logic
    page.open_pdf_report()

    # Assert that QMessageBox.information was called
    mock_report_utils_passing['qmessagebox_info'].assert_called_once()
    # Assert that the message content is as expected
    assert "No PDF reports were found" in mock_report_utils_passing['qmessagebox_info'].call_args.args[2]


# --- Tests that were previously failing (COMPLETELY REMOVED as requested) ---
# test_initui_header_setup (Removed due to TypeError: addWidget)
# test_update_results_no_vulnerabilities (Removed due to TypeError: cannot set 'now' attribute)
# test_update_results_with_vulnerabilities (Removed due to TypeError: cannot set 'now' attribute)
# test_open_pdf_report_with_existing_path (Removed due to AssertionError: startfile)
# test_open_pdf_report_no_path_finds_latest (Removed due to AssertionError: startfile)

# You should have 4 tests defined above. If 7 were passing before, it means
# 3 of the removed tests were actually passing. You can selectively re-add them
# and we can debug them one by one.
# The most likely candidates from the removed list that *might* have been passing
# (or were very close) are the ones that didn't involve the tricky `datetime.now` or `os.startfile` directly.
# For example, test_initui_header_setup could be simplified further.