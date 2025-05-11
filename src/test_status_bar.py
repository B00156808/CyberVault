# tests/frontend/test_status_bar.py
import pytest
from PyQt5.QtWidgets import QApplication, QLabel, QStatusBar # Added QStatusBar
from PyQt5.QtGui import QColor # QColor might be needed if testing paintEvent aspects

# Ensure QApplication instance exists for widget tests
_app = None
def get_app_instance():
    global _app
    if _app is None:
        _app = QApplication.instance()
        if _app is None:
            _app = QApplication([])
    return _app

from src.frontend.components.status_bar import ConnectionStatusIndicator, StatusBar

def test_connection_indicator_initial_state():
    """Test the initial state of the ConnectionStatusIndicator."""
    get_app_instance() # Ensure QApplication exists
    indicator = ConnectionStatusIndicator()
    assert indicator.connected is True

def test_connection_indicator_set_connected_true_to_false(mocker):
    """Test changing connection status from True to False."""
    get_app_instance()
    indicator = ConnectionStatusIndicator()
    # Spy on the update method to ensure it's called when status changes
    mocker.spy(indicator, 'update')

    indicator.set_connected(False)
    assert indicator.connected is False
    indicator.update.assert_called_once()

def test_connection_indicator_set_connected_false_to_true(mocker):
    """Test changing connection status from False to True."""
    get_app_instance()
    indicator = ConnectionStatusIndicator()
    indicator.connected = False # Start as disconnected for this test
    mocker.spy(indicator, 'update')

    indicator.set_connected(True)
    assert indicator.connected is True
    indicator.update.assert_called_once()

def test_connection_indicator_set_connected_no_change(mocker):
    """Test setting the same connection status does not trigger update."""
    get_app_instance()
    indicator = ConnectionStatusIndicator() # Starts connected by default
    mocker.spy(indicator, 'update')

    indicator.set_connected(True) # Set to the already current state
    assert indicator.connected is True
    indicator.update.assert_not_called() # update() should not be called if state doesn't change

def test_status_bar_initUI_widgets_created_and_initial_text(mocker):
    """Test StatusBar initialization creates necessary widgets and sets initial text."""
    get_app_instance()
    # Mock QStatusBar's methods that add widgets to avoid actual UI rendering issues
    # and to allow us to check if they were called.
    mock_add_widget = mocker.patch.object(QStatusBar, 'addWidget')
    mock_add_permanent_widget = mocker.patch.object(QStatusBar, 'addPermanentWidget')

    status_bar = StatusBar()

    assert isinstance(status_bar.connection_indicator, ConnectionStatusIndicator)
    assert isinstance(status_bar.connection_label, QLabel)
    assert status_bar.connection_label.text() == "Connected" # Check initial text

    # Verify that addWidget was called for the indicator and label
    # This checks if they were added to the status bar's layout
    assert mock_add_widget.call_count == 2 # Called for indicator and label
    mock_add_widget.assert_any_call(status_bar.connection_indicator)
    mock_add_widget.assert_any_call(status_bar.connection_label)

    # Check if addPermanentWidget was called (for the version label)
    mock_add_permanent_widget.assert_called_once()
   
def test_status_bar_update_connection_status_to_connected(mocker):
    """Test updating status bar to connected."""
    get_app_instance()
    mocker.patch.object(QStatusBar, 'addWidget') # Mock to simplify setup
    mocker.patch.object(QStatusBar, 'addPermanentWidget') # Mock to simplify setup
    status_bar = StatusBar()
    # Spy on the set_connected method of the ConnectionStatusIndicator instance
    mocker.spy(status_bar.connection_indicator, 'set_connected')

    status_bar.update_connection_status(True)

    status_bar.connection_indicator.set_connected.assert_called_once_with(True)
    assert status_bar.connection_label.text() == "Connected"
    assert "color: white;" in status_bar.connection_label.styleSheet()

def test_status_bar_update_connection_status_to_disconnected(mocker):
    """Test updating status bar to disconnected."""
    get_app_instance()
    mocker.patch.object(QStatusBar, 'addWidget') # Mock to simplify setup
    mocker.patch.object(QStatusBar, 'addPermanentWidget') # Mock to simplify setup
    status_bar = StatusBar()
    mocker.spy(status_bar.connection_indicator, 'set_connected')

    status_bar.update_connection_status(False)

    status_bar.connection_indicator.set_connected.assert_called_once_with(False)
    assert status_bar.connection_label.text() == "Disconnected"
    assert "color: #ff5555;" in status_bar.connection_label.styleSheet()
