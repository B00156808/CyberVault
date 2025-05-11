"""
Network connectivity utilities for CyberVault.
Provides functionality to check and monitor internet connectivity.
"""

import socket
import threading
import time
from PyQt5.QtCore import QObject, pyqtSignal


def check_internet_connection(test_url="8.8.8.8", port=53, timeout=3):
    """
    Check if there is an internet connection by trying to connect to Google's DNS server.

    Args:
        test_url (str): The URL to test connection with (default is Google's DNS)
        port (int): The port to use for the connection test
        timeout (int): Connection timeout in seconds

    Returns:
        bool: True if connected, False otherwise
    """
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((test_url, port))
        return True
    except (socket.timeout, socket.error):
        return False
    except Exception as e:
        print(f"Unexpected error checking internet connection: {e}")
        return False


class NetworkMonitor(QObject):
    """Monitor network connectivity and emit signals when status changes."""

    # Define signals
    connection_established = pyqtSignal()
    connection_lost = pyqtSignal()

    def __init__(self, check_interval=5):
        """
        Initialize the network monitor.

        Args:
            check_interval (int): How often to check connectivity in seconds
        """
        super().__init__()
        self.check_interval = check_interval
        self.is_running = False
        self.was_connected = None
        self.monitor_thread = None

    def _monitor_connection(self):
        """Monitor internet connection continuously."""
        self.is_running = True

        while self.is_running:
            is_connected = check_internet_connection()

            # first check, store the state
            if self.was_connected is None:
                self.was_connected = is_connected
            # If state changed from disconnected to connected
            elif not self.was_connected and is_connected:
                self.connection_established.emit()
            # If state changed from connected to disconnected
            elif self.was_connected and not is_connected:
                self.connection_lost.emit()

            # Update the previous state
            self.was_connected = is_connected

            # Wait before next check
            time.sleep(self.check_interval)

    def start_monitoring(self):
        """Start monitoring the network connection in a separate thread."""
        if not self.is_running:
            self.monitor_thread = threading.Thread(target=self._monitor_connection)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop monitoring the network connection."""
        self.is_running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=1)