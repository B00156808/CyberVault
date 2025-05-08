#this file is system_info.py
import subprocess
import psutil
import platform
import sys

def get_OS_platform():
    os_name = platform.system()
    return os_name

def get_OS_version():
    os_version = platform.version()
    return os_version

def get_installed_programs():
    # This function now checks if the OS is Windows or Linux
    if sys.platform == "win32":
        return get_installed_programs_windows()
    elif sys.platform == "linux" or sys.platform == "linux2":
        return "Installed programs listing is not available on Linux."
    else:
        return "Installed programs listing is only available on Windows."



