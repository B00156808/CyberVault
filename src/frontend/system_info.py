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

def get_installed_programs_windows():
    # This is the Windows-specific function to list installed programs
    import winreg
    installed_programs = []
    uninstall_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_key)
        for i in range(winreg.QueryInfoKey(reg_key)[0]):
            try:
                subkey_name = winreg.EnumKey(reg_key, i)
                subkey = winreg.OpenKey(reg_key, subkey_name)
                display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                try:
                    display_version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                except FileNotFoundError:
                    display_version = "Version not found"
                installed_programs.append((display_name, display_version))
            except Exception as e:
                continue
        winreg.CloseKey(reg_key)
    except FileNotFoundError:
        print("No programs found in the registry.")
    return installed_programs

def get_service_version(service_name):
    # Windows-specific command to get service version info
    try:
        command = f"wmic service where the name='{service_name}' get version"
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        version = result.stdout.strip().split("\n")[1] if result.stdout else "Version info not available"
        return version
    except Exception as e:
        return f"Error obtaining version: {str(e)}"

def get_system_services():
    # This function now checks if the OS is Windows or Linux
    if platform.system() == "Windows":
        return get_system_services_windows()
    elif platform.system() == "Linux":
        return "Service iteration is only available on Windows. Current OS: Linux."
    else:
        return f"Service iteration is only available on Windows. Current OS: {platform.system()}"

def get_system_services_windows():
    # This function is Windows-specific, using psutil to get services
    services = []
    for service in psutil.win_service_iter():
        try:
            service_name = service.name()
            service_status = service.status()
            service_version = get_service_version(service_name)
            services.append((service_name, service_status, service_version))
        except Exception as e:
            continue
    return services