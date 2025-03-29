import subprocess
import psutil
import platform
import sys


"""Get functions to retrieve info about OS, installed software/applications, and system services"""

def get_OS_platform():
    os_name = platform.system()
    return os_name

def get_OS_version():
    os_version = platform.version()
    return os_version

def get_installed_programs_windows():
    if sys.platform == "win32":
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
    else:
        # Handle alternative functionality for Linux or macOS
        print("winreg is only available on Windows.")
  
# Function to get the version of the service. This will be used in get_system_services_windows() because psutil has no function to provide version *doesnt work*
def get_service_version(service_name):
    try:
        command = f"wmic service where the name='{service_name}' get version"
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        version = result.stdout.strip().split("\n")[1] if result.stdout else "Version info not available"
        return version
    except Exception as e:
        return f"Error obtaining version: {str(e)}"

# (Windows - psutil)
def get_system_services_windows():
    services = []
    for service in psutil.win_service_iter():
        try:
            service_name = service.name()
            service_status = service.status()

            # Get version using the WMIC function
            service_version = get_service_version(service_name)

            services.append((service_name, service_status, service_version))
        except Exception as e:
            continue
    return services

""" Display data from the get functions"""

def print_OS_info():
    operating_system = get_OS_platform()
    operating_system_version = get_OS_version()
    print(f"Operating System: {operating_system}, version: {operating_system_version}")

def print_installed_programs():
    programs = get_installed_programs_windows()

    print("Installed Programs:")
    for name, version in programs:
        print(f"{name} - {version}")

#  *version scraper doesnt work
def print_system_services():
    services = get_system_services_windows()

    print("\nSystem Services:")
    for name, version, status in services:
        print(f"{name} - {version} - {status}")


if __name__ == "__main__":
    print_OS_info()
    #print_installed_programs()
    #print_system_services()


