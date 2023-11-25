import os
import platform
import subprocess
import sys

def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    return output.decode().strip(), error.decode().strip(), process.returncode

def install_aircrack():
    distro = platform.linux_distribution()[0].lower()
    install_command = ''

    if distro in ('debian', 'ubuntu'):
        install_command = 'sudo apt-get install -y aircrack-ng'
    elif distro in ('fedora', 'redhat', 'centos'):
        install_command = 'sudo yum install -y aircrack-ng'
    elif distro in ('arch', 'manjaro'):
        install_command = 'sudo pacman -S --noconfirm aircrack-ng'
    elif distro in ('kali', 'parrot'):
        install_command = 'sudo apt-get install -y aircrack-ng'
    else:
        print(f"Unsupported distribution: {distro}")
        sys.exit(1)

    print(f"Installing aircrack-ng on {distro}...")
    _, error, return_code = run_command(install_command)

    if return_code != 0:
        print(f"Failed to install aircrack-ng: {error}")
        sys.exit(1)

def detect_chipset_and_enable_monitor_mode():
    print("Detecting wireless interface...")
    iwconfig_output, _, _ = run_command("iwconfig")
    
    # Extract the wireless interface from iwconfig output (assumes the first one is the wireless interface)
    wireless_interface = iwconfig_output.split(' ')[0]

    print(f"Detected wireless interface: {wireless_interface}")

    print("Checking chipset compatibility...")
    airmon_check_output, _, _ = run_command(f"airmon-ng check {wireless_interface}")

    if "Interface" not in airmon_check_output:
        print("No compatible wireless chipset found.")
        sys.exit(1)

    print("Putting the wireless interface into monitor mode...")
    _, error, return_code = run_command(f"airmon-ng start {wireless_interface}")

    if return_code != 0:
        print(f"Failed to enable monitor mode: {error}")
        sys.exit(1)

    print("Monitor mode enabled successfully.")

def main():
    install_aircrack()
    detect_chipset_and_enable_monitor_mode()

if __name__ == "__main__":
    main()
