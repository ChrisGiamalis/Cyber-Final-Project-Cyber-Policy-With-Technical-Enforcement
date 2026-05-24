import os
import platform
import subprocess
import json
import hashlib
from datetime import datetime

# Log path varies by OS
LOG_PATH = (
    "C:\\ProgramData\\DeviceCompliance\\compliance_log.json"
    if platform.system() == "Windows"
    else "/var/log/device_compliance.json"
)

# Prohibited software list (expand as needed)
PROHIBITED_SOFTWARE = [
    "utorrent",
    "bittorrent",
    "tor browser",
    "unauthorized_vpn",
    "unknown_edr",
]

# Critical file integrity expectations
CRITICAL_FILES = {
    "/etc/hosts": "expected_hash_here",
    "/etc/passwd": "expected_hash_here",
}

def hash_file(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def check_os_version():
    return platform.platform()

def check_disk_encryption():
    system = platform.system()

    if system == "Windows":
        try:
            output = subprocess.check_output(["manage-bde", "-status"], text=True)
            return "Fully Encrypted" in output
        except:
            return False

    elif system == "Darwin":
        try:
            output = subprocess.check_output(["fdesetup", "status"], text=True)
            return "FileVault is On" in output
        except:
            return False

    else:  # Linux
        return os.path.exists("/dev/mapper/cryptroot")

def check_firewall():
    system = platform.system()

    if system == "Windows":
        output = subprocess.getoutput("netsh advfirewall show allprofiles")
        return "State ON" in output

    elif system == "Darwin":
        output = subprocess.getoutput(
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
        )
        return "enabled" in output.lower()

    else:  # Linux
        output = subprocess.getoutput("ufw status")
        return "active" in output.lower()

def check_updates():
    system = platform.system()

    if system == "Windows":
        return True  # Placeholder — Windows Update API requires admin privileges

    elif system == "Darwin":
        output = subprocess.getoutput("softwareupdate -l")
        return "No new software available" in output

    else:  # Linux
        try:
            subprocess.check_output(["apt", "update"])
            return True
        except:
            return False

def check_prohibited_software():
    system = platform.system()

    if system == "Windows":
        installed = subprocess.getoutput("wmic product get name").lower()
    elif system == "Darwin":
        installed = subprocess.getoutput("ls /Applications").lower()
    else:
        installed = subprocess.getoutput("ls /usr/bin").lower()

    return any(app.lower() in installed for app in PROHIBITED_SOFTWARE)

def check_file_integrity():
    for path, expected_hash in CRITICAL_FILES.items():
        actual = hash_file(path)
        if actual is None or actual != expected_hash:
            return False
    return True

def check_secure_boot():
    if platform.system() != "Windows":
        return True
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", "Confirm-SecureBootUEFI"], text=True
        )
        return "True" in output
    except:
        return False

def run_checks():
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "device_name": platform.node(),
        "os_version": check_os_version(),
        "disk_encryption": check_disk_encryption(),
        "firewall_enabled": check_firewall(),
        "updates_current": check_updates(),
        "secure_boot": check_secure_boot(),
        "prohibited_software_found": check_prohibited_software(),
        "critical_file_integrity": check_file_integrity(),
    }

    results["status"] = "PASS" if all([
        results["disk_encryption"],
        results["firewall_enabled"],
        results["updates_current"],
        results["secure_boot"],
        not results["prohibited_software_found"],
        results["critical_file_integrity"],
    ]) else "FAIL"

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(results) + "\n")

    return results

if __name__ == "__main__":
    print(json.dumps(run_checks(), indent=4))
