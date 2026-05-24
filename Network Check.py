import subprocess
import platform
import json
import socket
from datetime import datetime

NETWORK_LOG = (
    "C:\\ProgramData\\DeviceCompliance\\network_log.json"
    if platform.system() == "Windows"
    else "/var/log/network_compliance.json"
)

APPROVED_DNS = ["8.8.8.8", "1.1.1.1"]
APPROVED_IP_RANGES = ["10.0.0.", "192.168.1."]
REQUIRED_VPN_PROCESS = "company_vpn"

def get_ip():
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except:
        return None

def check_ip_range(ip):
    return any(ip.startswith(prefix) for prefix in APPROVED_IP_RANGES)

def check_dns():
    output = subprocess.getoutput("nslookup google.com")
    return any(dns in output for dns in APPROVED_DNS)

def check_vpn():
    output = subprocess.getoutput(
        "tasklist" if platform.system() == "Windows" else "ps aux"
    )
    return REQUIRED_VPN_PROCESS.lower() in output.lower()

def check_firewall():
    if platform.system() == "Windows":
        output = subprocess.getoutput("netsh advfirewall show allprofiles")
        return "State ON" in output
    else:
        output = subprocess.getoutput("ufw status")
        return "active" in output.lower()

def check_edr():
    output = subprocess.getoutput("ps aux")
    return (
        "edr" in output.lower()
        or "sentinel" in output.lower()
        or "crowdstrike" in output.lower()
    )

def load_device_compliance():
    path = (
        "C:\\ProgramData\\DeviceCompliance\\compliance_log.json"
        if platform.system() == "Windows"
        else "/var/log/device_compliance.json"
    )
    try:
        with open(path, "r") as f:
            last_line = f.readlines()[-1]
            return json.loads(last_line)
    except:
        return {"status": "FAIL"}

def run_network_checks():
    ip = get_ip()
    device_status = load_device_compliance()

    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "device_name": platform.node(),
        "ip_address": ip,
        "ip_range_valid": check_ip_range(ip) if ip else False,
        "dns_valid": check_dns(),
        "vpn_connected": check_vpn(),
        "firewall_enabled": check_firewall(),
        "edr_running": check_edr(),
        "device_compliance_status": device_status.get("status", "FAIL"),
    }

    results["status"] = "PASS" if all([
        results["ip_range_valid"],
        results["dns_valid"],
        results["vpn_connected"],
        results["firewall_enabled"],
        results["edr_running"],
        results["device_compliance_status"] == "PASS",
    ]) else "FAIL"

    with open(NETWORK_LOG, "a") as f:
        f.write(json.dumps(results) + "\n")

    return results

if __name__ == "__main__":
    print(json.dumps(run_network_checks(), indent=4))
