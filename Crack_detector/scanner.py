import os
import socket
import winreg
import json
from datetime import datetime
from sshtunnel import SSHTunnelForwarder
import mysql.connector
import psutil

# =========================
# CONFIG
# =========================
SSH_HOST = "152.42.228.57"
SSH_PORT = 22
SSH_USER = "root"
SSH_PASSWORD = "ia5lnbvo8j"

REMOTE_DB_HOST = "127.0.0.1"
REMOTE_DB_PORT = 3306

MYSQL_USER = "romel"
MYSQL_PASSWORD = "ia5lnbvo8j"
MYSQL_DATABASE = "dsg_it"

SUSPICIOUS_KEYWORDS = [
    "kms",
    "kmspico",
    "autokms",
    "keygen",
    "crack",
    "activator",
    "patcher",
    "loader",
    "re-loader",
    "chew-wga",
    "microsoft toolkit",
    "vlmcsd"
]

# =========================
# HELPERS
# =========================
def contains_suspicious_keyword(text):
    if not text:
        return False
    text = str(text).lower()
    return any(keyword in text for keyword in SUSPICIOUS_KEYWORDS)


def get_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return os.environ.get("COMPUTERNAME", "UNKNOWN-HOST")


def get_primary_mac_address():
    try:
        for interface_name, addresses in psutil.net_if_addrs().items():
            for addr in addresses:
                # AF_LINK on Windows usually contains MAC
                if getattr(addr, "family", None) == psutil.AF_LINK:
                    mac = addr.address.replace("-", ":").strip()
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
    except Exception:
        pass
    return "00:00:00:00:00:00"


# =========================
# INSTALLED SOFTWARE
# =========================
def get_installed_software_from_key(root, path):
    software_list = []

    try:
        registry_key = winreg.OpenKey(root, path)
    except FileNotFoundError:
        return software_list

    try:
        count = winreg.QueryInfoKey(registry_key)[0]
        for i in range(count):
            try:
                subkey_name = winreg.EnumKey(registry_key, i)
                subkey_path = path + "\\" + subkey_name
                subkey = winreg.OpenKey(root, subkey_path)

                def get_value(name):
                    try:
                        value, _ = winreg.QueryValueEx(subkey, name)
                        return str(value)
                    except FileNotFoundError:
                        return ""
                    except Exception:
                        return ""

                display_name = get_value("DisplayName")
                if not display_name.strip():
                    continue

                software_list.append({
                    "software_name": display_name,
                    "version": get_value("DisplayVersion"),
                    "publisher": get_value("Publisher"),
                    "install_date": get_value("InstallDate"),
                    "install_location": get_value("InstallLocation"),
                    "uninstall_string": get_value("UninstallString"),
                    "display_icon": get_value("DisplayIcon"),
                    "registry_path": subkey_path
                })

            except Exception:
                continue

    except Exception:
        pass

    return software_list


def get_installed_software():
    results = []

    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for root, path in uninstall_paths:
        results.extend(get_installed_software_from_key(root, path))

    unique = {}
    for item in results:
        key = (
            item["software_name"].strip().lower(),
            item["version"].strip().lower(),
            item["publisher"].strip().lower()
        )
        if key not in unique:
            unique[key] = item

    return list(unique.values())


def detect_suspicious_software(installed_software):
    alerts = []

    for app in installed_software:
        blob = " ".join([
            app.get("software_name", ""),
            app.get("publisher", ""),
            app.get("install_location", ""),
            app.get("uninstall_string", "")
        ])

        if contains_suspicious_keyword(blob):
            alerts.append({
                "rule_id": "SW-001",
                "severity": "high",
                "title": "Suspicious software name/publisher",
                "source": "installed_software",
                "entity": app.get("software_name", ""),
                "evidence": blob,
                "recommendation": "Remove the software and investigate installer source."
            })

    return alerts


# =========================
# PROCESS SCAN
# =========================
def get_running_processes():
    processes = []

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid", "create_time"]):
        try:
            info = proc.info
            cmdline = " ".join(info.get("cmdline") or [])

            processes.append({
                "process_id": info.get("pid"),
                "process_name": info.get("name") or "",
                "parent_process_id": info.get("ppid"),
                "executable_path": info.get("exe") or "",
                "command_line": cmdline,
                "creation_time": str(info.get("create_time") or "")
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return processes


def detect_suspicious_processes(processes):
    alerts = []

    for proc in processes:
        blob = " ".join([
            str(proc.get("process_name", "")),
            str(proc.get("command_line", "")),
            str(proc.get("executable_path", ""))
        ])

        if contains_suspicious_keyword(blob):
            alerts.append({
                "rule_id": "PR-001",
                "severity": "high",
                "title": "Suspicious process indicator",
                "source": "process",
                "entity": proc.get("process_name", ""),
                "evidence": blob,
                "recommendation": "Investigate this running process and the file path immediately."
            })

    return alerts


# =========================
# REPORT / DB
# =========================
def get_overall_severity(alerts):
    severities = [a.get("severity", "").lower() for a in alerts]

    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    if "low" in severities:
        return "low"
    return "clean"


def build_report():
    hostname = get_hostname()
    mac_address = get_primary_mac_address()

    installed_software = get_installed_software()
    software_alerts = detect_suspicious_software(installed_software)

    running_processes = get_running_processes()
    process_alerts = detect_suspicious_processes(running_processes)

    alerts = software_alerts + process_alerts
    overall_severity = get_overall_severity(alerts)

    report = {
        "report_metadata": {
            "generated_utc": datetime.utcnow().isoformat(),
            "hostname": hostname,
            "primary_mac_address": mac_address,
            "overall_severity": overall_severity
        },
        "inventory_counts": {
            "installed_software": len(installed_software),
            "running_processes": len(running_processes),
            "alerts": len(alerts)
        },
        "inventory": {
            "installed_software": installed_software,
            "running_processes": running_processes
        },
        "alerts": alerts
    }

    return report, overall_severity, hostname, mac_address


def insert_report_to_db(report, severity, hostname, mac_address):
    result_json = json.dumps(report)

    print("Opening SSH tunnel...")
    with SSHTunnelForwarder(
        (SSH_HOST, SSH_PORT),
        ssh_username=SSH_USER,
        ssh_password=SSH_PASSWORD,
        remote_bind_address=(REMOTE_DB_HOST, REMOTE_DB_PORT)
    ) as tunnel:
        local_port = tunnel.local_bind_port
        print(f"SSH tunnel opened on local port: {local_port}")

        print("Connecting to MySQL...")
        conn = mysql.connector.connect(
            host="127.0.0.1",
            port=local_port,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE
        )

        cursor = conn.cursor()

        sql = """
        INSERT INTO soft_inv (computer_name, severity, mac_address, result)
        VALUES (%s, %s, %s, %s)
        """

        cursor.execute(sql, (hostname, severity, mac_address, result_json))
        conn.commit()

        print("Insert successful.")

        cursor.close()
        conn.close()


def main():
    print("Collecting installed software...")
    print("Collecting running processes...")

    report, severity, hostname, mac_address = build_report()

    print(f"Hostname: {hostname}")
    print(f"MAC Address: {mac_address}")
    print(f"Installed software count: {report['inventory_counts']['installed_software']}")
    print(f"Running processes count: {report['inventory_counts']['running_processes']}")
    print(f"Alert count: {report['inventory_counts']['alerts']}")
    print(f"Overall severity: {severity}")

    if report["alerts"]:
        print("\nTop alerts:")
        for i, alert in enumerate(report["alerts"][:10], start=1):
            print(f"{i}. [{alert['severity'].upper()}] {alert['title']} -> {alert['entity']}")

    insert_report_to_db(report, severity, hostname, mac_address)

    print("Done.")


if __name__ == "__main__":
    main()