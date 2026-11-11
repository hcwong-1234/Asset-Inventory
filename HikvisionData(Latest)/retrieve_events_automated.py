import argparse
import base64
import ctypes
import json
import os
import sys
import traceback
from ctypes import wintypes
from datetime import date, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import paramiko

from retrieve_events import (
    COUNTRY_TIMEZONES,
    SFTP_DIRECTORY,
    SFTP_HOST,
    SFTP_HOST_KEY_SHA256,
    SFTP_PORT,
    SFTP_USERNAME,
    application_folder,
    create_report_files,
    prompt_country,
    prompt_devices,
    prompt_password,
    prompt_yes_no,
    retrieve_from_devices,
    upload_files_sftp,
)


CONFIG_FILENAME = "automated_config.json"
LOG_FILENAME = "automated_retriever.log"
CONFIG_VERSION = 1
CRYPTPROTECT_UI_FORBIDDEN = 0x01


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class Tee:
    """Write unattended output to both the console and a persistent log."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, value):
        for stream in self.streams:
            stream.write(value)
            stream.flush()
        return len(value)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def _require_windows():
    if os.name != "nt":
        raise RuntimeError(
            "Credential setup and unattended runs require Windows."
        )


def _blob_from_bytes(value):
    buffer = ctypes.create_string_buffer(value)
    blob = DATA_BLOB(
        len(value),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    return blob, buffer


def _windows_data_protection_apis():
    _require_windows()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    blob_pointer = ctypes.POINTER(DATA_BLOB)
    crypt32.CryptProtectData.argtypes = [
        blob_pointer,
        wintypes.LPCWSTR,
        blob_pointer,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        blob_pointer,
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        blob_pointer,
        wintypes.LPVOID,
        blob_pointer,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        blob_pointer,
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return crypt32, kernel32


def protect_secret(secret):
    """Encrypt a secret for the current Windows user using DPAPI."""
    crypt32, kernel32 = _windows_data_protection_apis()
    plaintext, plaintext_buffer = _blob_from_bytes(secret.encode("utf-8"))
    encrypted = DATA_BLOB()

    success = crypt32.CryptProtectData(
        ctypes.byref(plaintext),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(encrypted),
    )
    del plaintext_buffer
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        encrypted_bytes = ctypes.string_at(
            encrypted.pbData,
            encrypted.cbData,
        )
        return base64.b64encode(encrypted_bytes).decode("ascii")
    finally:
        kernel32.LocalFree(ctypes.cast(encrypted.pbData, ctypes.c_void_p))


def unprotect_secret(encoded_secret):
    """Decrypt a DPAPI secret for the current Windows user."""
    crypt32, kernel32 = _windows_data_protection_apis()
    encrypted_bytes = base64.b64decode(encoded_secret, validate=True)
    encrypted, encrypted_buffer = _blob_from_bytes(encrypted_bytes)
    plaintext = DATA_BLOB()

    success = crypt32.CryptUnprotectData(
        ctypes.byref(encrypted),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(plaintext),
    )
    del encrypted_buffer
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        plaintext_bytes = ctypes.string_at(
            plaintext.pbData,
            plaintext.cbData,
        )
        return plaintext_bytes.decode("utf-8")
    finally:
        kernel32.LocalFree(ctypes.cast(plaintext.pbData, ctypes.c_void_p))


def write_config(config_path, config):
    config_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = config_path.with_suffix(config_path.suffix + ".tmp")
    temporary_path.write_text(
        json.dumps(config, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(config_path)


def setup(config_path):
    _require_windows()
    if config_path.exists() and not prompt_yes_no(
        f"Replace existing configuration at {config_path}?",
        default=False,
    ):
        print("Setup cancelled. Existing configuration was not changed.")
        return 1

    print("Automated Hikvision Event Retriever setup")
    print("-" * 42)
    country, timezone = prompt_country()
    devices = prompt_devices()

    configured_devices = []
    for device in devices:
        configured_devices.append(
            {
                "name": device["name"],
                "ip": device["ip"],
                "username": device["username"],
                "password_dpapi": protect_secret(device["password"]),
            }
        )

    print()
    print(
        f"SFTP destination: {SFTP_USERNAME}@{SFTP_HOST}:"
        f"{SFTP_PORT}{SFTP_DIRECTORY}"
    )
    sftp_password = prompt_password("SFTP password")

    config = {
        "version": CONFIG_VERSION,
        "country": country,
        "timezone": timezone.key,
        "report_days_ago": 1,
        "output_directory": "output",
        "devices": configured_devices,
        "sftp": {
            "host": SFTP_HOST,
            "port": SFTP_PORT,
            "username": SFTP_USERNAME,
            "directory": SFTP_DIRECTORY,
            "host_key_sha256": SFTP_HOST_KEY_SHA256,
            "password_dpapi": protect_secret(sftp_password),
        },
    }
    write_config(config_path, config)

    print()
    print(f"Configuration saved: {config_path}")
    print("Passwords are encrypted for this Windows user with DPAPI.")
    print(
        "Scheduled runs will retrieve the previous local calendar day "
        "without prompting."
    )
    return 0


def load_config(config_path):
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RuntimeError(
            f"Configuration not found: {config_path}. Run the EXE with "
            "--setup first."
        ) from error
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot read configuration: {error}") from error

    if config.get("version") != CONFIG_VERSION:
        raise RuntimeError("Unsupported automated configuration version.")
    if not config.get("devices"):
        raise RuntimeError("The configuration contains no devices.")
    if config.get("timezone") not in COUNTRY_TIMEZONES.values():
        raise RuntimeError("The configured timezone is not supported.")

    try:
        devices = [
            {
                "name": item["name"],
                "ip": item["ip"],
                "username": item["username"],
                "password": unprotect_secret(item["password_dpapi"]),
            }
            for item in config["devices"]
        ]
        sftp = dict(config["sftp"])
        sftp["password"] = unprotect_secret(sftp.pop("password_dpapi"))
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError(
            "The automated configuration is incomplete or invalid."
        ) from error

    return config, devices, sftp


def resolve_report_date(config, date_override=None, now=None):
    timezone = ZoneInfo(config["timezone"])
    if date_override is not None:
        try:
            return date.fromisoformat(date_override), timezone
        except ValueError as error:
            raise RuntimeError("--date must use YYYY-MM-DD format.") from error

    current_time = now or datetime.now(timezone)
    days_ago = int(config.get("report_days_ago", 1))
    if days_ago < 1:
        raise RuntimeError("report_days_ago must be at least 1.")
    report_date = current_time.astimezone(timezone).date() - timedelta(
        days=days_ago
    )
    return report_date, timezone


def run(config_path, date_override=None):
    config, devices, sftp = load_config(config_path)
    report_date, timezone = resolve_report_date(config, date_override)
    start_time = datetime.combine(
        report_date,
        time.min,
        tzinfo=timezone,
    ).isoformat(timespec="seconds")
    end_time = datetime.combine(
        report_date,
        time(23, 59, 59),
        tzinfo=timezone,
    ).isoformat(timespec="seconds")

    print()
    started_at = datetime.now(timezone).isoformat(timespec="seconds")
    print(f"Automated run started: {started_at}")
    print(f"Retrieving attendance for {report_date} ({config['country']}).")

    combined_events, retrieval_incomplete = retrieve_from_devices(
        devices,
        start_time,
        end_time,
    )
    if not combined_events:
        print("No events were returned. No report was uploaded.")
        return 2 if retrieval_incomplete else 0

    output_setting = config.get("output_directory", "output")
    output_folder = Path(output_setting)
    if not output_folder.is_absolute():
        output_folder = application_folder() / output_folder

    csv_path, _, _, _, _ = create_report_files(
        combined_events,
        start_time,
        end_time,
        devices,
        output_folder,
    )

    if retrieval_incomplete:
        print(
            "Retrieval was incomplete. Local files were kept, but the CSV "
            "was not uploaded."
        )
        return 2

    print()
    print(
        f"SFTP destination: {sftp['username']}@{sftp['host']}:"
        f"{sftp['port']}{sftp['directory']}"
    )
    try:
        upload_files_sftp(
            (csv_path,),
            sftp["password"],
            host=sftp["host"],
            port=int(sftp["port"]),
            username=sftp["username"],
            directory=sftp["directory"],
            host_key_sha256=sftp["host_key_sha256"],
        )
    except paramiko.AuthenticationException:
        print("SFTP authentication failed. Local files were kept.")
        return 2
    except (OSError, paramiko.SSHException) as error:
        print(f"SFTP upload failed: {error}")
        print("Local files were kept.")
        return 2

    print("BIPO CSV upload completed successfully.")
    completed_at = datetime.now(timezone).isoformat(timespec="seconds")
    print(f"Automated run completed: {completed_at}")
    return 0


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run Hikvision attendance retrieval without prompts.",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="create or replace the encrypted local configuration",
    )
    parser.add_argument(
        "--date",
        help="retrieve one specific date in YYYY-MM-DD format",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="configuration path (default: beside the EXE)",
    )
    return parser.parse_args()


def main():
    arguments = parse_arguments()
    config_path = arguments.config or (application_folder() / CONFIG_FILENAME)
    config_path = config_path.resolve()

    if arguments.setup:
        return setup(config_path)

    log_path = application_folder() / LOG_FILENAME
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log_file:
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = Tee(original_stdout, log_file)
        sys.stderr = Tee(original_stderr, log_file)
        try:
            return run(config_path, arguments.date)
        except Exception:
            print("\nUnexpected automated-run error:", file=sys.stderr)
            traceback.print_exc()
            return 1
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr


if __name__ == "__main__":
    raise SystemExit(main())
