import base64
import csv
import hashlib
import hmac
import os
import posixpath
import socket
import sys
import time as time_module
import traceback
from getpass import getpass
from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import paramiko
import requests
from requests.auth import HTTPDigestAuth


MAX_RESULTS_PER_REQUEST = 30
EVENT_REQUEST_ATTEMPTS = 6
EVENT_RETRY_INITIAL_DELAY_SECONDS = 2
EVENT_RETRY_MAX_DELAY_SECONDS = 30
EVENT_PAGE_DELAY_SECONDS = 1
DEVICE_CONNECT_TIMEOUT_SECONDS = 15
DEVICE_READ_TIMEOUT_SECONDS = 60
SFTP_HOST = "52.76.92.95"
SFTP_PORT = 8022
SFTP_USERNAME = "dsgvip"
SFTP_DIRECTORY = "/DPH_clock"
SFTP_HOST_KEY_SHA256 = "belxYoOkQAeMbl+wf0Tx2TTOgYii0SP4q5LvT6qPvFE"
COUNTRY_TIMEZONES = {
    "SG": "Asia/Singapore",
    "PH": "Asia/Manila",
}


class EventRetrievalError(Exception):
    """Report a failed page without discarding pages already retrieved."""

    def __init__(self, position, attempts, cause, partial_events):
        super().__init__(str(cause))
        self.position = position
        self.attempts = attempts
        self.cause = cause
        self.partial_events = partial_events


def summarize_attendance(events):
    """Return one first/last clock row per employee and local event date."""
    attendance = {}
    skipped_events = 0

    for event in events:
        employee_id = str(event.get("employeeNoString", "")).strip()
        verify_mode = str(event.get("currentVerifyMode", "")).strip().lower()
        timestamp_value = str(event.get("time", "")).strip()

        if not employee_id or verify_mode == "invalid" or not timestamp_value:
            skipped_events += 1
            continue

        try:
            event_time = datetime.fromisoformat(timestamp_value)
        except ValueError:
            skipped_events += 1
            continue

        key = (employee_id, event_time.date())
        existing = attendance.get(key)

        if existing is None:
            attendance[key] = [event_time, event_time]
            continue

        if event_time < existing[0]:
            existing[0] = event_time
        if event_time > existing[1]:
            existing[1] = event_time

    rows = [
        {
            "employee_id": employee_id,
            "date": event_date,
            "first_clock": clock_times[0],
            "last_clock": clock_times[1],
        }
        for (employee_id, event_date), clock_times in attendance.items()
    ]
    rows.sort(key=lambda row: (row["date"], row["employee_id"]))
    return rows, skipped_events


def write_bipo_csv(
    path,
    attendance_rows,
    start_date,
    end_date,
    export_time,
    operator,
):
    """Write the custom BIPO report layout, including its metadata lines."""
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file, lineterminator="\r\n")
        writer.writerow([])
        writer.writerow(["Custom Report-BIPO"])
        writer.writerow(
            [f"Export Time: {export_time.strftime('%Y-%m-%d %H:%M')}"]
        )
        writer.writerow([f"Operator: {operator}"])
        writer.writerow([f"Time Period: {start_date} - {end_date}"])
        writer.writerow(
            [
                "ID",
                "Required Check-In Date",
                "Actual Check-In Time",
                "Required Check-Out Date",
                "Actual Check-Out Time",
                "",
            ]
        )

        for row in attendance_rows:
            event_date = row["date"].isoformat()
            writer.writerow(
                [
                    row["employee_id"],
                    event_date,
                    row["first_clock"].strftime("%H:%M"),
                    event_date,
                    row["last_clock"].strftime("%H:%M"),
                    "",
                ]
            )


def application_folder():
    """Return the folder containing the script or packaged executable."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def prompt_country():
    while True:
        country = input("Country/timezone (SG or PH): ").strip().upper()
        if country in COUNTRY_TIMEZONES:
            return country, ZoneInfo(COUNTRY_TIMEZONES[country])
        print("Please enter SG for Singapore or PH for the Philippines.")


def prompt_date(label, today, earliest=None):
    while True:
        entered = input(f"{label} (D/M/YYYY): ").strip()
        try:
            selected = datetime.strptime(entered, "%d/%m/%Y").date()
        except ValueError:
            print("Invalid date. Use D/M/YYYY, for example 1/7/2026.")
            continue

        if selected > today:
            print(
                f"Date cannot be later than today "
                f"({today.day}/{today.month}/{today.year})."
            )
            continue

        if earliest and selected < earliest:
            print("End date cannot be earlier than the start date.")
            continue

        return selected


def prompt_retrieval_period():
    print("Event date range")
    print("-" * 20)
    country, timezone = prompt_country()
    today = datetime.now(timezone).date()
    start_date = prompt_date("Start date", today)
    end_date = prompt_date("End date", today, earliest=start_date)

    start_time = datetime.combine(
        start_date, time.min, tzinfo=timezone
    ).isoformat(timespec="seconds")
    end_time = datetime.combine(
        end_date, time(23, 59, 59), tzinfo=timezone
    ).isoformat(timespec="seconds")

    print(
        f"Retrieving {start_date.strftime('%d/%m/%Y')} to "
        f"{end_date.strftime('%d/%m/%Y')} ({country})."
    )
    return start_time, end_time


def prompt_required(label):
    while True:
        value = input(f"{label}: ").strip()
        if value:
            return value
        print(f"{label} cannot be empty.")


def prompt_password(label="Password"):
    while True:
        password = getpass(f"{label} (input hidden): ")
        if password:
            return password
        print("Password cannot be empty.")


def prompt_yes_no(question, default=True):
    hint = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{question} [{hint}]: ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please enter yes or no.")


def prompt_device(number):
    print()
    print(f"Device {number}")
    print("-" * 20)
    name = input("Name (optional): ").strip()
    ip = prompt_required("IP address")
    username = prompt_required("Username")
    password = prompt_password()

    return {
        "name": name or ip,
        "ip": ip,
        "username": username,
        "password": password,
    }


def prompt_devices():
    devices = [prompt_device(1)]
    if not prompt_yes_no("Is this the only device?"):
        devices.append(prompt_device(2))
    return devices


def host_key_fingerprint(key):
    digest = hashlib.sha256(key.asbytes()).digest()
    return base64.b64encode(digest).decode("ascii").rstrip("=")


def upload_files_sftp(
    paths,
    password,
    host=SFTP_HOST,
    port=SFTP_PORT,
    username=SFTP_USERNAME,
    directory=SFTP_DIRECTORY,
    host_key_sha256=SFTP_HOST_KEY_SHA256,
):
    sock = socket.create_connection((host, port), timeout=15)
    transport = None
    sftp = None

    try:
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=15)

        actual_fingerprint = host_key_fingerprint(
            transport.get_remote_server_key()
        )
        if not hmac.compare_digest(
            actual_fingerprint, host_key_sha256
        ):
            raise paramiko.SSHException(
                "SFTP server identity check failed. The host key has changed."
            )

        transport.auth_password(username, password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.chdir(directory)

        for local_path in paths:
            remote_path = posixpath.join(directory, local_path.name)
            sftp.put(str(local_path), remote_path, confirm=True)
            print(f"Uploaded: {remote_path}")
    finally:
        if sftp is not None:
            sftp.close()
        if transport is not None:
            transport.close()
        else:
            sock.close()


def create_device_session(device):
    session = requests.Session()
    session.auth = HTTPDigestAuth(
        device["username"],
        device["password"],
    )
    session.headers.update({"Accept": "application/json"})
    return session


def test_connection(device, session):
    url = f"http://{device['ip']}/ISAPI/System/deviceInfo"

    response = session.get(
        url,
        timeout=(
            DEVICE_CONNECT_TIMEOUT_SECONDS,
            DEVICE_READ_TIMEOUT_SECONDS,
        ),
    )

    response.raise_for_status()
    print(f"{device['name']}: Connection successful")


def is_retryable_event_error(error):
    if isinstance(error, requests.exceptions.HTTPError):
        response = error.response
        if response is None:
            return True
        return response.status_code in (401, 408, 429) or response.status_code >= 500

    return isinstance(
        error,
        (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            ValueError,
        ),
    )


def request_event_page(session, url, device, payload, position):
    for attempt in range(1, EVENT_REQUEST_ATTEMPTS + 1):
        try:
            response = session.post(
                url,
                json=payload,
                timeout=(
                    DEVICE_CONNECT_TIMEOUT_SECONDS,
                    DEVICE_READ_TIMEOUT_SECONDS,
                ),
            )

            response.raise_for_status()
            return response.json()

        except (
            requests.exceptions.RequestException,
            ValueError,
        ) as error:
            is_unauthorized = (
                isinstance(error, requests.exceptions.HTTPError)
                and error.response is not None
                and error.response.status_code == 401
            )

            if (
                not is_retryable_event_error(error)
                or attempt == EVENT_REQUEST_ATTEMPTS
            ):
                raise EventRetrievalError(
                    position,
                    attempt,
                    error,
                    [],
                ) from error

            if is_unauthorized:
                # Some Hikvision firmware expires its digest nonce during a
                # long paginated search. Drop the cached nonce and pooled TCP
                # connections so the next request performs a fresh handshake.
                error.response.close()
                session.auth = HTTPDigestAuth(
                    device["username"],
                    device["password"],
                )
                for adapter in session.adapters.values():
                    adapter.close()
                print(
                    f"{device['name']}: Digest authentication expired; "
                    "starting a fresh authenticated connection."
                )

            delay = min(
                EVENT_RETRY_INITIAL_DELAY_SECONDS * (2 ** (attempt - 1)),
                EVENT_RETRY_MAX_DELAY_SECONDS,
            )
            print(
                f"{device['name']}: Page starting at record {position + 1} "
                f"failed ({error}). Retrying in {delay} seconds "
                f"[{attempt}/{EVENT_REQUEST_ATTEMPTS}]..."
            )
            time_module.sleep(delay)


def retrieve_events(
    device,
    session,
    start_time,
    end_time,
    max_results,
):
    url = (
        f"http://{device['ip']}"
        "/ISAPI/AccessControl/AcsEvent?format=json"
    )

    all_events = []
    position = 0
    search_id = datetime.now().strftime("%Y%m%d%H%M%S")

    while True:
        payload = {
            "AcsEventCond": {
                "searchID": search_id,
                "searchResultPosition": position,
                "maxResults": max_results,
                "major": 0,
                "minor": 0,
                "startTime": start_time,
                "endTime": end_time,
            }
        }

        try:
            result = request_event_page(
                session,
                url,
                device,
                payload,
                position,
            )
        except EventRetrievalError as error:
            error.partial_events = all_events
            raise

        event_response = result.get("AcsEvent", result)
        events = event_response.get("InfoList", [])

        if isinstance(events, dict):
            events = [events]

        if not events:
            break

        for event in events:
            event["deviceName"] = device["name"]
            event["deviceIP"] = device["ip"]

        all_events.extend(events)
        position += len(events)

        total_matches = event_response.get("totalMatches", 0)
        response_status = event_response.get("responseStatusStrg", "")

        print(
            f"{device['name']}: Retrieved "
            f"{len(all_events)} of {total_matches} records"
        )

        if response_status != "MORE" or position >= int(total_matches or 0):
            break

        time_module.sleep(EVENT_PAGE_DELAY_SECONDS)

    return all_events


def retrieve_from_devices(devices, start_time, end_time):
    """Retrieve records from all devices and preserve partial results."""
    combined_events = []
    retrieval_incomplete = False

    for device in devices:
        try:
            with create_device_session(device) as session:
                test_connection(device, session)
                events = retrieve_events(
                    device,
                    session,
                    start_time,
                    end_time,
                    MAX_RESULTS_PER_REQUEST,
                )
            combined_events.extend(events)

        except EventRetrievalError as error:
            retrieval_incomplete = True
            combined_events.extend(error.partial_events)
            print(
                f"{device['name']}: Could not retrieve the page starting at "
                f"record {error.position + 1} after {error.attempts} attempts."
            )
            print(f"{device['name']}: Last error: {error.cause}")
            if (
                isinstance(error.cause, requests.exceptions.HTTPError)
                and error.cause.response is not None
                and error.cause.response.status_code == 401
            ):
                print(
                    f"{device['name']}: Authentication was rejected. Verify "
                    "the password in the device web page. If there were several "
                    "failed attempts, wait 30 minutes before trying again."
                )
            if error.partial_events:
                print(
                    f"{device['name']}: Keeping "
                    f"{len(error.partial_events)} records already retrieved."
                )

        except requests.exceptions.HTTPError as error:
            retrieval_incomplete = True
            status = error.response.status_code
            print(f"{device['name']}: HTTP error {status}")
            print(error.response.text)
            if status == 401:
                print(
                    f"{device['name']}: Authentication was rejected. Verify "
                    "the password in the device web page. If there were several "
                    "failed attempts, wait 30 minutes before trying again."
                )

        except requests.exceptions.RequestException as error:
            retrieval_incomplete = True
            print(f"{device['name']}: Connection error: {error}")

        except ValueError as error:
            retrieval_incomplete = True
            print(f"{device['name']}: Invalid JSON response: {error}")

    return combined_events, retrieval_incomplete


def create_report_files(
    combined_events,
    start_time,
    end_time,
    devices,
    output_folder,
):
    """Create the BIPO CSV and local raw Excel audit file."""
    output_folder.mkdir(parents=True, exist_ok=True)
    dataframe = pd.json_normalize(combined_events)

    start_date = datetime.fromisoformat(start_time).date()
    end_date = datetime.fromisoformat(end_time).date()
    report_timezone = datetime.fromisoformat(start_time).tzinfo
    export_time = datetime.now(report_timezone)
    timestamp = export_time.strftime("%Y%m%d_%H%M%S")
    report_timestamp = export_time.strftime("%Y%m%d%H%M%S%f")[:17]

    csv_path = output_folder / (
        f"Custom Report_BIPO_{start_date}_{end_date}_"
        f"{report_timestamp}.csv"
    )
    excel_path = output_folder / f"hikvision_events_{timestamp}.xlsx"

    attendance_rows, skipped_events = summarize_attendance(combined_events)
    write_bipo_csv(
        csv_path,
        attendance_rows,
        start_date,
        end_date,
        export_time,
        devices[0]["username"],
    )
    dataframe.to_excel(excel_path, index=False)

    print()
    print(f"Raw records retrieved: {len(dataframe)}")
    print(f"Invalid/system records removed from CSV: {skipped_events}")
    print(f"Attendance rows written: {len(attendance_rows)}")
    print(f"BIPO CSV file: {csv_path.resolve()}")
    print(f"Raw Excel file (local only): {excel_path.resolve()}")

    return csv_path, excel_path, len(dataframe), skipped_events, len(
        attendance_rows
    )


def main():
    start_time, end_time = prompt_retrieval_period()
    devices = prompt_devices()
    output_folder = application_folder() / "output"

    combined_events, retrieval_incomplete = retrieve_from_devices(
        devices,
        start_time,
        end_time,
    )

    if not combined_events:
        print("No events were returned.")
        return 2 if retrieval_incomplete else 0

    csv_path, _, _, _, _ = create_report_files(
        combined_events,
        start_time,
        end_time,
        devices,
        output_folder,
    )

    print()
    print(
        f"SFTP destination: {SFTP_USERNAME}@{SFTP_HOST}:"
        f"{SFTP_PORT}{SFTP_DIRECTORY}"
    )
    sftp_password = prompt_password("SFTP password")

    try:
        upload_files_sftp((csv_path,), sftp_password)
        print("BIPO CSV upload completed successfully.")
    except paramiko.AuthenticationException:
        print("SFTP authentication failed. Check the SFTP password.")
        print("The local CSV and Excel files have been kept.")
        return 2
    except (OSError, paramiko.SSHException) as error:
        print(f"SFTP upload failed: {error}")
        print("The local CSV and Excel files have been kept.")
        return 2

    if retrieval_incomplete:
        print()
        print(
            "Warning: The export contains partial results because one or more "
            "device requests failed."
        )
        return 2

    return 0


def pause_after_error(exit_code):
    if exit_code and os.name == "nt" and getattr(sys, "frozen", False):
        try:
            input("\nAn error occurred. Press Enter to close this window...")
        except (EOFError, KeyboardInterrupt):
            pass


if __name__ == "__main__":
    try:
        result_code = main()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        result_code = 1
    except Exception:
        print("\nUnexpected error:")
        traceback.print_exc()
        result_code = 1

    pause_after_error(result_code)
    raise SystemExit(result_code)
