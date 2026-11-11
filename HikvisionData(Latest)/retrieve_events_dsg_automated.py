import argparse
import json
import sys
import traceback
from datetime import datetime, time, timezone
from pathlib import Path

from retrieve_events import (
    COUNTRY_TIMEZONES,
    application_folder,
    create_report_files,
    prompt_country,
    prompt_devices,
    prompt_yes_no,
    retrieve_from_devices,
)
from retrieve_events_automated import (
    CONFIG_VERSION,
    Tee,
    _require_windows,
    protect_secret,
    resolve_report_date,
    unprotect_secret,
    write_config,
)


CONFIG_FILENAME = "dsg_automated_config.json"
LOG_FILENAME = "dsg_automated_retriever.log"
OUTPUT_DIRECTORY = "dsg_output"
DEPLOYMENT = "DSG"


def setup(config_path):
    _require_windows()
    if config_path.exists() and not prompt_yes_no(
        f"Replace existing DSG configuration at {config_path}?",
        default=False,
    ):
        print("Setup cancelled. Existing configuration was not changed.")
        return 1

    print("DSG Automated Hikvision Event Retriever setup")
    print("-" * 48)
    country, selected_timezone = prompt_country()
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

    config = {
        "version": CONFIG_VERSION,
        "deployment": DEPLOYMENT,
        "country": country,
        "timezone": selected_timezone.key,
        "report_days_ago": 1,
        "output_directory": OUTPUT_DIRECTORY,
        "devices": configured_devices,
    }
    write_config(config_path, config)

    print()
    print(f"DSG configuration saved: {config_path}")
    print("Device passwords are encrypted for this Windows user with DPAPI.")
    print(
        "Scheduled runs will retrieve the previous local calendar day and "
        "save the files locally without uploading them."
    )
    return 0


def load_config(config_path):
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RuntimeError(
            f"DSG configuration not found: {config_path}. Run the EXE with "
            "--setup first."
        ) from error
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot read DSG configuration: {error}") from error

    if config.get("version") != CONFIG_VERSION:
        raise RuntimeError("Unsupported DSG configuration version.")
    if config.get("deployment") != DEPLOYMENT:
        raise RuntimeError("The selected configuration is not a DSG configuration.")
    if not config.get("devices"):
        raise RuntimeError("The DSG configuration contains no devices.")
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
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError(
            "The DSG configuration is incomplete or invalid."
        ) from error

    return config, devices


def run(config_path, date_override=None):
    config, devices = load_config(config_path)
    report_date, selected_timezone = resolve_report_date(
        config,
        date_override,
    )
    start_time = datetime.combine(
        report_date,
        time.min,
        tzinfo=selected_timezone,
    ).isoformat(timespec="seconds")
    end_time = datetime.combine(
        report_date,
        time(23, 59, 59),
        tzinfo=selected_timezone,
    ).isoformat(timespec="seconds")

    print()
    started_at = datetime.now(selected_timezone).isoformat(timespec="seconds")
    print(f"DSG automated run started: {started_at}")
    print(f"Retrieving attendance for {report_date} ({config['country']}).")

    combined_events, retrieval_incomplete = retrieve_from_devices(
        devices,
        start_time,
        end_time,
    )
    if not combined_events:
        print("No events were returned. No local report was created.")
        return 2 if retrieval_incomplete else 0

    output_setting = config.get("output_directory", OUTPUT_DIRECTORY)
    output_folder = Path(output_setting)
    if not output_folder.is_absolute():
        output_folder = application_folder() / output_folder

    create_report_files(
        combined_events,
        start_time,
        end_time,
        devices,
        output_folder,
    )

    if retrieval_incomplete:
        print("Retrieval was incomplete. Partial DSG files were kept locally.")
        return 2

    print("DSG local report creation completed successfully. No files uploaded.")
    completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"DSG automated run completed: {completed_at}")
    return 0


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Create DSG Hikvision attendance files without prompts.",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="create or replace the encrypted DSG configuration",
    )
    parser.add_argument(
        "--date",
        help="retrieve one specific date in YYYY-MM-DD format",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="DSG configuration path (default: beside the EXE)",
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
            print("\nUnexpected DSG automated-run error:", file=sys.stderr)
            traceback.print_exc()
            return 1
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr


if __name__ == "__main__":
    raise SystemExit(main())
