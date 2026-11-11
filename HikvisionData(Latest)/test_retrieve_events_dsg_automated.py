import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from zoneinfo import ZoneInfo

import retrieve_events_dsg_automated as dsg_automated


class DSGSetupTests(unittest.TestCase):
    def test_setup_creates_local_only_dsg_configuration(self):
        devices = [
            {
                "name": "DSG terminal",
                "ip": "192.0.2.10",
                "username": "admin",
                "password": "device-secret",
            }
        ]

        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / dsg_automated.CONFIG_FILENAME
            with (
                patch.object(dsg_automated, "_require_windows"),
                patch.object(
                    dsg_automated,
                    "prompt_country",
                    return_value=(
                        "SG",
                        SimpleNamespace(key="Asia/Singapore"),
                    ),
                ),
                patch.object(
                    dsg_automated,
                    "prompt_devices",
                    return_value=devices,
                ),
                patch.object(
                    dsg_automated,
                    "protect_secret",
                    return_value="encrypted-device-secret",
                ),
            ):
                result = dsg_automated.setup(config_path)

            config = json.loads(config_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(config["deployment"], "DSG")
        self.assertEqual(config["output_directory"], "dsg_output")
        self.assertNotIn("sftp", config)
        self.assertNotIn("password", config["devices"][0])
        self.assertEqual(
            config["devices"][0]["password_dpapi"],
            "encrypted-device-secret",
        )

    def test_load_config_rejects_dph_configuration(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / "automated_config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "version": dsg_automated.CONFIG_VERSION,
                        "country": "SG",
                        "timezone": "Asia/Singapore",
                        "devices": [{"name": "DPH terminal"}],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "not a DSG"):
                dsg_automated.load_config(config_path)


class DSGRunTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "deployment": "DSG",
            "country": "SG",
            "timezone": "Asia/Singapore",
            "output_directory": "dsg_output",
        }
        self.devices = [
            {
                "name": "DSG terminal",
                "ip": "192.0.2.10",
                "username": "admin",
                "password": "decrypted-secret",
            }
        ]

    def test_successful_run_creates_local_files(self):
        events = [{"employeeNoString": "1001"}]
        with tempfile.TemporaryDirectory() as temporary_directory:
            application_path = Path(temporary_directory)
            with (
                patch.object(
                    dsg_automated,
                    "load_config",
                    return_value=(self.config, self.devices),
                ),
                patch.object(
                    dsg_automated,
                    "resolve_report_date",
                    return_value=(
                        date(2026, 8, 12),
                        ZoneInfo("Asia/Singapore"),
                    ),
                ),
                patch.object(
                    dsg_automated,
                    "retrieve_from_devices",
                    return_value=(events, False),
                ),
                patch.object(dsg_automated, "application_folder", return_value=application_path),
                patch.object(dsg_automated, "create_report_files") as create_files,
            ):
                result = dsg_automated.run(Path("unused.json"))

        self.assertEqual(result, 0)
        create_files.assert_called_once()
        self.assertEqual(create_files.call_args.args[4], application_path / "dsg_output")

    def test_partial_retrieval_keeps_local_files_and_returns_two(self):
        events = [{"employeeNoString": "1001"}]
        with (
            patch.object(
                dsg_automated,
                "load_config",
                return_value=(self.config, self.devices),
            ),
            patch.object(
                dsg_automated,
                "resolve_report_date",
                return_value=(date(2026, 8, 12), ZoneInfo("Asia/Singapore")),
            ),
            patch.object(
                dsg_automated,
                "retrieve_from_devices",
                return_value=(events, True),
            ),
            patch.object(dsg_automated, "create_report_files") as create_files,
        ):
            result = dsg_automated.run(Path("unused.json"))

        self.assertEqual(result, 2)
        create_files.assert_called_once()


if __name__ == "__main__":
    unittest.main()
