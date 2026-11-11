# Hikvision Event Retriever

The application asks for device connection details each time it runs. The
password is hidden while it is typed, and device details are not saved or
compiled into the executable.

## Run

Run `HikvisionEventRetriever.exe` from Command Prompt or double-click it. First
select `SG` (Singapore) or `PH` (Philippines), then enter the start and end dates
in `D/M/YYYY` format. Future dates are rejected, and the end date cannot be
earlier than the start date.

The executable does not have to remain in this project folder. It can be moved
to any normal folder where the user has permission to create files. The
application creates an `output` folder beside the executable and saves a
BIPO-format CSV report and a raw Excel audit file there.

To run the current copy from Command Prompt, open CMD and enter:

```bat
cd /d C:\Users\HauCheng_PC\Desktop\HikvisionData\dist
HikvisionEventRetriever.exe
```

The `/d` option allows CMD to change the drive as well as the directory. You can
also launch the executable from any CMD directory by entering its complete path:

```bat
"C:\Users\HauCheng_PC\Desktop\HikvisionData\dist\HikvisionEventRetriever.exe"
```

Then enter the first device's name, IP address, username, and password. The
name is optional and is only a friendly label in the exported files. The IP
address is used as the label when the name is empty.

After device 1, answer the `Is this the only device?` question:

- `Yes` retrieves events from device 1 only.
- `No` asks for device 2 and combines both devices in one export.

Event pages are requested with a short delay to avoid overloading the device.
If a device temporarily closes a connection, times out, or returns `401
Unauthorized`, the application retries the same page up to six times with
increasing delays capped at 30 seconds. For a 401 during a long retrieval, it
discards the stale Digest authentication state and opens a fresh authenticated
connection before retrying. If all attempts fail, records from earlier pages
are still exported and the export is clearly marked as partial in the console.

A persistent 401 after all six attempts may indicate an incorrect password, a
temporarily locked account, or a device-side authentication issue.

The connection test and event retrieval reuse one authenticated HTTP session,
which avoids repeatedly challenging the terminal for Digest authentication.
Device requests allow up to 60 seconds for a response.

The CSV excludes events without an `employeeNoString` and events whose
verification mode is `invalid`. The employee ID comes from
`employeeNoString`. For each employee and event date, the earliest valid event
is written as the actual check-in time and the latest valid event is written as
the actual check-out time. If there is only one event, that time is used for
both fields.

The report filename follows this pattern:

```text
Custom Report_BIPO_YYYY-MM-DD_YYYY-MM-DD_YYYYMMDDHHMMSSmmm.csv
```

When the packaged application exits because of an error or partial retrieval,
it waits for Enter before closing so error details remain visible.

## SFTP upload

After the CSV and Excel files are created locally, the application asks for
the SFTP password as hidden input. It uploads only the BIPO-format CSV to:

```text
dsgvip@52.76.92.95:8022/DPH_clock
```

The raw Excel file remains in the local `output` folder and is never uploaded.
The SFTP password is not stored in the source code or executable. The server's
public host-key fingerprint is pinned in the application so that credentials
and files are sent only when the server identity matches. If authentication or
uploading fails, the local files remain in the `output` folder and an error is
displayed.

## Automated Windows Task Scheduler version

`HikvisionEventRetrieverAutomated.exe` runs without prompts and is intended for
Windows Task Scheduler. A normal unattended run retrieves the previous calendar
day in the configured SG or PH timezone, creates the BIPO CSV and local raw
Excel file, and uploads only the CSV. If retrieval is incomplete, it keeps the
local files but does not upload the partial CSV.

### What the automated version does

When it is run without command-line arguments, it:

1. Loads the device and SFTP settings from `automated_config.json`.
2. Decrypts the passwords for the current Windows user.
3. Calculates yesterday's date using the configured SG or PH timezone.
4. Retrieves all Hikvision events for that date.
5. Creates the BIPO-format attendance CSV.
6. Creates the raw Excel audit file locally.
7. Uploads only the CSV to the configured SFTP destination.
8. Appends the run details and any errors to `automated_retriever.log`.

If no events are returned, it does not create or upload a report. If retrieval
fails after some pages have been received, it creates local partial audit files
but does not upload the partial CSV.

### Files included in the GitHub download

Download the `HikvisionEventRetriever-Windows-x64` artifact from a successful
**Build Windows EXE** GitHub Actions run. Extract the ZIP; it contains:

```text
HikvisionEventRetriever.exe
HikvisionEventRetrieverAutomated.exe
DSG_automated.exe
```

The first file is the interactive version. The second file is the existing DPH
unattended version. `DSG_automated.exe` is the DSG local-only unattended
version described below.

### Step 1: Install the automated EXE

1. Create a normal writable folder on the Windows computer, for example:

   ```text
   C:\HikvisionRetriever
   ```

2. Copy `HikvisionEventRetrieverAutomated.exe` into that folder.
3. Do not place it in `C:\Program Files`, because the application must be able
   to create its configuration, log, and output files beside the EXE.
4. Make sure this Windows computer can reach both the Hikvision terminal and
   the SFTP server.

If Windows SmartScreen warns about an unknown publisher, confirm that the EXE
came from this repository's successful GitHub Actions run before choosing
**More info** and **Run anyway**. The EXE is not currently code-signed.

### Step 2: Create `automated_config.json`

Yes, the automated EXE creates `automated_config.json`. It is created in the
same folder as the EXE after one-time setup completes successfully.

Open Command Prompt as the same Windows user that will run the scheduled task:

```bat
cd /d C:\HikvisionRetriever
HikvisionEventRetrieverAutomated.exe --setup
```

Enter the requested values:

1. Country/timezone: `SG` or `PH`.
2. Friendly device name, which is optional.
3. Hikvision HTTP/ISAPI address, for example `192.168.1.54`.
4. Hikvision username, normally `admin` unless a different account is used.
5. Hikvision password. Input is hidden.
6. Whether another device should be included. Up to two devices are supported.
7. SFTP password. Input is hidden.

The Hikvision address uses the device's HTTP/ISAPI port, normally port 80. If
the HTTP port was changed, include it in the address, for example
`192.168.1.54:81`. Port 8000 is the Hikvision SDK server port and is not used by
this application.

After successful setup, the folder contains:

```text
C:\HikvisionRetriever\HikvisionEventRetrieverAutomated.exe
C:\HikvisionRetriever\automated_config.json
```

The configuration file stores the timezone, device address, device username,
SFTP destination, and encrypted password values. It does not contain either
password as readable plain text.

Windows Data Protection API (DPAPI) encrypts the device and SFTP passwords for
the Windows user and computer that performed setup. Therefore:

- The scheduled task must use the same Windows user that ran `--setup`.
- Copying the configuration to another Windows account or computer will not
  make the encrypted passwords usable there.
- Do not commit, email, or deliberately share `automated_config.json`.
- If the file is deleted, run `--setup` again to recreate it.

The repository ignores `automated_config.json` to reduce the risk of committing
it accidentally.

### Step 3: Test a known date

Before creating the scheduled task, test a date known to contain attendance
events. Dates for the automated version use `YYYY-MM-DD` format:

```bat
cd /d C:\HikvisionRetriever
HikvisionEventRetrieverAutomated.exe --date 2026-07-22
```

This is a real run: if retrieval succeeds, it creates both local files and
uploads the resulting CSV to SFTP. Confirm that:

1. The terminal reports `Connection successful`.
2. All expected event pages are retrieved.
3. The BIPO CSV and raw XLSX appear under
   `C:\HikvisionRetriever\output`.
4. The CSV appears in the SFTP destination.
5. `automated_retriever.log` contains a successful completion message.

### Step 4: Test yesterday's automatic run

Run the EXE without arguments:

```bat
cd /d C:\HikvisionRetriever
HikvisionEventRetrieverAutomated.exe
```

No questions should be displayed. It automatically retrieves the previous
calendar day based on the configured SG or PH timezone.

### Step 5: Create the Windows Task Scheduler task

1. Open the Windows Start menu, search for **Task Scheduler**, and open it.
2. Select **Task Scheduler Library**.
3. Select **Create Task**. Using **Create Task** provides all required account
   and working-directory options.
4. On the **General** tab:
   - Name: `Hikvision Attendance Upload`.
   - Select the same Windows user that ran `--setup`.
   - Select **Run whether user is logged on or not** if unattended background
     execution is required.
   - **Run with highest privileges** is normally not required.
5. On the **Triggers** tab, select **New**:
   - Begin the task: **On a schedule**.
   - Settings: **Daily**.
   - Start time: choose a time after midnight and after the attendance day is
     complete, for example `5:30:00 AM`.
   - Select **Enabled**, then select **OK**.
6. On the **Actions** tab, select **New**:
   - Action: **Start a program**.
   - Program/script:

     ```text
     C:\HikvisionRetriever\HikvisionEventRetrieverAutomated.exe
     ```

   - Add arguments: leave empty.
   - Start in:

     ```text
     C:\HikvisionRetriever
     ```

   - Select **OK**.
7. On the **Conditions** tab:
   - For a laptop, optionally enable **Wake the computer to run this task**.
   - Review any power condition that might prevent the task from running on
     battery power.
   - If available, require a network connection so the terminal and SFTP server
     can be reached.
8. On the **Settings** tab:
   - Enable **Allow task to be run on demand**.
   - Enable **Run task as soon as possible after a scheduled start is missed**.
   - Optionally configure a retry after failure, such as every 30 minutes for
     two attempts.
   - Prevent overlapping runs by selecting **Do not start a new instance** if
     the task is already running.
9. Select **OK** and enter the Windows account password if requested.

The **Start in** field should contain the folder only, not the EXE filename and
not quotation marks.

### Step 6: Test the scheduled task

1. Find `Hikvision Attendance Upload` in Task Scheduler Library.
2. Right-click it and select **Run**.
3. Wait for it to finish, then select **Refresh**.
4. Check **Last Run Result**.
5. Review `C:\HikvisionRetriever\automated_retriever.log` and the `output`
   folder.

Common result codes are:

- `0x0`: run completed, or there were no events to report.
- `0x1`: unexpected program or configuration error.
- `0x2`: retrieval was incomplete, authentication failed, or SFTP upload
  failed. Local files are kept when available.

### Generated files and folders

After setup and successful runs, the application folder can contain:

```text
C:\HikvisionRetriever\
  HikvisionEventRetrieverAutomated.exe
  automated_config.json
  automated_retriever.log
  output\
    Custom Report_BIPO_YYYY-MM-DD_YYYY-MM-DD_YYYYMMDDHHMMSSmmm.csv
    hikvision_events_YYYYMMDD_HHMMSS.xlsx
```

Only the `Custom Report_BIPO_...csv` file is transferred to SFTP. The XLSX file
always stays in the local `output` folder.

### Change a password, address, or device

Run setup again from the same folder:

```bat
cd /d C:\HikvisionRetriever
HikvisionEventRetrieverAutomated.exe --setup
```

When asked whether to replace the existing configuration, answer `Yes`, then
enter all settings again. The previous configuration is replaced only after the
new setup finishes successfully.

### Move the automated version to another Windows computer

1. Copy `HikvisionEventRetrieverAutomated.exe` to a writable folder on the new
   computer.
2. Do not rely on the old `automated_config.json`; its passwords were encrypted
   for the old user and computer.
3. Run `HikvisionEventRetrieverAutomated.exe --setup` on the new computer.
4. Test a known date.
5. Create a new scheduled task under the Windows account used for setup.

### Troubleshooting

- **Configuration not found:** Run the EXE with `--setup` and confirm
  `automated_config.json` is beside it.
- **Password cannot be decrypted:** Run `--setup` again using the Windows
  account that will run the scheduled task.
- **401 Unauthorized:** Confirm the Hikvision username and password in the
  device web page. After several failed attempts, wait for any device account
  lock to expire before trying again.
- **Connection timeout:** Confirm the terminal IP, HTTP port, network route, and
  that no other device is using the same IP address.
- **SFTP authentication failed:** Run `--setup` again and carefully re-enter the
  SFTP password.
- **SFTP host identity failed:** Do not bypass the check. Confirm whether the
  SFTP server host key was intentionally changed before updating the program.
- **Task runs manually but not on schedule:** Confirm that Task Scheduler uses
  the same Windows account as setup, the **Start in** folder is correct, and the
  computer was awake and connected to the network.
- **No CSV was uploaded after partial retrieval:** This is intentional. Partial
  files remain local so incomplete attendance data is not sent to SFTP.
- **Need more details:** Review `automated_retriever.log` beside the EXE.

### Optional custom configuration path

By default, configuration is read from beside the EXE. An advanced deployment
can supply another path:

```bat
HikvisionEventRetrieverAutomated.exe --config "C:\HikvisionConfig\automated_config.json"
```

To create that configuration initially:

```bat
HikvisionEventRetrieverAutomated.exe --setup --config "C:\HikvisionConfig\automated_config.json"
```

The same Windows-user and DPAPI restrictions still apply. When using this mode
in Task Scheduler, put the complete `--config` value in **Add arguments**.

## DSG local-only automated version

`DSG_automated.exe` is separate from the existing DPH automation. It retrieves
Hikvision attendance events and creates the BIPO CSV and raw Excel audit file
locally. It does not request SFTP details and never uploads either file.

The DSG version uses its own files so it can run beside the DPH executable
without overwriting the DPH configuration or log:

```text
dsg_automated_config.json
dsg_automated_retriever.log
dsg_output\
```

### One-time DSG setup

Open Command Prompt as the Windows user that will run the scheduled task:

```bat
cd /d C:\HikvisionRetriever
DSG_automated.exe --setup
```

Setup asks for the SG or PH timezone and the name, HTTP/ISAPI address,
username, and password for one or two Hikvision devices. It does not ask for
an SFTP password. Device passwords are encrypted with Windows DPAPI, so the
scheduled task must run as the same Windows user that performed setup.

### Test DSG for a known date

Dates use `YYYY-MM-DD` format:

```bat
DSG_automated.exe --date 2026-07-22
```

This creates the CSV and XLSX under `dsg_output` and does not upload them.

### Run DSG for yesterday

```bat
DSG_automated.exe
```

With no arguments, the program retrieves the previous calendar day in the
configured timezone. For Task Scheduler, set `DSG_automated.exe` as the
program, leave arguments empty, and set **Start in** to the directory containing
the EXE. Enable **Run task as soon as possible after a scheduled start is
missed** and use the same Windows account that ran `--setup`.

## Run from Python

```powershell
.\.venv\Scripts\python.exe .\retrieve_events.py
```

Exports are saved in the `output` folder beside the script.



## Build the Windows executable

### From Windows

```powershell
.\build_exe.cmd
```

The results are `dist\HikvisionEventRetriever.exe`,
`dist\HikvisionEventRetrieverAutomated.exe`, and `dist\DSG_automated.exe`.
The interactive version does not require a configuration file. Each automated
version requires its own one-time `--setup`. DPH exports are saved in
`dist\output`; DSG exports are saved in `dist\dsg_output`.

If dependency installation or executable creation fails, the build window
remains open so the error can be reviewed.

### From macOS using GitHub Actions

PyInstaller cannot create a Windows executable directly on macOS. Push the
project to GitHub, then:

1. Open the repository's **Actions** tab.
2. Select **Build Windows EXE**.
3. Select **Run workflow**, then run it from the `main` branch.
4. Open the completed workflow run.
5. Download **HikvisionEventRetriever-Windows-x64** from the Artifacts section.
6. Unzip the artifact to get `HikvisionEventRetriever.exe`,
   `HikvisionEventRetrieverAutomated.exe`, and `DSG_automated.exe`.

The workflow uses a Windows x64 runner and retains each downloadable artifact
for 30 days.
