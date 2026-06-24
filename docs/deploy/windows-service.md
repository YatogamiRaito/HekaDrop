# Running HekaDrop CLI Daemon as a Windows Service

Windows does not natively support running standard CLI executables directly as system background services without helper utilities. The recommended approach to running `hekadrop-cli daemon` in the background on Windows is to use **NSSM (Non-Sucking Service Manager)**.

## Installation and Configuration Guide

### 1. Download NSSM
Download the latest release of NSSM from [nssm.cc](https://nssm.cc/) and place `nssm.exe` in your system path (e.g. `C:\Windows\System32` or a dedicated folder added to your Environment Variables).

### 2. Register the Service
Open an **Administrator Command Prompt** or **PowerShell** and execute:

```cmd
nssm install HekaDropCLI
```

This will launch the graphical service installer. Configure the following fields:

- **Application Tab**:
  - **Path**: Path to `hekadrop-cli.exe` (e.g., `C:\Program Files\HekaDrop\hekadrop-cli.exe`).
  - **Startup directory**: Directory where `hekadrop-cli.exe` is located (e.g., `C:\Program Files\HekaDrop`).
  - **Arguments**: `daemon` (or `daemon --config C:\ProgramData\HekaDrop\config.json` if using a custom config path).
- **Details Tab**:
  - **Display name**: `HekaDrop CLI Daemon`
  - **Description**: `HekaDrop background file sharing engine.`
  - **Startup type**: `Automatic`
- **I/O Tab (Optional but recommended)**:
  - **Stdout**: Path to output log (e.g., `C:\ProgramData\HekaDrop\logs\stdout.log`).
  - **Stderr**: Path to error log (e.g., `C:\ProgramData\HekaDrop\logs\stderr.log`).

Click **Install service**.

### 3. Start the Service
To start the newly created service, run:

```cmd
nssm start HekaDropCLI
```

Or start it via the standard Windows Service Manager (`services.msc`).

### 4. Removing the Service
If you need to uninstall the service:

```cmd
nssm remove HekaDropCLI confirm
```

---

## Alternative: Windows Task Scheduler
If you do not want to install NSSM, you can configure the daemon to run on user login via the Windows Task Scheduler:

1. Open **Task Scheduler** (`taskschd.msc`).
2. Click **Create Basic Task...** and name it `HekaDrop CLI Daemon`.
3. Set the trigger to **When I log on**.
4. Set the action to **Start a program**.
5. Select `hekadrop-cli.exe` and set the argument to `daemon` (and optionally `--config ...`).
6. Finish and open task properties. Under **Conditions**, ensure "Start the task only if the computer is on AC power" is disabled if running on a laptop. Under **Settings**, make sure "Stop the task if it runs longer than" is unchecked.
