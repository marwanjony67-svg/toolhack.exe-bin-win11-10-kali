# BudgieOS Security Toolkit 1.0

A small, read-only local security diagnostics app for **Windows 10/11** and **Kali Linux**.

## Features

- Local operating-system, architecture, disk and IP configuration summary
- Read-only firewall status check (Windows Firewall or UFW status)
- Read-only Microsoft Defender status check on Windows
- SHA-256 fingerprint for a file you choose
- JSON report mode for troubleshooting

**Safety scope:** this is a defensive local utility. It does not attack or scan other devices, exploit vulnerabilities, bypass logins, collect passwords, or change security settings. Run it only on a device you own or are authorized to administer.

## Windows 10/11

1. Install Python 3.10 or newer.
2. Open PowerShell in this folder.
3. Run:

```powershell
py -3 app.py
```

To build a standalone EXE:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build_windows.ps1
```

The executable will be at `dist\BudgieOS-Security-Toolkit.exe`.

## Kali Linux

Python 3 and Tkinter are needed. Install Tkinter if your installation does not include it:

```bash
sudo apt update
sudo apt install python3-tk
chmod +x run_kali.sh
./run_kali.sh
```

For a terminal JSON report:

```bash
python3 app.py --report
```

## Download the Windows EXE from GitHub Actions

1. Open the repository's **Actions** tab.
2. Select **Build BudgieOS Security Toolkit**.
3. Wait for the Windows job to finish successfully.
4. Open the completed run and download the `BudgieOS-Security-Toolkit-Windows` artifact.

GitHub Actions builds the Windows executable on a Windows runner and stores it as a workflow artifact. The first build has not been verified until that workflow completes successfully.

## Project status

Starter version 1.0. The app uses Python's standard library; PyInstaller is used only for Windows packaging.
