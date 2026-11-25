#!/usr/bin/env python3
"""BudgieOS Security Toolkit: read-only local defensive diagnostics."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "BudgieOS Security Toolkit"
VERSION = "1.0"


def run_read_only(command: list[str], timeout: int = 8) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        output = (result.stdout or result.stderr).strip()
        return output if output else f"Command completed (exit code {result.returncode})."
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"Not available: {exc}"


def system_report() -> dict:
    addresses = sorted({
        item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None)
        if item[0] in (socket.AF_INET, socket.AF_INET6)
    })
    disk = shutil.disk_usage(os.path.abspath(os.sep))
    return {
        "app": f"{APP_NAME} {VERSION}",
        "operating_system": platform.platform(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "device_name": socket.gethostname(),
        "local_ip_addresses": addresses,
        "root_disk_total_gb": round(disk.total / (1024 ** 3), 2),
        "root_disk_free_gb": round(disk.free / (1024 ** 3), 2),
    }


def firewall_report() -> str:
    system = platform.system()
    if system == "Windows":
        return run_read_only(["netsh", "advfirewall", "show", "allprofiles"])
    if system == "Linux":
        ufw = shutil.which("ufw")
        if ufw:
            return run_read_only([ufw, "status"])
        nft = shutil.which("nft")
        if nft:
            return "UFW is not installed. nftables is present; rules are not displayed by this basic viewer."
        return "No supported firewall status command found. Check your distribution's firewall settings."
    return "Firewall status check is not implemented for this operating system."


def defender_report() -> str:
    if platform.system() != "Windows":
        return "Microsoft Defender status is only queried on Windows."
    command = [
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Format-List"
    ]
    return run_read_only(command)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_report() -> dict:
    return {
        "system": system_report(),
        "firewall_status": firewall_report(),
        "defender_status": defender_report(),
        "scope": "Read-only checks on this device. No network scanning or remote access.",
    }


class ToolkitApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {VERSION}")
        self.geometry("820x610")
        self.minsize(680, 480)
        self.configure(bg="#101827")
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#101827")
        style.configure("TLabel", background="#101827", foreground="#e8f0ff")
        style.configure("Title.TLabel", font=("Segoe UI", 19, "bold"), foreground="#69a9ff")
        style.configure("TButton", padding=8)
        self._build()

    def _build(self) -> None:
        outer = ttk.Frame(self, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="BudgieOS Security Toolkit", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="Local defensive diagnostics • Windows 10/11 • Kali Linux").pack(anchor="w", pady=(2, 14))
        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(0, 12))
        for label, callback in [
            ("System info", self.show_system),
            ("Firewall status", self.show_firewall),
            ("Defender status", self.show_defender),
            ("Check a file hash", self.choose_hash),
            ("Full report", self.show_full_report),
        ]:
            ttk.Button(actions, text=label, command=callback).pack(side="left", padx=(0, 7), pady=3)
        self.output = tk.Text(outer, wrap="word", bg="#0b1220", fg="#dce8ff",
                              insertbackground="white", relief="flat", padx=12, pady=12,
                              font=("Consolas", 10))
        self.output.pack(fill="both", expand=True)
        self.output.insert("end", "Welcome! Choose a read-only diagnostic above.\n\n"
                           "This app checks only the computer where it is running. "
                           "It does not scan other devices, exploit systems, or collect passwords.\n")
        self.output.configure(state="disabled")

    def display(self, title: str, value: object) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("end", f"{title}\n{'=' * len(title)}\n\n")
        self.output.insert("end", value if isinstance(value, str) else json.dumps(value, indent=2))
        self.output.configure(state="disabled")

    def show_system(self) -> None:
        self.display("System information", system_report())

    def show_firewall(self) -> None:
        self.display("Firewall status (read-only)", firewall_report())

    def show_defender(self) -> None:
        self.display("Microsoft Defender status (read-only)", defender_report())

    def show_full_report(self) -> None:
        self.display("Local security report", make_report())

    def choose_hash(self) -> None:
        path = filedialog.askopenfilename(title="Choose a file to hash")
        if not path:
            return
        try:
            digest = sha256_file(path)
            self.display("SHA-256 file integrity check",
                         f"File: {path}\n\nSHA-256:\n{digest}\n\n"
                         "This fingerprint can help you compare the file with a trusted publisher checksum.")
        except OSError as exc:
            messagebox.showerror("Could not read file", str(exc))


def main() -> None:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--report", action="store_true", help="print a read-only JSON system report")
    args = parser.parse_args()
    if args.report:
        print(json.dumps(make_report(), indent=2))
    else:
        ToolkitApp().mainloop()


if __name__ == "__main__":
    main()
