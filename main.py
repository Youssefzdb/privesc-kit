#!/usr/bin/env python3
"""privesc-kit - Privilege Escalation Detection Lab"""
import argparse
import platform
from modules.linux_checks import LinuxPrivescChecker
from modules.windows_checks import WindowsPrivescChecker
from modules.report import Report

def main():
    parser = argparse.ArgumentParser(description="privesc-kit - PrivEsc Detection")
    parser.add_argument("--os", choices=["linux", "windows", "auto"], default="auto")
    parser.add_argument("--output", default="privesc_report.html")
    args = parser.parse_args()

    os_type = args.os
    if os_type == "auto":
        os_type = "windows" if platform.system() == "Windows" else "linux"

    print(f"[*] privesc-kit running on: {os_type}")
    findings = []

    if os_type == "linux":
        checker = LinuxPrivescChecker()
    else:
        checker = WindowsPrivescChecker()

    findings = checker.check()
    print(f"[!] Found {len(findings)} potential vectors")
    Report(os_type, findings).save(args.output)
    print(f"[+] Report: {args.output}")

if __name__ == "__main__":
    main()
