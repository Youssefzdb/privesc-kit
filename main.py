#!/usr/bin/env python3
"""
privesc-kit - Privilege Escalation Detection & Defense Lab
Detects common Linux/Windows privilege escalation vectors (defensive use)
"""
import argparse
import platform
from modules.linux_checks import LinuxPrivEscChecker
from modules.windows_checks import WindowsPrivEscChecker
from modules.report import PrivEscReport

def main():
    parser = argparse.ArgumentParser(description="privesc-kit - PrivEsc Detection Tool")
    parser.add_argument("--os", choices=["linux", "windows", "auto"], default="auto")
    parser.add_argument("--output", default="privesc_report.html")
    args = parser.parse_args()

    os_type = args.os
    if os_type == "auto":
        os_type = "linux" if platform.system() == "Linux" else "windows"

    print(f"[*] Running privilege escalation checks on: {os_type.upper()}")
    findings = []

    if os_type == "linux":
        checker = LinuxPrivEscChecker()
        findings = checker.check_all()
    else:
        checker = WindowsPrivEscChecker()
        findings = checker.check_all()

    report = PrivEscReport(os_type, findings)
    report.save(args.output)
    print(f"[+] Found {len(findings)} potential vectors. Report: {args.output}")

if __name__ == "__main__":
    main()
