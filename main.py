#!/usr/bin/env python3
"""
privesc-kit - Privilege Escalation Detection Lab
Detects common privilege escalation vectors on Linux/Windows systems
"""
import argparse
import platform
from modules.linux_checker import LinuxPrivescChecker
from modules.windows_checker import WindowsPrivescChecker
from modules.report import PrivescReport

def main():
    parser = argparse.ArgumentParser(description="privesc-kit - Detection Lab")
    parser.add_argument("--os", choices=["linux", "windows", "auto"], default="auto")
    parser.add_argument("--output", default="privesc_report.html")
    args = parser.parse_args()

    current_os = platform.system().lower() if args.os == "auto" else args.os
    print(f"[*] Running privesc checks on: {current_os}")
    results = {}

    if current_os == "linux":
        checker = LinuxPrivescChecker()
        results = checker.check()
    elif current_os == "windows":
        checker = WindowsPrivescChecker()
        results = checker.check()
    else:
        print("[*] Running both OS checks in demo mode")
        results["linux"] = LinuxPrivescChecker().check()
        results["windows"] = WindowsPrivescChecker().check()

    report = PrivescReport(current_os, results)
    report.save(args.output)
    print(f"[+] Report: {args.output}")

if __name__ == "__main__":
    main()
