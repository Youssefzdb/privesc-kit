#!/usr/bin/env python3
"""
privesc-kit - Privilege Escalation Detection & Lab Tool
For use in authorized penetration testing and CTF environments ONLY
"""
import argparse
from modules.linux_enum import LinuxEnumerator
from modules.suid_finder import SUIDFinder
from modules.cron_checker import CronChecker
from modules.report import PrivescReport

def main():
    parser = argparse.ArgumentParser(
        description="privesc-kit - Priv Esc Detection Tool (AUTHORIZED USE ONLY)"
    )
    parser.add_argument("--full", action="store_true", help="Run full enumeration")
    parser.add_argument("--suid", action="store_true", help="Check SUID binaries")
    parser.add_argument("--cron", action="store_true", help="Check cron jobs")
    parser.add_argument("--output", default="privesc_report.txt")
    args = parser.parse_args()

    results = {}
    print("[*] privesc-kit starting (AUTHORIZED LAB USE ONLY)")

    if args.full or args.suid:
        suid = SUIDFinder()
        results["suid"] = suid.find()

    if args.full or args.cron:
        cron = CronChecker()
        results["cron"] = cron.check()

    if args.full:
        enum = LinuxEnumerator()
        results["system"] = enum.enumerate()

    report = PrivescReport(results)
    report.save(args.output)
    print(f"[+] Report saved: {args.output}")

if __name__ == "__main__":
    main()
