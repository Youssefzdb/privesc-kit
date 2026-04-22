#!/usr/bin/env python3
"""privesc-kit - Privilege Escalation Detection Lab"""
import argparse
from modules.suid_checker import SUIDChecker
from modules.cron_checker import CronChecker
from modules.writable_checker import WritableChecker
from modules.reporter import PrivescReporter

def main():
    parser = argparse.ArgumentParser(description="privesc-kit - PrivEsc Detection")
    parser.add_argument("--mode", choices=["suid", "cron", "writable", "full"], default="full")
    parser.add_argument("--output", default="privesc_report.json")
    args = parser.parse_args()

    print("[*] privesc-kit - Privilege Escalation Detection")
    results = {}

    if args.mode in ["suid", "full"]:
        suid = SUIDChecker()
        results["suid"] = suid.check()

    if args.mode in ["cron", "full"]:
        cron = CronChecker()
        results["cron"] = cron.check()

    if args.mode in ["writable", "full"]:
        writable = WritableChecker()
        results["writable"] = writable.check()

    reporter = PrivescReporter(results)
    reporter.save(args.output)
    print(f"[+] Report: {args.output}")

if __name__ == "__main__":
    main()
